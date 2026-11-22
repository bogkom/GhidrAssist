package ghidrassist.hardware;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * The read-only preflight is used to default-select safely applicable items.
 * Actual changes happen ONLY after explicit user confirmation inside one
 * undoable Ghidra transaction; conflicting user blocks/code are never cleared.
 */
public final class HardwareApplyService {
    private HardwareApplyService(){}

    public enum State { READY, UPGRADE, ALREADY_PRESENT, BLOCKED, MANUAL_REVIEW }
    public static final class Decision {
        public final State state;
        public final String description;
        public final boolean selectedByDefault;
        private Decision(State state,String description,boolean selected) {
            this.state=state;this.description=description;selectedByDefault=selected;
        }
        public boolean allowed(){return state==State.READY||state==State.UPGRADE||
            state==State.MANUAL_REVIEW;}
    }
    private static Decision decide(State state,String reason,boolean selected) {
        return new Decision(state,reason,selected);
    }
    public static final class Outcome {
        public final int changed,skipped;
        public final List<String> messages;
        Outcome(int changed,int skipped,List<String> messages){
            this.changed=changed;this.skipped=skipped;this.messages=List.copyOf(messages);
        }
    }
    private static Address address(Program p,long offset) {
        return p.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }
    private static boolean covers(Memory m,Address a,Address b) {
        return m.contains(a)&&m.contains(b)&&m.getBlock(a)==m.getBlock(b);
    }
    private static boolean legacyPart(HardwareApplyPlan.Item item,MemoryBlock block){
        String n=block.getName();
        long at=block.getStart().getOffset();
        if(n.equals(item.name) && at==item.address)return true;
        if(item.name.equals("QSM_MM1"))
            return (n.equals("QSM_CONTROL_MM1") && at==0xfffc00L) ||
                (n.equals("QSM_QUEUE_MM1") && at==0xfffd00L);
        if(item.name.equals("TPU_MM1"))
            return (n.equals("TPU_CONTROL_MM1") && at==0xfffe00L) ||
                (n.equals("TPU_PARAM_RAM_MM1") && at==0xffff00L);
        return false;
    }
    private static List<MemoryBlock> overlaps(Program p,HardwareApplyPlan.Item item){
        Address first=address(p,item.address),last=address(p,item.last());
        List<MemoryBlock> blocks=new ArrayList<>();
        for(MemoryBlock b:p.getMemory().getBlocks()) {
            if(!b.getStart().getAddressSpace().equals(first.getAddressSpace()))continue;
            if(b.getStart().compareTo(last)<=0 && b.getEnd().compareTo(first)>=0)
                blocks.add(b);
        }
        blocks.sort(Comparator.comparing(MemoryBlock::getStart));
        return blocks;
    }
    private static boolean csWindow(HardwareApplyPlan.Item item) {
        return item.name.startsWith("CS_WINDOW_");
    }
    private static List<HardwareRegionLayout.Range> csMissing(
            HardwareApplyPlan.Item item, List<MemoryBlock> blocks) {
        List<HardwareRegionLayout.Range> existing=new ArrayList<>();
        for(MemoryBlock block:blocks)
            existing.add(new HardwareRegionLayout.Range(
                block.getStart().getOffset(),block.getEnd().getOffset()));
        return HardwareRegionLayout.missingClipped(item.address,item.last(),existing);
    }
    private static Decision memoryDecision(Program p,HardwareApplyPlan.Item item){
        List<MemoryBlock> parts=overlaps(p,item);
        if(csWindow(item)){
            // A benign-looking user block is still user-owned: coverage is not
            // authorization to adopt it as a speculative external CS mapping.
            // Only exact previously created CS fragments may be reused.
            for(MemoryBlock block:parts){
                boolean owned=block.getName().equals(item.name) ||
                    block.getName().matches(java.util.regex.Pattern.quote(item.name)+"_PART_[1-9][0-9]*");
                if(!owned || block.getStart().getOffset()<item.address ||
                        block.getEnd().getOffset()>item.last() ||
                        block.isInitialized() || block.isMapped() || block.isVolatile() ||
                        block.getType()!=MemoryBlockType.DEFAULT ||
                        block.isExecute() || !block.isRead() || !block.isWrite())
                    return decide(State.BLOCKED,
                        "CS window overlaps incompatible user memory: "+
                        block.getName()+" at "+block.getStart()+".."+block.getEnd()+
                        "; active decode and wiring UNKNOWN",false);
            }
            List<HardwareRegionLayout.Range> gaps=csMissing(item,parts);
            return gaps.isEmpty() ?
                decide(State.ALREADY_PRESENT,"CS address range is already mapped",false) :
                decide(State.MANUAL_REVIEW,"Potential external CS window: map "+
                    gaps.size()+" missing fragment(s) only after explicit "+
                    "operator selection; active decode and wiring UNKNOWN",false);
        }
        if(parts.size()==1 && parts.get(0).getStart().getOffset()==item.address &&
                parts.get(0).getEnd().getOffset()==item.last()) {
            MemoryBlock existing=parts.get(0);
            // Exact coverage is not ownership: never silently accept an
            // arbitrary user block as a completed hardware module.
            if(!legacyPart(item,existing) || existing.isInitialized() ||
                    existing.isMapped() || existing.isVolatile() || existing.getType()!=MemoryBlockType.DEFAULT ||
                    existing.isExecute() || !existing.isRead() || !existing.isWrite())
                return decide(State.BLOCKED,
                    "Exact region belongs to existing user memory: "+
                    existing.getName(),false);
            return decide(State.ALREADY_PRESENT,
                "Matching uninitialized hardware region already mapped as "+
                existing.getName(),false);
        }
        // Full coverage by unrelated user blocks is not proof that TPURAM
        // belongs to this candidate. Let the normal ownership checks below
        // reject foreign blocks instead of reporting ALREADY_PRESENT.
        for(MemoryBlock block:parts){
            if(block.getStart().getOffset()<item.address ||
                    block.getEnd().getOffset()>item.last() ||
                    block.isInitialized() || block.isMapped() || block.isVolatile() ||
                    block.getType()!=MemoryBlockType.DEFAULT ||
                    block.isExecute() || !block.isRead() || !block.isWrite() ||
                    !legacyPart(item,block)){
                return decide(State.BLOCKED,
                    "Overlaps other memory: "+block.getName()+" at "+
                    block.getStart()+".."+block.getEnd(),false);
            }
        }
        if(parts.isEmpty()){
            boolean speculative=item.name.startsWith("CS") ||
                item.name.equals("TPURAM_2K_CANDIDATE");
            return decide(speculative?State.MANUAL_REVIEW:State.READY,
                speculative?"External device/relocation not confirmed":
                    "MC68332 module region; uninitialized block",
                !speculative);
        }
        return decide(State.UPGRADE,"Extend/join "+parts.size()+
            " existing GhidrAssist block(s), preserving typed data",true);
    }
    private static Decision registerDecision(Program p,HardwareApplyPlan.Item item,
                                              List<HardwareApplyPlan.Item> all){
        Address first=address(p,item.address),last=address(p,item.last());
        Memory m=p.getMemory();
        if(covers(m,first,last)) {
            Symbol old=p.getSymbolTable().getPrimarySymbol(first);
            if(old!=null && old.getSource()!=SourceType.DEFAULT &&
                    !old.getName().equals(item.name))
                return decide(State.BLOCKED,"Existing non-default label: "+old.getName(),false);
            // A matching label alone does not prove the register is safe:
            // reject overlapping instructions and incompatible typed data.
            boolean undefined=p.getListing().isUndefined(first,last);
            if(!undefined) {
                ghidra.program.model.listing.Data prior=p.getListing().getDataAt(first);
                if(prior==null || !prior.isDefined() || prior.getLength()!=item.length)
                    return decide(State.BLOCKED,
                        "Data/code defined with incompatible size or location",false);
            }
            if(undefined) {
                // A matching user label does not prove that register data exists.
                // Complete the definition without recreating the existing label.
                return decide(State.READY,
                    old!=null && old.getSource()!=SourceType.DEFAULT ?
                        "Matching register label exists; define missing data only" :
                        "Mapped, undefined register bytes",true);
            }
            if(old!=null && old.getSource()!=SourceType.DEFAULT)
                return decide(State.ALREADY_PRESENT,
                    "Short register label and compatible data already defined",false);
            return decide(State.UPGRADE,
                "Preserve existing typed data; add short register label",true);
        }
        for(HardwareApplyPlan.Item candidate:all){
            if(candidate.kind!=HardwareApplyPlan.Kind.MEMORY)continue;
            if(candidate.address<=item.address && candidate.last()>=item.last()){
                Decision parent=memoryDecision(p,candidate);
                if(parent.state==State.READY || parent.state==State.UPGRADE)
                    return decide(State.READY,"Will be mapped by "+
                        candidate.name+" if its row remains selected",true);
                if(parent.state==State.MANUAL_REVIEW)
                    return decide(State.MANUAL_REVIEW,
                        "Depends on manually approved "+candidate.name,false);
            }
        }
        return decide(State.BLOCKED,"No safe mapped memory for register",false);
    }
    private static final String TPURAM_CANDIDATE_NOTE =
        "GhidrAssist: candidate relocated 2KiB TPURAM 0xFFF000..0xFFF7FF; " +
        "confirm TRAMBAR and runtime memory configuration.";
    private static Decision annotationDecision(Program p,HardwareApplyPlan.Item item) {
        Address at=address(p,item.address);
        if(!p.getMemory().contains(at))
            return decide(State.BLOCKED,"Annotation address is not mapped; create CS region first",false);
        // Never attach speculative TPURAM annotations to existing executable code.
        if(p.getListing().getInstructionContaining(at)!=null)
            return decide(State.BLOCKED,
                "Candidate address contains an instruction; preserve user code",false);
        Symbol prior=p.getSymbolTable().getPrimarySymbol(at);
        if(prior!=null && prior.getSource()!=SourceType.DEFAULT) {
            if(!prior.getName().equals(item.name))
                return decide(State.BLOCKED,
                    "Keep existing user label: "+prior.getName(),false);
            String comment=p.getListing().getComment(
                ghidra.program.model.listing.CodeUnit.PLATE_COMMENT,at);
            if(comment!=null && comment.contains(TPURAM_CANDIDATE_NOTE))
                return decide(State.ALREADY_PRESENT,
                    "Candidate label and provenance comment already exist",false);
            return decide(State.MANUAL_REVIEW,
                "Candidate label exists but provenance comment is missing; add comment only",false);
        }
        return decide(State.MANUAL_REVIEW,
            "Mapped inside existing memory; add candidate label and comment only",false);
    }
    /** Read-only status for one row, reusable in both the UI and apply guard. */
    public static Decision preflight(Program p,HardwareApplyPlan.Item item,
                                     List<HardwareApplyPlan.Item> plan){
        if(p==null||item==null)throw new IllegalArgumentException("Missing program or item");
        if(item.kind==HardwareApplyPlan.Kind.MEMORY)return memoryDecision(p,item);
        if(item.kind==HardwareApplyPlan.Kind.REGISTER)return registerDecision(p,item,plan);
        if(item.kind==HardwareApplyPlan.Kind.ANNOTATION)return annotationDecision(p,item);
        Address a=address(p,item.address),b=address(p,item.last());
        if(!covers(p.getMemory(),a,b) || !p.getListing().isUndefined(a,b))
            return decide(State.BLOCKED,
                "VBR location unmapped or contains defined code/data; never overwrite",false);
        return decide(State.MANUAL_REVIEW,"VBR runtime address has not been proven",false);
    }
    private static boolean createRegion(Program p,HardwareApplyPlan.Item item,
                                        List<String> notes)throws Exception {
        Decision check=memoryDecision(p,item);
        if(!check.allowed()){
            notes.add("SKIP "+item.name+": "+check.description);
            return false;
        }
        Memory m=p.getMemory();
        List<MemoryBlock> parts=overlaps(p,item);
        if(csWindow(item)){
            int segment=0;
            // A later Apply can fill a new gap after earlier fragments were
            // created. Never reuse a name already present in this program.
            java.util.Set<String> usedNames=new java.util.HashSet<>();
            for(MemoryBlock existing:m.getBlocks())usedNames.add(existing.getName());
            for(HardwareRegionLayout.Range gap:csMissing(item,parts)){
                String name;
                do { name=item.name+"_PART_"+(++segment); }
                while(usedNames.contains(name));
                usedNames.add(name);
                MemoryBlock added=m.createUninitializedBlock(name,address(p,gap.first),
                    gap.length(),false);
                added.setRead(true);added.setWrite(true);added.setExecute(false);
                notes.add("NEW CS REGION "+name+" "+
                    ChipSelectModel.hex(gap.first,6)+".."+ChipSelectModel.hex(gap.last,6));
            }
            return !notes.isEmpty();
        }
        if(parts.isEmpty()){
            MemoryBlock b=m.createUninitializedBlock(item.name,address(p,item.address),
                item.length,false);
            b.setRead(true);b.setWrite(true);b.setExecute(false);
            notes.add("NEW MODULE REGION "+item.name+" "+item.location());
            return true;
        }
        // Existing user-approved register types remain in the original blocks.
        // Fill missing gaps, then join contiguous UNINITIALIZED default blocks.
        List<MemoryBlock> chain=new ArrayList<>(parts);
        List<HardwareRegionLayout.Range> existingRanges=new ArrayList<>();
        for(MemoryBlock part:parts)
            existingRanges.add(new HardwareRegionLayout.Range(
                part.getStart().getOffset(),part.getEnd().getOffset()));
        int suffix=0;
        for(HardwareRegionLayout.Range missing:HardwareRegionLayout.missing(
                item.address,item.last(),existingRanges)){
            MemoryBlock gap=m.createUninitializedBlock(
                item.name+"_GAP_"+(++suffix),address(p,missing.first),
                missing.length(),false);
            gap.setRead(true);gap.setWrite(true);gap.setExecute(false);
            chain.add(gap);
        }
        chain.sort(Comparator.comparing(MemoryBlock::getStart));
        MemoryBlock combined=chain.get(0);
        for(int i=1;i<chain.size();i++)combined=m.join(combined,chain.get(i));
        combined.setName(item.name);
        notes.add("UPGRADED MODULE REGION "+item.name+" "+item.location()+
            "; existing register definitions and symbols preserved");
        return true;
    }
    private static boolean defineRegister(Program p,HardwareApplyPlan.Item item,
                                          List<String> notes)throws Exception {
        Address first=address(p,item.address),last=address(p,item.last());
        if(!covers(p.getMemory(),first,last)){
            notes.add("SKIP "+item.name+" (unmapped)");
            return false;
        }
        Symbol prior=p.getSymbolTable().getPrimarySymbol(first);
        if(prior!=null && prior.getSource()!=SourceType.DEFAULT &&
                !prior.getName().equals(item.name)){
            notes.add("BLOCK "+item.name+"; preserve existing symbol "+
                prior.getName());
            return false;
        }
        DataType type=switch(item.length) {
            case 1 -> ByteDataType.dataType;
            case 2 -> WordDataType.dataType;
            case 4 -> DWordDataType.dataType;
            default -> throw new IllegalArgumentException("Unsupported register length: "+item.length);
        };
        boolean undefined=p.getListing().isUndefined(first,last);
        if(undefined) {
            p.getListing().createData(first,type);
        } else {
            ghidra.program.model.listing.Data priorData=p.getListing().getDataAt(first);
            if(priorData==null || !priorData.isDefined() ||
                    priorData.getLength()!=item.length) {
                notes.add("SKIP "+item.name+" (existing incompatible data/code)");
                return false;
            }
            // Preserve user-approved data type: only add an informative symbol.
        }
        String name=item.name;
        if(prior==null || prior.getSource()==SourceType.DEFAULT)
            p.getSymbolTable().createLabel(first,name,SourceType.USER_DEFINED);
        notes.add("DEFINED REGISTER "+name+" at "+first);
        return true;
    }
    private static boolean annotateCandidate(Program p,HardwareApplyPlan.Item item,
                                              List<String> notes)throws Exception {
        Decision check=annotationDecision(p,item);
        if(!check.allowed()){
            notes.add("SKIP "+item.name+": "+check.description);
            return false;
        }
        Address at=address(p,item.address);
        Symbol prior=p.getSymbolTable().getPrimarySymbol(at);
        if(prior==null || prior.getSource()==SourceType.DEFAULT)
            p.getSymbolTable().createLabel(at,item.name,SourceType.USER_DEFINED);
        String existing=p.getListing().getComment(ghidra.program.model.listing.CodeUnit.PLATE_COMMENT,at);
        String line=TPURAM_CANDIDATE_NOTE;
        if(existing==null || !existing.contains(line))
            p.getListing().setComment(at,
                ghidra.program.model.listing.CodeUnit.PLATE_COMMENT,
                existing==null || existing.isBlank()?line:existing+"\n"+line);
        notes.add("ANNOTATED CANDIDATE "+item.name+" at "+at);
        return true;
    }
    private static boolean defineVbr(Program p,HardwareApplyPlan.Item item,
                                     List<String> notes)throws Exception {
        Address start=address(p,item.address),end=address(p,item.last());
        if(!covers(p.getMemory(),start,end) ||
                !p.getListing().isUndefined(start,end)){
            notes.add("SKIP VBR (unmapped or already typed)");
            return false;
        }
        StructureDataType vectors=new StructureDataType(
            new CategoryPath("/GhidrAssist/Hardware"),"CPU32_VBR_256_VECTORS",0);
        for(int i=0;i<256;i++)
            vectors.add(DWordDataType.dataType,4,
                String.format("vector_%03d",i),
                "Vector entry; actual runtime VBR not verified");
        DataType type=p.getDataTypeManager().addDataType(vectors,
            DataTypeConflictHandler.KEEP_HANDLER);
        p.getListing().createData(start,type);
        notes.add("DEFINED VBR STRUCTURE "+item.location());
        return true;
    }
    public static Outcome apply(Program program,List<HardwareApplyPlan.Item> approved)
            throws Exception {
        if(program==null||approved==null||approved.isEmpty())
            throw new IllegalArgumentException("Nothing approved");
        int transaction=program.startTransaction("GhidrAssist: Apply hardware definitions");
        int changed=0,skipped=0;boolean commit=false;
        List<String> messages=new ArrayList<>();
        try {
            // Two independently approved MEMORY proposals must never claim the
            // same byte range. Review selection is not an ownership override;
            // reject ambiguous batches before mutating the first block.
            for (int i = 0; i < approved.size(); i++) {
                HardwareApplyPlan.Item left = approved.get(i);
                if (left.kind != HardwareApplyPlan.Kind.MEMORY) continue;
                for (int j = i + 1; j < approved.size(); j++) {
                    HardwareApplyPlan.Item right = approved.get(j);
                    if (right.kind != HardwareApplyPlan.Kind.MEMORY) continue;
                    if (left.address <= right.last() && right.address <= left.last()) {
                        throw new IllegalStateException(
                            "Hardware Apply ambiguous overlapping MEMORY approvals: " +
                            left.name + " / " + right.name);
                    }
                }
            }
            // Preflight the entire approved MEMORY batch before creating any block.
            // Register rows may depend on newly mapped regions, so their live
            // preflight remains in the ordered mutation pass below.
            for (HardwareApplyPlan.Item item : approved) {
                if (item.kind != HardwareApplyPlan.Kind.MEMORY) continue;
                Decision initial = preflight(program, item, approved);
                if (initial.state == State.BLOCKED) {
                    throw new IllegalStateException(
                        "Hardware Apply blocked by changed project state: " +
                        item.name + " (" + initial.description + ")");
                }
            }
            for(HardwareApplyPlan.Kind kind:HardwareApplyPlan.Kind.values()) {
                for(HardwareApplyPlan.Item item:approved) {
                    if(item.kind!=kind)continue;
                    // Recheck the live database inside the same undoable transaction.
                    // A stale Review selection must not partially apply earlier rows
                    // and silently skip a newly conflicting user definition.
                    Decision current=preflight(program,item,approved);
                    if(current.state==State.BLOCKED) {
                        throw new IllegalStateException("Hardware Apply blocked by changed project state: "+
                            item.name+" ("+current.description+")");
                    }
                    if(current.state==State.ALREADY_PRESENT) {
                        skipped++;
                        messages.add("SKIP "+item.name+": "+current.description);
                        continue;
                    }
                    boolean applied=switch(kind) {
                        case MEMORY -> createRegion(program,item,messages);
                        case REGISTER -> defineRegister(program,item,messages);
                        case ANNOTATION -> annotateCandidate(program,item,messages);
                        case VBR_STRUCTURE -> defineVbr(program,item,messages);
                    };
                    // A READY/UPGRADE/MANUAL_REVIEW row that cannot be written is
                    // not an idempotent skip. Abort the entire transaction so
                    // earlier successful rows cannot be committed on stale state.
                    if(!applied) {
                        throw new IllegalStateException(
                            "Hardware Apply could not apply approved row: "+item.name);
                    }
                    changed++;
                }
            }
            commit=true;
            return new Outcome(changed,skipped,messages);
        } finally {
            program.endTransaction(transaction,commit);
        }
    }
}
