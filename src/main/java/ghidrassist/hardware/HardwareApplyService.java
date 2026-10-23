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
        List<HardwareRegionLayout.Range> gaps=new ArrayList<>();
        long cursor=item.address;
        for(MemoryBlock block:blocks) {
            long first=Math.max(item.address,block.getStart().getOffset());
            long last=Math.min(item.last(),block.getEnd().getOffset());
            if(first>cursor)gaps.add(new HardwareRegionLayout.Range(cursor,first-1));
            cursor=Math.max(cursor,last+1);
        }
        if(cursor<=item.last())gaps.add(new HardwareRegionLayout.Range(cursor,item.last()));
        return gaps;
    }
    private static Decision memoryDecision(Program p,HardwareApplyPlan.Item item){
        List<MemoryBlock> parts=overlaps(p,item);
        if(csWindow(item)){
            List<HardwareRegionLayout.Range> gaps=csMissing(item,parts);
            return gaps.isEmpty() ?
                decide(State.ALREADY_PRESENT,"CS address range is already mapped",false) :
                decide(State.READY,"Map "+gaps.size()+
                    " missing CS fragment(s), keep existing blocks/data unchanged",true);
        }
        if(parts.size()==1 && parts.get(0).getStart().getOffset()==item.address &&
                parts.get(0).getEnd().getOffset()==item.last())
            return decide(State.ALREADY_PRESENT,"Entire region already mapped as "+
                parts.get(0).getName(),false);
        for(MemoryBlock block:parts){
            if(block.getStart().getOffset()<item.address ||
                    block.getEnd().getOffset()>item.last() ||
                    block.isInitialized() || block.isMapped() ||
                    block.getType()!=MemoryBlockType.DEFAULT ||
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
            if(!p.getListing().isUndefined(first,last))
                return decide(State.ALREADY_PRESENT,"Data or code already defined",false);
            Symbol old=p.getSymbolTable().getPrimarySymbol(first);
            if(old!=null && old.getSource()!=SourceType.DEFAULT)
                return decide(State.BLOCKED,"Existing non-default label: "+old.getName(),false);
            return decide(State.READY,"Mapped, undefined and no user symbol",true);
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
    /** Read-only status for one row, reusable in both the UI and apply guard. */
    public static Decision preflight(Program p,HardwareApplyPlan.Item item,
                                     List<HardwareApplyPlan.Item> plan){
        if(p==null||item==null)throw new IllegalArgumentException("Missing program or item");
        if(item.kind==HardwareApplyPlan.Kind.MEMORY)return memoryDecision(p,item);
        if(item.kind==HardwareApplyPlan.Kind.REGISTER)return registerDecision(p,item,plan);
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
            for(HardwareRegionLayout.Range gap:csMissing(item,parts)){
                String name=item.name+"_PART_"+(++segment);
                MemoryBlock added=m.createUninitializedBlock(name,address(p,gap.first),
                    gap.length(),false);
                added.setRead(true);added.setWrite(true);added.setExecute(false);
                notes.add("NEW CS REGION "+name+" "+
                    ChipSelectModel.hex(gap.first,6)+".."+ChipSelectModel.hex(gap.last,6));
            }
            return segment>0;
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
        if(!covers(p.getMemory(),first,last) ||
                !p.getListing().isUndefined(first,last)){
            notes.add("SKIP "+item.name+" (unmapped or already defined)");
            return false;
        }
        Symbol prior=p.getSymbolTable().getPrimarySymbol(first);
        if(prior!=null && prior.getSource()!=SourceType.DEFAULT){
            notes.add("SKIP "+item.name+"; preserve existing symbol "+
                prior.getName());
            return false;
        }
        DataType type=switch(item.length) {
            case 1 -> ByteDataType.dataType;
            case 2 -> WordDataType.dataType;
            case 4 -> DWordDataType.dataType;
            default -> throw new IllegalArgumentException("Unsupported register length: "+item.length);
        };
        p.getListing().createData(first,type);
        String name=item.name;
        p.getSymbolTable().createLabel(first,name,SourceType.USER_DEFINED);
        notes.add("DEFINED REGISTER "+name+" at "+first);
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
            for(HardwareApplyPlan.Kind kind:HardwareApplyPlan.Kind.values()) {
                for(HardwareApplyPlan.Item item:approved) {
                    if(item.kind!=kind)continue;
                    boolean applied=switch(kind) {
                        case MEMORY -> createRegion(program,item,messages);
                        case REGISTER -> defineRegister(program,item,messages);
                        case VBR_STRUCTURE -> defineVbr(program,item,messages);
                    };
                    if(applied)changed++;else skipped++;
                }
            }
            commit=true;
            return new Outcome(changed,skipped,messages);
        } finally {
            program.endTransaction(transaction,commit);
        }
    }
}
