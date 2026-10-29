package ghidrassist.hardware;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Intraprocedural Ghidra Listing CFG translation with conservative abstract
 * values for A0..A7 and D0..D7. No MCU detection, no database writes,
 * no physical/program execution and no interprocedural call state.
 */
public final class GhidraHardwareFlowService {
    private static final int MAX_CFG_MMIO_SITES=12000;
    private static final int MAX_POINTER_ROLE_SITES=8000;
    private static final Pattern REG=Pattern.compile("(?<![A-Z0-9])([AD][0-7])(?![A-Z0-9])");
    private static final Pattern OFFSET=Pattern.compile("(?<![A-Z0-9])(-?0[Xx][0-9A-F]+|-?[0-9]+)(?![A-Z0-9])");
    public static final class Report {
        public final String markdown;
        public final String configurationEvidenceCsv;
        public final List<HardwareCfgWriteAudit.Site> rawCfgMmioSites;
        public final List<HardwarePointerRoleReview.Proposal> pointerRoles;
        public final java.util.Set<Long> resetCandidateFunctions;
        public final boolean resetCandidateRecognized,resetGraphIncomplete;
        public final int functions,indirect,vbr,unresolved,visited;
        public final boolean limited;
        public final boolean cfgReviewComplete;
        public final long cfgSitesOmitted,pointerSitesOmitted;
        Report(String md,int fn,int indirect,int vbr,int unresolved,int visited,
                boolean limited,List<HardwarePointerRoleReview.Proposal> pointers,
                java.util.Set<Long> resetCandidates,boolean resetRecognized,
                boolean resetUnresolved,String configurationCsv,
                List<HardwareCfgWriteAudit.Site> cfgSites,
                boolean cfgReviewComplete,long cfgOmitted,long pointerOmitted){
            markdown=md;configurationEvidenceCsv=configurationCsv;
            rawCfgMmioSites=List.copyOf(cfgSites);
            pointerRoles=List.copyOf(pointers);
            resetCandidateFunctions=java.util.Set.copyOf(resetCandidates);
            resetCandidateRecognized=resetRecognized;
            resetGraphIncomplete=resetUnresolved;
            functions=fn;this.indirect=indirect;this.vbr=vbr;
            this.unresolved=unresolved;this.visited=visited;this.limited=limited;
            this.cfgReviewComplete=cfgReviewComplete;
            this.cfgSitesOmitted=cfgOmitted;this.pointerSitesOmitted=pointerOmitted;
        }
    }
    private static String opcode(Instruction i){
        String name=i.getMnemonicString().toUpperCase(Locale.ROOT);
        int dot=name.indexOf('.');
        return dot<0?name:name.substring(0,dot);
    }
    private static String op(Instruction i,int slot){
        if(slot<0||slot>=i.getNumOperands())return "";
        String s=i.getDefaultOperandRepresentation(slot);
        return s==null?"":s.toUpperCase(Locale.ROOT).trim();
    }
    private static String plainReg(Instruction i,int slot){
        String s=op(i,slot);
        return s.matches("[AD][0-7]")?s:null;
    }
    private static String indirectReg(Instruction i,int slot){
        String s=op(i,slot);
        if(!s.contains("(")||!s.contains(")")||s.contains("[")||
                s.contains("+")||s.contains("-(")||s.contains("PC"))return null;
        Matcher m=REG.matcher(s);
        if(!m.find())return null;
        String a=m.group(1);
        return a.startsWith("A")&&!m.find()?a:null;
    }
    private static long displacement(Instruction i,int slot){
        String s=op(i,slot);
        Matcher m=OFFSET.matcher(s);
        while(m.find()){
            try{return Long.decode(m.group(1));}
            catch(NumberFormatException e){return 0;}
        }
        return 0;
    }
    private static Long immediate(Instruction i,int slot){
        if(!op(i,slot).startsWith("#"))return null;
        Scalar s=i.getScalar(slot);
        return s==null?null:s.getUnsignedValue();
    }
    private static Long absolute(Instruction i,int slot){
        if(op(i,slot).isEmpty()||op(i,slot).startsWith("#")||
                indirectReg(i,slot)!=null)return null;
        Object[] objects=i.getOpObjects(slot);
        if(objects==null)return null;
        for(Object o:objects)if(o instanceof Register)return null;
        for(Object o:objects)if(o instanceof Address a)
            return a.getOffset()&HardwareDataflow.MASK24;
        return null;
    }
    private static Long value(Varnode v,Map<Varnode,Long> constants){
        if(v==null)return null;
        // A missing dataflow constant is UNKNOWN, not zero or an error.
        // Primitive long vs boxed Long in a ternary expression would unbox
        // the null returned by Map.get() and crash on normal P-code.
        if(v.isConstant())return HardwareDataflow.pcodeInputValue(true,v.getOffset(),null);
        return HardwareDataflow.pcodeInputValue(false,0L,constants.get(v));
    }
    /** Any unsupported memory mutation becomes a barrier instead of OTHER. */
    private static boolean hasPcodeStore(Instruction instruction) {
        PcodeOp[] ops=instruction.getPcode();
        if(ops==null)return false;
        for(PcodeOp p:ops)if(p.getOpcode()==PcodeOp.STORE)return true;
        return false;
    }

    /** Only one fully resolved P-code memory write yields an address. */
    private static Long pcodeStore(Instruction i){
        Map<Varnode,Long> computed=new HashMap<>();
        List<Long> destinations=new ArrayList<>();
        PcodeOp[] ops=i.getPcode();
        if(ops==null)return null;
        for(PcodeOp p:ops){
            Long result=null;int k=p.getOpcode();
            if(k==PcodeOp.STORE){
                Long ptr=p.getNumInputs()>=3?value(p.getInput(1),computed):null;
                destinations.add(ptr==null?null:ptr&HardwareDataflow.MASK24);
            } else if((k==PcodeOp.COPY||k==PcodeOp.INT_ZEXT||
                    k==PcodeOp.INT_SEXT) && p.getNumInputs()>0){
                result=value(p.getInput(0),computed);
            } else if((k==PcodeOp.INT_ADD||k==PcodeOp.INT_SUB) &&
                    p.getNumInputs()>1){
                Long x=value(p.getInput(0),computed),y=value(p.getInput(1),computed);
                if(x!=null&&y!=null)result=k==PcodeOp.INT_ADD?x+y:x-y;
            }
            Varnode out=p.getOutput();
            if(out!=null){
                if(result!=null)computed.put(out,result&HardwareDataflow.MASK24);
                else computed.remove(out);
            }
        }
        return HardwarePcodeStoreSafety.uniqueTarget(destinations);
    }
    private static List<Long> edges(Instruction i,Function fun){
        LinkedHashSet<Long> out=new LinkedHashSet<>();
        Address fall=i.getFallThrough();
        if(fall!=null && fun.getBody().contains(fall))out.add(fall.getOffset());
        if(!i.getFlowType().isCall())for(Address flow:i.getFlows())
            if(fun.getBody().contains(flow))out.add(flow.getOffset());
        return new ArrayList<>(out);
    }
    private static boolean writesMemory(String mnemonic){
        return switch(mnemonic){
            case "MOVE","CLR","ANDI","ORI","EORI","BCLR","BSET","ADD","SUB",
                "ADDI","SUBI","NEG","NOT" -> true;
            default -> false;
        };
    }
    private static HardwareDataflow.Step translate(Instruction i,Function function){
        HardwareDataflow.Step modeled=translateCore(i,function);
        // P-code output varnodes expose implicit and multi-register updates
        // invisible to the mnemonic parser (EXG, MOVEM load, LINK/UNLK, etc.).
        // Unknown/partial register definitions invalidate the full A/D
        // constant. Only an explicitly modeled destination can retain its
        // newly computed value.
        LinkedHashSet<String> written=new LinkedHashSet<>();
        PcodeOp[] pcode=i.getPcode();
        if(pcode!=null)for(PcodeOp p:pcode) {
            Varnode out=p.getOutput();
            if(out==null || !out.isRegister())continue;
            Register reg=i.getProgram().getLanguage()
                .getRegister(out.getAddress(),out.getSize());
            if(reg==null)continue;
            Register base=reg.getBaseRegister();
            String name=(base==null?reg:base).getName().toUpperCase(Locale.ROOT);
            if(name.matches("[AD][0-7]"))written.add(name);
        }
        for(int slot=0;slot<i.getNumOperands();slot++)
            written.addAll(HardwareAutoUpdateRegisters.changedByOperand(op(i,slot)));
        return modeled.withSideEffects(
            HardwareAutoUpdateRegisters.unmodeledOutputs(
                modeled.kind,modeled.register,written));
    }

    private static HardwareDataflow.Step translateCore(Instruction i,Function function){
        String m=opcode(i), full=i.getMnemonicString().toUpperCase(Locale.ROOT);
        List<Long> next=edges(i,function);
        int last=i.getNumOperands()-1;
        long pc=i.getAddress().getOffset();
        if(i.getFlowType().isCall())
            return new HardwareDataflow.Step(pc,HardwareDataflow.Kind.CALL_BARRIER,
                null,0,0,null,0,next,full);
        if(m.equals("MOVEC") && op(i,last).equals("VBR"))
            return new HardwareDataflow.Step(pc,HardwareDataflow.Kind.VBR_FROM_REGISTER,
                plainReg(i,0),0,0,null,0,next,full);
        String dst=plainReg(i,last),src=plainReg(i,0);
        Long imm=i.getNumOperands()==2?immediate(i,0):null;
        if(dst!=null){
            // MOVE.W into Dn preserves unknown upper bits; it must not be
            // promoted to a full 24-bit address-register/constant value.
            boolean fullOverwrite=m.equals("MOVEQ")||
                full.endsWith(".L")||m.equals("MOVEA");
            if((m.equals("MOVE")||m.equals("MOVEA")||m.equals("MOVEQ"))&&
                    imm!=null&&fullOverwrite){
                long v=imm;
                if(m.equals("MOVEQ")&&(v&0x80)!=0)v|=0xffffff00L;
                if(m.equals("MOVEA")&&full.endsWith(".W")&&(v&0x8000)!=0)
                    v|=0xffff0000L;
                return new HardwareDataflow.Step(pc,HardwareDataflow.Kind.SET_POINTER,
                    dst,v,0,null,0,next,full);
            }
            if(m.equals("LEA") && i.getNumOperands()==2){
                Long addr=absolute(i,0);
                if(addr!=null)return new HardwareDataflow.Step(pc,
                    HardwareDataflow.Kind.SET_POINTER,dst,addr,0,null,0,next,full);
            }
            if((m.equals("MOVE")||m.equals("MOVEA"))&&src!=null &&
                    full.endsWith(".L")){
                return new HardwareDataflow.Step(pc,HardwareDataflow.Kind.COPY_POINTER,
                    dst,src,0,0,null,0,next,full);
            }
            if(imm!=null&&(m.equals("ADDA")||m.equals("SUBA")||
                    m.equals("ADDQ")||m.equals("SUBQ"))){
                long signed=imm;
                if((m.equals("ADDA")||m.equals("SUBA"))&&
                        full.endsWith(".W")&&(signed&0x8000L)!=0)
                    signed|=0xffff0000L;
                return new HardwareDataflow.Step(pc,HardwareDataflow.Kind.ADJUST_POINTER,
                    dst,m.startsWith("SUB")?-signed:signed,0,null,0,next,full);
            }
            return new HardwareDataflow.Step(pc,HardwareDataflow.Kind.CLOBBER_POINTER,
                dst,0,0,null,0,next,full);
        }
        if(last>=0&&writesMemory(m)){
            Long address=absolute(i,last);
            String pointer=indirectReg(i,last);
            HardwareIndexedAddress.Expression indexed =
                HardwareIndexedAddress.parse(op(i,last));
            Integer word=null;String from=m.equals("MOVE")?src:null;
            int width=full.endsWith(".W")?16:full.endsWith(".L")?32:
                full.endsWith(".B")?8:0;
            if(width==16&&m.equals("CLR"))word=0;
            if(width==16&&m.equals("MOVE")&&imm!=null)word=(int)(imm&0xffff);
            if(!m.equals("MOVE"))from=null;
            if(address==null && pointer==null && indexed==null)
                address=pcodeStore(i);
            if(indexed!=null)return new HardwareDataflow.Step(pc,
                indexed.base(),from,indexed.index(),indexed.indexBits(),
                indexed.scale(),indexed.displacement(),word,width,next,full);
            if(address!=null)return new HardwareDataflow.Step(pc,
                HardwareDataflow.Kind.STORE_DIRECT,null,from,address,0,word,width,next,full);
            if(pointer!=null)return new HardwareDataflow.Step(pc,
                HardwareDataflow.Kind.STORE_INDIRECT,pointer,from,0,
                displacement(i,last),word,width,next,full);
        }
        // Includes unmodeled MOVEM, stack/predecrement and other P-code
        // STORE operations. Unknown alias may overwrite an earlier SIMCR,
        // CSBAR or TRAMBAR value and must invalidate peripheral snapshots.
        if(hasPcodeStore(i))
            return new HardwareDataflow.Step(pc,
                HardwareDataflow.Kind.STORE_INDIRECT,null,0,0,null,0,next,full);
        return new HardwareDataflow.Step(pc,HardwareDataflow.Kind.OTHER,
            null,0,0,null,0,next,full);
    }
    private static String csEpoch(HardwareDataflow.Snapshot hit,String changed,
            long base,int mm){
        Map<Long,Integer> values=hit.knownPeripheralWords;
        StringBuilder report=new StringBuilder();
        int from=0,to=10;
        if(changed.equals("CSPAR0")){from=-1;to=5;}
        if(changed.equals("CSPAR1")){from=6;to=10;}
        if(changed.startsWith("CSBAR")||changed.startsWith("CSOR")){
            String suffix=changed.startsWith("CSBAR")?
                changed.substring(5):changed.substring(4);
            int cs=suffix.equals("BT")?-1:Integer.parseInt(suffix);
            from=cs;to=cs;
        }
        ChipSelectModel.Decoder model=new ChipSelectModel.Decoder(
            "MC68332","MC68332 mapping hypothesis; CFG local only");
        for(int cs=from;cs<=to;cs++){
            String suffix=cs<0?"BT":String.valueOf(cs);
            long offset=cs<0?0:4L*(cs+1);
            Integer bar=values.get(base+0xa48+offset);
            Integer or=values.get(base+0xa4a+offset);
            Integer par=values.get(base+(cs<=5?0xa44:0xa46));
            if(bar==null)continue;
            ChipSelectModel.Window win=model.window(cs,bar,or,par);
            report.append("  - snapshot after write, address-map candidate MM=")
                .append(mm).append(": ").append(win.toSummary()).append("\n");
        }
        return report.toString();
    }
    private static final class CallerFrame {
        final Function function;
        final String chain;
        final int depth;
        final LinkedHashSet<Long> seen;
        CallerFrame(Function f,String chain,int depth,LinkedHashSet<Long> seen){
            function=f;this.chain=chain;this.depth=depth;this.seen=seen;
        }
    }
    private static String callerAncestors(Program program,Function function){
        // Direct-call XREF chains are possibilities only. They do not resolve
        // dynamic dispatch, indirect calls, reset vectors or branch conditions.
        java.util.ArrayDeque<CallerFrame> frontier=new java.util.ArrayDeque<>();
        LinkedHashSet<Long> initial=new LinkedHashSet<>();
        initial.add(function.getEntryPoint().getOffset());
        frontier.add(new CallerFrame(function,function.getName(),0,initial));
        StringBuilder lines=new StringBuilder();
        int found=0;
        while(!frontier.isEmpty() && found<5){
            CallerFrame at=frontier.removeFirst();
            if(at.depth>=3)continue;
            ReferenceIterator refs=program.getReferenceManager()
                .getReferencesTo(at.function.getEntryPoint());
            int cap=0;
            while(refs.hasNext() && cap++<80 && found<5){
                Reference ref=refs.next();
                if(!ref.getReferenceType().isCall())continue;
                Function caller=program.getFunctionManager()
                    .getFunctionContaining(ref.getFromAddress());
                if(caller==null)continue;
                long id=caller.getEntryPoint().getOffset();
                if(at.seen.contains(id))continue;
                String path=caller.getName()+" [call site "+ref.getFromAddress()+"] -> "+at.chain;
                lines.append("  - possible static-call ancestor chain (depth ")
                    .append(at.depth+1).append("): ").append(path).append("\n");
                found++;
                LinkedHashSet<Long> branch=new LinkedHashSet<>(at.seen);
                branch.add(id);
                frontier.add(new CallerFrame(caller,path,at.depth+1,branch));
            }
        }
        return lines.toString();
    }
    /**
     * Candidate boot vector and direct-call graph. The zero address is only
     * inspected for a compatible 68000 big-endian language. Reset vectors,
     * static edges and MMIO sightings are NOT evidence that code ran.
     */
    private record ResetCandidates(String markdown,java.util.Set<Long> visited,
            boolean recognized,boolean incomplete) {}
    private static ResetCandidates resetStaticCandidates(Program program,
            List<HardwareCallEffects.FunctionNode> graph,
            List<Long> evidencedFunctions) {
        StringBuilder md=new StringBuilder();
        md.append("## Candidate RESET vector and bounded static-call paths\n\n");
        String language=program.getLanguageID().toString().toUpperCase(Locale.ROOT);
        if(!language.startsWith("68000:BE:")){
            md.append("- Not evaluated: this program is not a 68000 big-endian "+
                "language. No reset-vector format is assumed.\n\n");
            return new ResetCandidates(md.toString(),java.util.Set.of(),false,true);
        }
        Address zero=program.getAddressFactory().getDefaultAddressSpace().getAddress(0);
        if(!program.getMemory().contains(zero)){
            md.append("- UNKNOWN: address 0 is not mapped; no candidate "+
                "vector can be read. No assumption about ROM base/relocation.\n\n");
            return new ResetCandidates(md.toString(),java.util.Set.of(),false,true);
        }
        byte[] data=new byte[8];
        try {
            if(program.getMemory().getBytes(zero,data)!=data.length){
                md.append("- UNKNOWN: reset vector at image 0 is incomplete.\n\n");
                return new ResetCandidates(md.toString(),java.util.Set.of(),false,true);
            }
        }catch(MemoryAccessException e){
            md.append("- UNKNOWN: reset vector bytes at image 0 "+
                "could not be read.\n\n");
            return new ResetCandidates(md.toString(),java.util.Set.of(),false,true);
        }
        HardwareResetFlow.Vector vector=HardwareResetFlow.readVector(data);
        md.append("- Image-zero vector candidate SP: ")
          .append(String.format(Locale.ROOT,"0x%08X",vector.initialSp()))
          .append("; PC: ")
          .append(String.format(Locale.ROOT,"0x%08X",vector.resetPc()))
          .append("; plausible: ").append(vector.valid())
          .append("; ").append(vector.reason()).append("\n");
        if(!vector.valid()){
            md.append("- No direct-call path inferred from invalid vector.\n\n");
            return new ResetCandidates(md.toString(),java.util.Set.of(),false,true);
        }
        Address reset;
        try {
            reset=program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(vector.resetPc());
        }catch(RuntimeException invalidAddress){
            md.append("- UNKNOWN: reset PC is outside the current program "+
                "address space.\n\n");
            return new ResetCandidates(md.toString(),java.util.Set.of(),false,true);
        }
        Function root=program.getFunctionManager().getFunctionContaining(reset);
        if(root==null){
            md.append("- UNKNOWN: reset PC is not contained in a recognized "+
                "Ghidra function. No candidate execution path is asserted.\n\n");
            return new ResetCandidates(md.toString(),java.util.Set.of(),false,true);
        }
        md.append("- Function containing vector PC: ").append(root.getName())
          .append(" at ").append(root.getEntryPoint())
          .append("; candidate only, not verified entry execution.\n");
        HardwareResetFlow.Summary candidate=HardwareResetFlow.trace(
            root.getEntryPoint().getOffset(),graph,evidencedFunctions,6,128,30);
        md.append(candidate.markdown(vector.resetPc(),
            root.getEntryPoint().getOffset())).append("\n");
        return new ResetCandidates(md.toString(),candidate.visitedEntries(),
            candidate.rootRecognized(),candidate.unresolved()||candidate.truncated());
    }

    public Report analyze(Program program,TaskMonitor monitor)throws CancelledException{
        return analyze(program,monitor,false);
    }
    public Report analyze(Program program,TaskMonitor monitor,
            boolean mc68332Selected)throws CancelledException{
        if(program==null)throw new IllegalArgumentException("Open Ghidra program required");
        if(monitor==null)monitor=TaskMonitor.DUMMY;
        Map<Long,String> targets=new LinkedHashMap<>();
        HardwareProfiles.Profile p=HardwareProfiles.mc68332();
        for(HardwareProfiles.Register r:p.registers)
            for(int mm=0;mm<2;mm++)targets.put(p.absoluteAddress(r,mm),r.name);
        StringBuilder detail=new StringBuilder();
        List<HardwareCallEffects.FunctionNode> staticCalls=new ArrayList<>();
        List<Long> evidencedFunctions=new ArrayList<>();
        HardwareEvidenceBudget<HardwarePointerRoleReview.Site> pointerSites=
            new HardwareEvidenceBudget<>(MAX_POINTER_ROLE_SITES);
        HardwareEvidenceBudget<HardwareCfgWriteAudit.Site> cfgMmioSites=
            new HardwareEvidenceBudget<>(MAX_CFG_MMIO_SITES);
        List<HardwareCfgStorePaths.Pair> cfgStoreRelations=new ArrayList<>();
        List<HardwareSimcrLocalFirst.Result> localFirstPaths=new ArrayList<>();
        int localFirstOmittedFunctions=0;
        int cfgPathLimitedFunctions=0;
        int foundFunctions=0,indirect=0,vbr=0,unresolved=0,visited=0,shown=0;
        boolean limited=false;
        FunctionIterator funs=program.getFunctionManager().getFunctions(true);
        while(funs.hasNext()){
            monitor.checkCancelled();
            Function fun=funs.next();
            List<HardwareDataflow.Step> steps=new ArrayList<>();
            List<Long> directCallees=new ArrayList<>();
            boolean localStore=false,localVbr=false,uncertainFlow=false;
            long decodedBytes=0;
            InstructionIterator it=program.getListing().getInstructions(fun.getBody(),true);
            while(it.hasNext()){
                monitor.checkCancelled();
                Instruction insn=it.next();
                decodedBytes+=insn.getLength();
                PcodeOp[] ops=insn.getPcode();
                if(ops!=null)for(PcodeOp op:ops){
                    if(op.getOpcode()==PcodeOp.STORE)localStore=true;
                    if(op.getOpcode()==PcodeOp.CALLOTHER)uncertainFlow=true;
                }
                String mnemonic=opcode(insn);
                if(mnemonic.equals("MOVEC") &&
                        op(insn,insn.getNumOperands()-1).equals("VBR"))
                    localVbr=true;
                if(insn.getFlowType().isComputed())
                    uncertainFlow=true;
                if(insn.getFlowType().isJump()) {
                    // A direct tail-jump outside the current Function can
                    // behave like a call to other code without a CALL opcode.
                    // Never classify its effect as a closed/no-store graph.
                    Address[] jumpTargets=insn.getFlows();
                    if(jumpTargets==null || jumpTargets.length==0)
                        uncertainFlow=true;
                    else for(Address destination:jumpTargets)
                        if(!fun.getBody().contains(destination))
                            uncertainFlow=true;
                }
                if(insn.getFlowType().isCall()){
                    Address[] destinations=insn.getFlows();
                    if(destinations==null || destinations.length!=1)
                        uncertainFlow=true;
                    else {
                        Function callee=program.getFunctionManager()
                            .getFunctionAt(destinations[0]);
                        if(callee==null)uncertainFlow=true;
                        else directCallees.add(callee.getEntryPoint().getOffset());
                    }
                }
                steps.add(translate(insn,fun));
            }
            // Undecoded bytes inside the Ghidra function body are not proof
            // of absence of hidden memory operations/call targets.
            if(decodedBytes!=fun.getBody().getNumAddresses())
                uncertainFlow=true;
            staticCalls.add(new HardwareCallEffects.FunctionNode(
                fun.getEntryPoint().getOffset(),localStore,localVbr,
                uncertainFlow,directCallees));
            if(steps.isEmpty())continue;
            HardwareDataflow.Result result=HardwareDataflow.analyze(
                fun.getEntryPoint().getOffset(),steps,targets.keySet(),
                Math.min(30000,Math.max(300,steps.size()*20)));
            visited+=result.reachedNodes;
            limited|=result.truncated;
            for(HardwareDataflow.Snapshot hit:result.snapshots){
                if(!hit.indirect || hit.effectiveAddress==null ||
                        hit.pointerRegister==null ||
                        !hit.pointerRegister.matches("A[0-7]"))continue;
                for(HardwareProfiles.Register reg:p.registers) {
                    int matchedMm=-1;
                    if(p.absoluteAddress(reg,0)==hit.effectiveAddress)matchedMm=0;
                    if(p.absoluteAddress(reg,1)==hit.effectiveAddress)matchedMm=1;
                    if(matchedMm<0)continue;
                    pointerSites.offer(new HardwarePointerRoleReview.Site(
                        fun.getEntryPoint().getOffset(),fun.getName(),hit.instruction,
                        hit.pointerRegister,reg.module,matchedMm,reg.name,
                        result.truncated || uncertainFlow ||
                            hit.priorUnknownCall || hit.priorUnknownStore));
                    break;
                }
            }
            for(HardwareDataflow.Snapshot hit:result.snapshots) {
                if(hit.kind!=HardwareDataflow.Kind.STORE_DIRECT &&
                        hit.kind!=HardwareDataflow.Kind.STORE_INDIRECT)continue;
                String target=hit.effectiveAddress==null?null:
                    targets.get(hit.effectiveAddress);
                if(target==null &&
                        !(hit.kind==HardwareDataflow.Kind.STORE_INDIRECT &&
                          hit.effectiveAddress==null))continue;
                cfgMmioSites.offer(new HardwareCfgWriteAudit.Site(
                    fun.getEntryPoint().getOffset(),hit.instruction,
                    target==null?"UNRESOLVED_ALIAS":target,
                    hit.effectiveAddress==null?-1L:hit.effectiveAddress,
                    hit.indirect,hit.writeBits,hit.writtenWord,
                    hit.priorMmCandidateMin,hit.priorMmCandidateMax,
                    hit.priorUnknownCall,hit.priorUnknownStore,
                    result.truncated || uncertainFlow));
            }
            if(mc68332Selected) {
                // Separate function-local CFG path alternatives from the
                // global reset/latch question. The entry may itself be
                // statically unreachable from the real hardware reset.
                boolean foundSimcr=false;
                java.util.Map<Long,HardwareSimcrLocalFirst.Effect> effects=
                    new java.util.HashMap<>();
                java.util.Map<Long,Integer> words=new java.util.HashMap<>();
                for(HardwareDataflow.Step step:steps)
                    if(step.kind==HardwareDataflow.Kind.CALL_BARRIER)
                        effects.put(step.address,
                            HardwareSimcrLocalFirst.Effect.ALIAS_OR_CALL_BARRIER);
                for(HardwareDataflow.Snapshot hit:result.snapshots){
                    if(hit.kind!=HardwareDataflow.Kind.STORE_DIRECT &&
                            hit.kind!=HardwareDataflow.Kind.STORE_INDIRECT)
                        continue;
                    HardwareSimcrLocalFirst.Effect next=null;
                    Integer word=null;
                    if(hit.effectiveAddress!=null &&
                            "SIMCR".equals(targets.get(hit.effectiveAddress))){
                        foundSimcr=true;
                        if(hit.writeBits==16 && hit.writtenWord!=null){
                            next=HardwareSimcrLocalFirst.Effect.WORD_LITERAL;
                            word=hit.writtenWord;
                        }else next=HardwareSimcrLocalFirst.Effect.UNKNOWN_WORD;
                    }else if(hit.indirect && hit.effectiveAddress==null)
                        next=HardwareSimcrLocalFirst.Effect.ALIAS_OR_CALL_BARRIER;
                    if(next==null)continue;
                    var previous=effects.putIfAbsent(hit.instruction,next);
                    if(previous!=null &&
                            (previous!=HardwareSimcrLocalFirst.Effect.WORD_LITERAL ||
                             next!=HardwareSimcrLocalFirst.Effect.WORD_LITERAL ||
                             !java.util.Objects.equals(words.get(hit.instruction),word))){
                        // Multiple P-code stores at one PC may be
                        // competing values; don't invent intra-PC order.
                        effects.put(hit.instruction,
                            HardwareSimcrLocalFirst.Effect.UNKNOWN_WORD);
                        words.remove(hit.instruction);
                    }else if(previous==null && word!=null)
                        words.put(hit.instruction,word);
                }
                if(foundSimcr){
                    if(steps.size()>50000 || localFirstPaths.size()>=75)
                        localFirstOmittedFunctions++;
                    else {
                        List<HardwareSimcrLocalFirst.Node> graph=new ArrayList<>();
                        for(HardwareDataflow.Step step:steps){
                            var effect=effects.getOrDefault(step.address,
                                HardwareSimcrLocalFirst.Effect.NONE);
                            graph.add(new HardwareSimcrLocalFirst.Node(
                                step.address,step.successors,effect,
                                effect==HardwareSimcrLocalFirst.Effect.WORD_LITERAL?
                                    words.get(step.address):null));
                        }
                        localFirstPaths.add(HardwareSimcrLocalFirst.inspect(
                            fun.getEntryPoint().getOffset(),steps.get(0).address,
                            graph,uncertainFlow || result.truncated,1500));
                    }
                }
            }
            if(mc68332Selected){
                List<HardwareCfgStorePaths.Store> pathStores=new ArrayList<>();
                for(HardwareDataflow.Snapshot hit:result.snapshots){
                    if(hit.effectiveAddress==null ||
                            (hit.kind!=HardwareDataflow.Kind.STORE_DIRECT &&
                             hit.kind!=HardwareDataflow.Kind.STORE_INDIRECT))continue;
                    String register=targets.get(hit.effectiveAddress);
                    if(register==null ||
                            !(register.equals("SIMCR") || register.equals("TRAMBAR") ||
                              register.startsWith("CSBAR") || register.startsWith("CSOR") ||
                              register.startsWith("CSPAR")))continue;
                    pathStores.add(new HardwareCfgStorePaths.Store(hit.instruction,register));
                }
                // A function may have repeated P-code STORE sites at one
                // instruction, or huge disassembly. Both are UNCERTAIN,
                // not a reason to abort the whole hardware analysis.
                java.util.LinkedHashMap<Long,HardwareCfgStorePaths.Store> uniqueStores=
                    new java.util.LinkedHashMap<>();
                for(var store:pathStores)
                    if(uniqueStores.putIfAbsent(store.pc(),store)!=null)
                        cfgPathLimitedFunctions++;
                pathStores=new ArrayList<>(uniqueStores.values());
                if(pathStores.size()>1 && steps.size()>50000){
                    cfgPathLimitedFunctions++;
                }else if(pathStores.size()>1 && cfgStoreRelations.size()<500){
                    List<HardwareCfgStorePaths.Node> pathNodes=new ArrayList<>();
                    for(HardwareDataflow.Step node:steps)
                        pathNodes.add(new HardwareCfgStorePaths.Node(
                            node.address,node.successors));
                    var pairs=HardwareCfgStorePaths.analyze(
                        fun.getEntryPoint().getOffset(),pathNodes,pathStores,
                        uncertainFlow || result.truncated,1500);
                    if(pairs.truncated())cfgPathLimitedFunctions++;
                    if(cfgStoreRelations.size()+pairs.relations().size()<=500)
                        cfgStoreRelations.addAll(pairs.relations());
                    else cfgPathLimitedFunctions++;
                }else if(pathStores.size()>1)cfgPathLimitedFunctions++;
            }
            List<HardwareDataflow.Snapshot> found=new ArrayList<>();
            for(HardwareDataflow.Snapshot hit:result.snapshots){
                if(hit.kind==HardwareDataflow.Kind.VBR_FROM_REGISTER){
                    found.add(hit);vbr++;
                } else if(hit.effectiveAddress!=null &&
                        targets.containsKey(hit.effectiveAddress) &&
                        HardwareReportScope.isInitializationRegister(
                            targets.get(hit.effectiveAddress))){
                    found.add(hit);
                    if(hit.indirect)indirect++;
                } else if(hit.kind==HardwareDataflow.Kind.STORE_INDIRECT &&
                        hit.effectiveAddress==null){
                    unresolved++;
                }
            }
            if(found.isEmpty())continue; // Retain global truncation warning, omit unrelated functions.
            foundFunctions++;
            evidencedFunctions.add(fun.getEntryPoint().getOffset());
            if(shown>=350)continue;
            detail.append("### ").append(fun.getName()).append(" at ")
                .append(fun.getEntryPoint()).append("\n\n");
            int callers=0;
            ReferenceIterator refs=program.getReferenceManager()
                .getReferencesTo(fun.getEntryPoint());
            StringBuilder callerSites=new StringBuilder();
            while(refs.hasNext()){
                Reference reference=refs.next();
                if(!reference.getReferenceType().isCall())continue;
                callers++;
                if(callers<=6){
                    Function caller=program.getFunctionManager()
                        .getFunctionContaining(reference.getFromAddress());
                    callerSites.append("- Static caller reference ")
                        .append(reference.getFromAddress()).append(" in ")
                        .append(caller==null?"UNKNOWN":caller.getName())
                        .append(" (not proof of runtime execution)\n");
                }
            }
            detail.append(callerAncestors(program,fun));
            detail.append("- CFG nodes reached: ").append(result.reachedNodes)
                .append("; direct call references: ").append(callers)
                .append("; propagation limit: ").append(result.truncated).append("\n")
                .append(callerSites);
            for(HardwareDataflow.Snapshot hit:found){
                if(shown++>=350)break;
                detail.append("- PC ")
                    .append(ChipSelectModel.hex(hit.instruction,6)).append(": ");
                if(hit.kind==HardwareDataflow.Kind.VBR_FROM_REGISTER){
                    detail.append("MOVEC to VBR; source inferred value ")
                        .append(hit.vbr==null?"UNKNOWN":ChipSelectModel.hex(hit.vbr,6));
                }else{
                    String name=targets.get(hit.effectiveAddress);
                    detail.append(name).append(" at ")
                        .append(ChipSelectModel.hex(hit.effectiveAddress,6))
                        .append(hit.indirect?" [CFG-resolved indirect/indexed candidate]":" [direct/P-code]")
                        .append(" value ")
                        .append(hit.writtenWord==null?"UNKNOWN":
                            ChipSelectModel.hex(hit.writtenWord,4));
                    int mm=hit.effectiveAddress<0x800000?0:1;
                    long base=mm==0?0x7ff000L:0xfff000L;
                    if(name.equals("SIMCR")) {
                        if(hit.writtenWord!=null)
                            detail.append(" ; candidate MM=")
                                .append((hit.writtenWord&0x40)!=0?1:0);
                        detail.append(" ; earlier matched SIMCR writes within FUNCTION "+
                            "CFG (0/1/2+): ")
                            .append(hit.priorMmCandidateMin==2?"2+":
                                Integer.toString(hit.priorMmCandidateMin))
                            .append("..")
                            .append(hit.priorMmCandidateMax==2?"2+":
                                Integer.toString(hit.priorMmCandidateMax))
                            .append("; unknown called-code effects=")
                            .append(hit.priorUnknownCall)
                            .append("; earlier unknown-destination STORE=")
                            .append(hit.priorUnknownStore)
                            .append("; MM write-once after reset: first successful "+
                                "write UNKNOWN");
                    }
                    if(name.startsWith("CSBAR")||name.startsWith("CSOR")||
                            name.startsWith("CSPAR")){
                        detail.append("\n").append(csEpoch(hit,name,base,mm));
                    }
                    if(name.equals("TRAMBAR") && hit.writtenWord!=null){
                        long ramBase=((long)(hit.writtenWord&0xfff8)<<8)&0xffffffL;
                        detail.append(" ; possible MC68332 TPURAM=")
                            .append(ChipSelectModel.hex(ramBase,6)).append("..")
                            .append(ChipSelectModel.hex(ramBase+2047,6))
                            .append(" [not active until MCU/reset state verified]");
                    }
                }
                detail.append("\n");
            }
            detail.append("\n");
        }
        // This is a call-tree MAY-effect inventory. No callee state is
        // imported into callers, and none of these paths are known to execute.
        StringBuilder effects=new StringBuilder();
        effects.append("## Bounded transitive static-call side-effect inventory\n\n")
            .append("Potential callee memory STORE and MOVEC VBR effects from "+
                "recognized function references only. Unknown targets, "+
                "computed branches, cycles, gaps and limits are explicit. "+
                "No reset-path or hardware MM latch is inferred.\n\n");
        int sideEffectsShown=0;
        for(long entry:evidencedFunctions){
            if(sideEffectsShown>=60)break;
            HardwareCallEffects.Summary summary=HardwareCallEffects.summarize(
                entry,staticCalls,4,100);
            effects.append("- Function ").append(ChipSelectModel.hex(entry,6))
                .append(": ").append(summary.description()).append("\n");
            sideEffectsShown++;
        }
        if(evidencedFunctions.size()>sideEffectsShown)
            effects.append("- Additional functions omitted by 60-row limit.\n");
        effects.append("\n");

        ResetCandidates reset=resetStaticCandidates(program,staticCalls,evidencedFunctions);
        StringBuilder out=new StringBuilder();
        out.append("## CFG/P-code initialization evidence (SIMCR/MM, TRAMBAR, CSBAR, CSOR, VBR)\n\n")
           .append("Only predecessor-agreed intraprocedural constants survive branch joins. ")
           .append("Calls and unknown-destination memory stores invalidate "+
               "previous peripheral constants; ")
           .append("indirect jumps, pointer aliases and real execution are not proven.\n")
           .append("SIMCR write histories are bounded *local* candidate counts, "+
               "NOT counts since the hardware reset. Unresolved indirect writes "+
               "and callers can add unknown writes; MM bit is write-once after reset.\n\n")
           .append("- Evidence functions: ").append(foundFunctions).append("\n")
           .append("- Reachable instruction nodes: ").append(visited).append("\n")
           .append("- Register-indirect matched writes: ").append(indirect).append("\n")
           .append("- VBR control-register sites: ").append(vbr).append("\n")
           .append("- Unresolved register-based stores: ").append(unresolved).append("\n")
           .append("- Propagation cap reached: ").append(limited).append("\n\n")
           .append(reset.markdown())
           .append(GhidraInterruptVectorService.analyze(program,monitor))
           .append(detail).append(effects);
        if(shown>=350)out.append("\n[Detailed report bounded at 350 sites.]\n");
        boolean cfgSourcesComplete=cfgMmioSites.safeAsComplete(!limited);
        out.append("\n- Bounded CFG source capture: ")
            .append(cfgMmioSites.provenance()).append("; pointer hints: ")
            .append(pointerSites.provenance())
            .append("; CSBAR source Review eligible for complete evidence: ")
            .append(cfgSourcesComplete)
            .append(". Missing sites MUST NOT be inferred as absent.\n");
        List<HardwarePointerRoleReview.Proposal> roles=
            HardwarePointerRoleReview.propose(mc68332Selected,pointerSites.snapshot(),
                limited || pointerSites.truncated());
        out.append(HardwarePointerRoleReview.report(roles));
        out.append(HardwareCfgWriteAudit.inspect(mc68332Selected,
            cfgMmioSites.snapshot()).markdown());
        out.append(HardwareCfgStorePaths.markdown(
            cfgStoreRelations,cfgPathLimitedFunctions));
        out.append(mc68332Selected?
            HardwareSimcrLocalFirst.markdown(localFirstPaths,localFirstOmittedFunctions):
            "## Possible local first SIMCR sites\\n\\nGeneric CPU32: explicit "+
            "MC68332 profile required for these candidate source paths.\\n\\n");
        String evidenceCsv=HardwareConfigurationEvidenceCsv.serialize(
            HardwareCfgWriteAudit.inspect(mc68332Selected,cfgMmioSites.snapshot()),
            cfgStoreRelations,mc68332Selected);
        return new Report(out.toString(),foundFunctions,indirect,vbr,unresolved,
            visited,limited || !cfgSourcesComplete || pointerSites.truncated(),
            roles,reset.visited(),reset.recognized(),reset.incomplete(),
            evidenceCsv,cfgMmioSites.snapshot(),
            cfgSourcesComplete,cfgMmioSites.omitted(),pointerSites.omitted());
    }
}
