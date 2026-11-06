package ghidrassist.hardware;

import ghidrassist.automation.AutomationCallPaths;
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
    private static final HardwareFunctionStageCache<Program> FUNCTION_STAGES=
        new HardwareFunctionStageCache<>();

    /** Read-only count of process-local completed function CFG checkpoints. */
    public static int checkpointedFunctionStages(Program program){
        return program==null?0:FUNCTION_STAGES.completed(program);
    }
    /** Explicit revision/authorization invalidation also retires function stages. */
    public static void invalidateFunctionStages(Program program){
        if(program!=null)FUNCTION_STAGES.invalidate(program);
    }
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
        return HardwareRegisterOperand.sourceOrDestination(
            op(i,slot),i.getMnemonicString());
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
        // Ghidra renders CPU32 MOVEQ #-1,D1 as "-0x1" (no '#').
        // Its encoded signed 8-bit immediate is unambiguous; for all
        // other instructions retain the original explicit marker gate.
        if(!HardwareRegisterOperand.isImmediateToken(
                op(i,slot),i.getMnemonicString()))return null;
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
                int adjustedBits=HardwareDataflow.registerAdjustWidth(dst,full);
                // A missing size for Dn cannot be modeled as long-register
                // arithmetic. ADDQ.W #1,Dn keeps its upper word intact.
                if(adjustedBits==0)return new HardwareDataflow.Step(pc,
                    HardwareDataflow.Kind.CLOBBER_POINTER,
                    dst,0,0,null,0,next,full);
                return new HardwareDataflow.Step(pc,HardwareDataflow.Kind.ADJUST_POINTER,
                    dst,m.startsWith("SUB")?-signed:signed,0,null,
                    adjustedBits,next,full);
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
    /**
     * Strict Ghidra Listing gate. Supports either a simple unconditional
     * leaf or a bounded acyclic conditional-branch leaf where ALL paths
     * produce agreeing output registers before an ordinary RTS. No unknown
     * P-code effects, out-of-function jumps or incomplete body accepted.
     */
    /**
     * Single-hop source-only callee input. A closed, contiguous, fully
     * disassembled local body is required; any nested CALL, computed flow,
     * off-body jump, CALLOTHER or truncated function rejects the candidate.
     * This is NOT a verified output summary for the caller and is not cached.
     */
    /**
     * Exact and fully decoded single nested CALL bridge for GA-02/03.
     * Ghidra's actual Listing and exact function-entry CALL target are
     * required; no other calls, stores, CALLOTHER, computed/outside jumps
     * or hidden undecoded bytes may provide a propagated register context.
     * A CALL may push return PC on A7, handled by the separate pure solver.
     */
    private static HardwareTwoHopRegisterFlow.Bridge contextualBridge(
            Program program,Function middle,TaskMonitor monitor)
            throws CancelledException {
        if(middle==null)return null;
        long entry=middle.getEntryPoint().getOffset();
        long bodyBytes=middle.getBody().getNumAddresses();
        if(bodyBytes<8 || bodyBytes>
                HardwareTwoHopRegisterFlow.MAX_BRIDGE_STEPS*16L)
            return null;
        List<HardwareDataflow.Step> steps=new ArrayList<>();
        long pc=entry,innerPc=-1;
        Long innerEntry=null;
        int calls=0;
        boolean complete=true;
        InstructionIterator it=program.getListing()
            .getInstructions(middle.getBody(),true);
        while(it.hasNext()){
            monitor.checkCancelled();
            Instruction insn=it.next();
            if(steps.size()>=HardwareTwoHopRegisterFlow.MAX_BRIDGE_STEPS ||
                    insn.getAddress().getOffset()!=pc ||
                    insn.getFlowType().isComputed()){
                complete=false;break;
            }
            boolean isCall=insn.getFlowType().isCall();
            PcodeOp[] ops=insn.getPcode();
            if(ops!=null)for(PcodeOp op:ops)
                if(op.getOpcode()==PcodeOp.CALLOTHER ||
                        // CPU32 JSR itself pushes the return PC. The
                        // injected context never includes the original A7.
                        op.getOpcode()==PcodeOp.STORE && !isCall)
                    complete=false;
            if(insn.getFlowType().isJump()){
                Address[] flows=insn.getFlows();
                if(flows==null || flows.length==0)complete=false;
                else for(Address dst:flows)
                    if(!middle.getBody().contains(dst))complete=false;
            }
            if(!complete)break;
            if(isCall) {
                calls++;
                if(calls!=1){complete=false;break;}
                innerPc=pc;
                Address[] flows=insn.getFlows();
                if(flows!=null && flows.length==1){
                    Function leaf=program.getFunctionManager().getFunctionAt(
                        flows[0]);
                    if(leaf!=null)
                        innerEntry=leaf.getEntryPoint().getOffset();
                }
            }
            steps.add(translate(insn,middle));
            pc+=insn.getLength();
        }
        if(calls!=1)return null;
        return new HardwareTwoHopRegisterFlow.Bridge(
            entry,steps,innerPc,innerEntry,complete &&
            pc-entry==bodyBytes);
    }

    private static HardwareCallsiteRegisterFlow.Callee contextualCallee(
            Program program,Function callee,TaskMonitor monitor)
            throws CancelledException{
        if(callee==null)return null;
        long entry=callee.getEntryPoint().getOffset();
        long bodyBytes=callee.getBody().getNumAddresses();
        if(bodyBytes<2 || bodyBytes>
                HardwareCallsiteRegisterFlow.MAX_CALLEE_STEPS*16L)
            return new HardwareCallsiteRegisterFlow.Callee(
                entry,List.of(),false);
        List<HardwareDataflow.Step> steps=new ArrayList<>();
        long cursor=entry;
        boolean safe=true;
        InstructionIterator it=program.getListing()
            .getInstructions(callee.getBody(),true);
        while(it.hasNext()){
            monitor.checkCancelled();
            Instruction insn=it.next();
            if(steps.size()>=HardwareCallsiteRegisterFlow.MAX_CALLEE_STEPS ||
                    insn.getAddress().getOffset()!=cursor ||
                    insn.getFlowType().isCall() ||
                    insn.getFlowType().isComputed()){
                safe=false;break;
            }
            PcodeOp[] ops=insn.getPcode();
            if(ops!=null)for(PcodeOp op:ops)
                if(op.getOpcode()==PcodeOp.CALLOTHER)
                    safe=false;
            if(insn.getFlowType().isJump()){
                Address[] destinations=insn.getFlows();
                if(destinations==null || destinations.length==0)
                    safe=false;
                else for(Address dst:destinations)
                    if(!callee.getBody().contains(dst))safe=false;
            }
            if(!safe)break;
            steps.add(translate(insn,callee));
            cursor+=insn.getLength();
        }
        return new HardwareCallsiteRegisterFlow.Callee(
            entry,steps,safe && cursor-entry==bodyBytes);
    }

    private static Map<String,Long> verifiedLeafReturn(
            Program program,Function callee,TaskMonitor monitor)
            throws CancelledException{
        if(callee==null || callee.getBody().getNumAddresses()<8 ||
                callee.getBody().getNumAddresses()>
                    HardwareVerifiedBranchReturn.MAX_INSTRUCTIONS*6L)
            return Map.of();
        List<HardwareDataflow.Step> steps=new ArrayList<>();
        Map<Long,Integer> lengths=new LinkedHashMap<>();
        long decoded=0;
        InstructionIterator iterator=program.getListing()
            .getInstructions(callee.getBody(),true);
        while(iterator.hasNext()){
            monitor.checkCancelled();
            if(steps.size()>=HardwareVerifiedBranchReturn.MAX_INSTRUCTIONS)
                return Map.of();
            Instruction instruction=iterator.next();
            if(instruction.getFlowType().isComputed() ||
                    instruction.getFlowType().isCall())
                return Map.of();
            if(instruction.getFlowType().isJump()){
                Address[] destinations=instruction.getFlows();
                if(destinations==null || destinations.length==0)
                    return Map.of();
                for(Address target:destinations)
                    if(!callee.getBody().contains(target))return Map.of();
            }
            decoded+=instruction.getLength();
            lengths.put(instruction.getAddress().getOffset(),
                instruction.getLength());
            steps.add(translate(instruction,callee));
        }
        if(decoded!=callee.getBody().getNumAddresses())
            return Map.of();
        Map<String,Long> simple=HardwareVerifiedLeafReturn.summarize(
            callee.getEntryPoint().getOffset(),decoded,steps);
        if(!simple.isEmpty())return simple;
        return HardwareVerifiedBranchReturn.summarize(
            callee.getEntryPoint().getOffset(),decoded,steps,lengths);
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
        if(!HardwareResetFlow.exactFunctionEntry(vector.resetPc(),
                root.getEntryPoint().getOffset())){
            // A Ghidra body containing RESET PC is not an entry at RESET PC.
            // The prefix from the function entry to RESET PC would be
            // artificially reachable and could include an earlier JSR to
            // MMIO/ISR. Fail closed before computing any direct-CALL subset.
            md.append("- **UNKNOWN RESET ROOT — INTERIOR FUNCTION POINTER:** ")
              .append("vector PC is not a function entry. No CALL graph is ")
              .append("rooted at the containing function's earlier entry; ")
              .append("instructions preceding the vector PC are NOT ")
              .append("reachable evidence. Disassemble/define a genuine entry ")
              .append("at the vector PC in an isolated working copy for ")
              .append("further analysis. Not proof of executed RESET.\n\n");
            return new ResetCandidates(md.toString(),java.util.Set.of(),
                false,true);
        }
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
        return analyze(program,monitor,mc68332Selected,null,null);
    }

    // The disk opt-in is passed exclusively by HardwareFlowStageCache AFTER
    // the exact full Ghidra program and extension JAR were fingerprinted.
    Report analyze(Program program,TaskMonitor monitor,boolean mc68332Selected,
            java.nio.file.Path privateDirectory,
            HardwareDurableStageStore.Key fullInput)throws CancelledException{
        if(program==null)throw new IllegalArgumentException("Open Ghidra program required");
        if(monitor==null)monitor=TaskMonitor.DUMMY;
        long functionEpoch=FUNCTION_STAGES.begin(program);
        HardwareFunctionStageCache.Scope functionScope=
            new HardwareFunctionStageCache.Scope(
                program.getModificationNumber(),
                program.getLanguageID().toString(),
                program.getExecutableSHA256(),mc68332Selected);
        Map<Long,String> targets=new LinkedHashMap<>();
        HardwareProfiles.Profile p=HardwareProfiles.mc68332();
        for(HardwareProfiles.Register r:p.registers)
            for(int mm=0;mm<2;mm++)targets.put(p.absoluteAddress(r,mm),r.name);
        StringBuilder detail=new StringBuilder();
        List<HardwareCallEffects.FunctionNode> staticCalls=new ArrayList<>();
        List<HardwareVbrRelocationEvidence.Site> vbrSourceSites=new ArrayList<>();
        int vbrSourceSitesOmitted=0;
        List<HardwareInterproceduralMmEffects.FunctionNode> mmEffectNodes=
            new ArrayList<>();
        List<HardwareInterproceduralMmEffects.CallSite> mmCallSites=
            new ArrayList<>();
        Map<Long,Map<String,Long>> verifiedLeafByEntry=new HashMap<>();
        List<HardwareCallsiteRegisterFlow.Call> callerContexts=
            new ArrayList<>();
        int callerContextsOmitted=0;
        List<HardwareIndirectCallEvidence.Site> indirectCandidates=
            new ArrayList<>();
        int indirectUnknownCalls=0,indirectCandidatesOmitted=0;
        int provenLeafCallSites=0;
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
        int reusedFunctions=0,computedFunctions=0;
        int restoredDiskFunctions=0,savedDiskFunctions=0,eligibleDiskFunctions=0;
        int restoredMidFunctionWorklists=0,savedMidFunctionWorklists=0;
        boolean limited=false;
        FunctionIterator funs=program.getFunctionManager().getFunctions(true);
        while(funs.hasNext()){
            monitor.checkCancelled();
            Function fun=funs.next();
            List<HardwareDataflow.Step> steps=new ArrayList<>();
            List<Long> directCallees=new ArrayList<>();
            boolean localStore=false,localVbr=false,uncertainFlow=false;
            long decodedBytes=0;
            int firstFunctionCallSite=mmCallSites.size();
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
                if(mc68332Selected && insn.getFlowType().isCall() &&
                        insn.getFlowType().isComputed()) {
                    // Display-only MAY evidence. The same byte-proven
                    // Automation API verifier proves either an adjacent
                    // MOVEA/JSR or <=3 NOP/MOVEQ instructions between
                    // the two. The owner scope checks EVERY instruction
                    // belongs to this exact Function body. Do NOT make
                    // inferred CALL edges, RESET paths, cache checkpoints
                    // or Review/Apply-eligible MMIO writes from this.
                    AutomationCallPaths.BoundedCallSource witness=null;
                    try {
                        witness=AutomationCallPaths
                            .boundedConstantRegisterSource(
                                program,insn,fun);
                    } catch(MemoryAccessException unavailable) {
                        // Incomplete or invalid Ghidra memory is UNKNOWN.
                    }
                    long pc=insn.getAddress().getOffset();
                    if(witness!=null &&
                            fun.getEntryPoint().getOffset()<=
                                HardwareDataflow.MASK24 &&
                            witness.movePc().getOffset()<=
                                HardwareDataflow.MASK24 &&
                            pc<=HardwareDataflow.MASK24 &&
                            witness.target().getOffset()<=
                                HardwareDataflow.MASK24) {
                        if(indirectCandidates.size()<
                                HardwareIndirectCallEvidence.MAX_SITES)
                            indirectCandidates.add(
                                new HardwareIndirectCallEvidence.Site(
                                    fun.getEntryPoint().getOffset(),
                                    witness.movePc().getOffset(),
                                    pc,witness.target().getOffset(),
                                    witness.evidence()));
                        else indirectCandidatesOmitted++;
                    }else indirectUnknownCalls++;
                }
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
                Long callTarget=null;
                if(insn.getFlowType().isCall()){
                    Address[] destinations=insn.getFlows();
                    // Ghidra's getFlows() may contain ONE manually added
                    // COMPUTED_CALL reference for JSR (An). It does not
                    // make that instruction a direct CALL. Only decoded
                    // non-computed CALLs with a single exact Function
                    // entry may populate static RESET/CALL/MMIO/ISR edges.
                    // The separate bounded indirect byte witness is
                    // display-only and NEVER upgrades graph reachability.
                    if(!HardwareDirectCallGate.directCandidate(
                            true,insn.getFlowType().isComputed(),
                            destinations==null?0:destinations.length))
                        uncertainFlow=true;
                    else {
                        Function callee=program.getFunctionManager()
                            .getFunctionAt(destinations[0]);
                        if(callee==null)uncertainFlow=true;
                        else {
                            callTarget=callee.getEntryPoint().getOffset();
                            directCallees.add(callTarget);
                        }
                    }
                    mmCallSites.add(new HardwareInterproceduralMmEffects.CallSite(
                        fun.getEntryPoint().getOffset(),
                        insn.getAddress().getOffset(),callTarget));
                }
                HardwareDataflow.Step translated=translate(insn,fun);
                if(mc68332Selected && callTarget!=null &&
                        verifiedLeafByEntry.size()<256){
                    Map<String,Long> proved=verifiedLeafByEntry.get(callTarget);
                    if(proved==null){
                        Function callee=program.getFunctionManager()
                            .getFunctionAt(insn.getFlows()[0]);
                        proved=verifiedLeafReturn(program,callee,monitor);
                        verifiedLeafByEntry.put(callTarget,proved);
                    }
                    if(!proved.isEmpty()){
                        translated=translated.withVerifiedCallReturns(proved);
                        provenLeafCallSites++;
                    }
                }
                // Ghidra represents some absolute-address MOVE.W stores
                // as P-code COPY to an address-space varnode rather than
                // PcodeOp.STORE. The existing Listing translator recognizes
                // these as STORE_DIRECT. Count BOTH forms as static source
                // memory effects; this is not an MMIO or execution proof.
                if(translated.kind==HardwareDataflow.Kind.STORE_DIRECT ||
                        translated.kind==HardwareDataflow.Kind.STORE_INDIRECT)
                    localStore=true;
                steps.add(translated);
            }
            // Undecoded bytes inside the Ghidra function body are not proof
            // of absence of hidden memory operations/call targets.
            if(decodedBytes!=fun.getBody().getNumAddresses())
                uncertainFlow=true;
            staticCalls.add(new HardwareCallEffects.FunctionNode(
                fun.getEntryPoint().getOffset(),localStore,localVbr,
                uncertainFlow,directCallees));
            if(steps.isEmpty()){
                mmEffectNodes.add(new HardwareInterproceduralMmEffects.FunctionNode(
                    fun.getEntryPoint().getOffset(),false,false,true,directCallees));
                callerContextsOmitted+=mmCallSites.size()-firstFunctionCallSite;
                continue;
            }
            long functionEntry=fun.getEntryPoint().getOffset();
            int budget=Math.min(30000,Math.max(300,steps.size()*20));
            HardwareDataflow.Result result=FUNCTION_STAGES.get(
                program,functionEpoch,functionScope,functionEntry,budget,
                steps,targets.keySet());
            boolean diskEligible=privateDirectory!=null && fullInput!=null &&
                ++eligibleDiskFunctions<=
                    HardwareDurableFunctionStages.MAX_DURABLE_FUNCTIONS;
            if(result==null && diskEligible){
                monitor.checkCancelled();
                if(program.getModificationNumber()!=functionScope.modification())
                    throw new CancelledException();
                result=HardwareDurableFunctionStages.load(
                    privateDirectory,fullInput,functionEntry,budget,
                    steps,targets.keySet()).orElse(null);
                if(result!=null){
                    monitor.checkCancelled();
                    if(program.getModificationNumber()!=functionScope.modification())
                        throw new CancelledException();
                    if(FUNCTION_STAGES.put(program,functionEpoch,functionScope,
                            functionEntry,budget,steps,targets.keySet(),result))
                        restoredDiskFunctions++;
                    else result=null;
                }
            }
            if(result==null){
                var sliced=HardwarePartialStageRunner.analyze(
                    functionEntry,steps,targets.keySet(),budget,
                    diskEligible?privateDirectory:null,
                    diskEligible?fullInput:null,monitor,
                    ()->program.getModificationNumber()==
                            functionScope.modification() &&
                        FUNCTION_STAGES.current(program,functionEpoch));
                result=sliced.result();
                if(sliced.restoredPartial())restoredMidFunctionWorklists++;
                savedMidFunctionWorklists+=sliced.storedPartial();
                // NEVER save an unfinished function, or a stale generation
                // after Cancel/explicit invalidate or Ghidra Program edit.
                monitor.checkCancelled();
                if(program.getModificationNumber()!=functionScope.modification())
                    throw new CancelledException();
                boolean completed=FUNCTION_STAGES.put(
                    program,functionEpoch,functionScope,functionEntry,budget,
                    steps,targets.keySet(),result);
                if(diskEligible && completed &&
                        program.getModificationNumber()==functionScope.modification() &&
                        HardwareDurableFunctionStages.save(privateDirectory,
                            fullInput,functionEntry,budget,steps,targets.keySet(),result))
                    savedDiskFunctions++;
                computedFunctions++;
            }else{
                reusedFunctions++;
            }
            visited+=result.reachedNodes;
            limited|=result.truncated;
            if(mc68332Selected)for(int idx=firstFunctionCallSite;
                    idx<mmCallSites.size();idx++){
                if(callerContexts.size()>=
                        HardwareCallsiteRegisterFlow.MAX_CALL_SITES){
                    callerContextsOmitted++;
                    continue;
                }
                var call=mmCallSites.get(idx);
                Map<String,Long> registers=result.knownPointersAtEntry
                    .getOrDefault(call.pc(),Map.of());
                callerContexts.add(new HardwareCallsiteRegisterFlow.Call(
                    functionEntry,call.pc(),call.target(),registers,
                    uncertainFlow || result.truncated));
            }
            // A MOVEC-to-VBR source is only an intraprocedural CFG candidate.
            // Correlate its containing function with the static RESET graph
            // after scanning every function; never treat it as active VBR.
            if(mc68332Selected)for(HardwareDataflow.Snapshot hit:result.snapshots){
                if(hit.kind!=HardwareDataflow.Kind.VBR_FROM_REGISTER)continue;
                if(vbrSourceSites.size()>=
                        HardwareVbrRelocationEvidence.MAX_SOURCE_SITES ||
                        fun.getEntryPoint().getOffset()>
                            HardwareVbrRelocationEvidence.MAX_24BIT ||
                        hit.instruction>HardwareVbrRelocationEvidence.MAX_24BIT){
                    vbrSourceSitesOmitted++;
                    continue;
                }
                vbrSourceSites.add(new HardwareVbrRelocationEvidence.Site(
                    functionEntry,hit.instruction,hit.vbr,
                    result.truncated || uncertainFlow,hit.priorUnknownCall));
            }
            boolean localMmCandidate=false,localUnknownStore=false;
            for(HardwareDataflow.Snapshot hit:result.snapshots){
                if(hit.kind!=HardwareDataflow.Kind.STORE_DIRECT &&
                        hit.kind!=HardwareDataflow.Kind.STORE_INDIRECT)continue;
                if(HardwareInterproceduralMmEffects.unknownMemoryWrite(
                        hit.effectiveAddress,hit.writeBits))
                    localUnknownStore=true;
                else if(mc68332Selected &&
                        HardwareDataflow.mayTouchSimcrMmLowByte(
                            hit.effectiveAddress,hit.writeBits))
                    localMmCandidate=true;
            }
            mmEffectNodes.add(new HardwareInterproceduralMmEffects.FunctionNode(
                fun.getEntryPoint().getOffset(),localMmCandidate,localUnknownStore,
                uncertainFlow || result.truncated,directCallees));
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
                    boolean exactSimcr=hit.effectiveAddress!=null &&
                        "SIMCR".equals(targets.get(hit.effectiveAddress));
                    // A long STORE spanning SIMCR or a low-byte STORE may be
                    // the first source write; keep UNKNOWN_WORD, not a full
                    // word or evidence of an accepted hardware MM latch.
                    boolean overlapsMm=HardwareDataflow.mayTouchSimcrMmLowByte(
                        hit.effectiveAddress,hit.writeBits);
                    if(exactSimcr || overlapsMm){
                        foundSimcr=true;
                        if(exactSimcr && hit.writeBits==16 &&
                                hit.writtenWord!=null){
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
                            fun.getEntryPoint().getOffset(),fun.getEntryPoint().getOffset(),
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
        String callsiteRegisters;
        String twoHopRegisters;
        if(mc68332Selected){
            List<HardwareCallsiteRegisterFlow.Callee> contextualCallees=
                new ArrayList<>();
            java.util.LinkedHashSet<Long> needed=new java.util.LinkedHashSet<>();
            for(var call:callerContexts)
                if(call.directCallee()!=null &&
                        !call.agreedRegisters().isEmpty() &&
                        !call.callerIncomplete())
                    needed.add(call.directCallee());
            for(Long entry:needed){
                monitor.checkCancelled();
                if(program.getModificationNumber()!=
                        functionScope.modification() ||
                        !FUNCTION_STAGES.current(program,functionEpoch))
                    throw new CancelledException();
                Address addr=program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(entry);
                Function callee=program.getFunctionManager().getFunctionAt(addr);
                var decoded=contextualCallee(program,callee,monitor);
                if(decoded!=null)contextualCallees.add(decoded);
            }
            var contextual=HardwareCallsiteRegisterFlow.analyze(
                callerContexts,contextualCallees,targets.keySet(),80);
            callsiteRegisters=contextual.markdown()+
                HardwareRegisterByteCoverage.analyze(p,
                    contextual.candidates().stream()
                        .map(c->new HardwareRegisterByteCoverage.Store(
                            c.callPc(),c.storePc(),c.address(),c.writeBits()))
                        .toList()).markdown("one-hop");
            if(callerContextsOmitted>0)
                callsiteRegisters+="- **INCOMPLETE INPUT:** "+
                    callerContextsOmitted+
                    " source CALL sites skipped by the bounded 96-site "+
                    "budget or unavailable caller CFG. Missing calls are "+
                    "UNKNOWN, not proven side-effect-free.\n\n";
            // A separate two-hop analysis is intentionally NOT attached
            // to the ordinary GA-12 FUNCTION_STAGES or durable checkpoint.
            // Its scope is one chosen outer CALL PC and ONE nested CALL.
            List<HardwareCallsiteRegisterFlow.Call> twoHopInputs=
                new ArrayList<>();
            int twoHopInputsOmitted=callerContextsOmitted;
            for(var call:callerContexts)
                if(twoHopInputs.size()<
                        HardwareTwoHopRegisterFlow.MAX_OUTER_CALLS)
                    twoHopInputs.add(call);
                else twoHopInputsOmitted++;
            java.util.LinkedHashMap<Long,HardwareTwoHopRegisterFlow.Bridge>
                bridgeByEntry=new java.util.LinkedHashMap<>();
            java.util.LinkedHashMap<Long,HardwareCallsiteRegisterFlow.Callee>
                leafByEntry=new java.util.LinkedHashMap<>();
            for(var call:twoHopInputs) {
                monitor.checkCancelled();
                if(call.directCallee()==null || call.callerIncomplete() ||
                        call.agreedRegisters().isEmpty())continue;
                if(program.getModificationNumber()!=
                        functionScope.modification() ||
                        !FUNCTION_STAGES.current(program,functionEpoch))
                    throw new CancelledException();
                if(!bridgeByEntry.containsKey(call.directCallee())) {
                    Address middleAddr=program.getAddressFactory()
                        .getDefaultAddressSpace()
                        .getAddress(call.directCallee());
                    Function middle=program.getFunctionManager()
                        .getFunctionAt(middleAddr);
                    var bridge=contextualBridge(program,middle,monitor);
                    if(bridge!=null)
                        bridgeByEntry.put(bridge.entry(),bridge);
                }
                var bridge=bridgeByEntry.get(call.directCallee());
                if(bridge==null || bridge.finalTarget()==null ||
                        leafByEntry.containsKey(bridge.finalTarget()))
                    continue;
                Address leafAddr=program.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(bridge.finalTarget());
                Function leaf=program.getFunctionManager()
                    .getFunctionAt(leafAddr);
                var decoded=contextualCallee(program,leaf,monitor);
                if(decoded!=null)leafByEntry.put(decoded.entry(),decoded);
            }
            var twoHop=HardwareTwoHopRegisterFlow.analyze(
                twoHopInputs,bridgeByEntry.values(),leafByEntry.values(),
                targets.keySet(),40);
            twoHopRegisters=twoHop.markdown()+
                HardwareRegisterByteCoverage.analyze(p,
                    twoHop.rows().stream()
                        .map(c->new HardwareRegisterByteCoverage.Store(
                            c.outerCallPc(),c.storePc(),
                            c.effectiveAddress(),c.bits()))
                        .toList()).markdown("two-hop");
            if(twoHopInputsOmitted>0)
                twoHopRegisters+="- **INCOMPLETE INPUT:** "+
                    twoHopInputsOmitted+" CALL sites beyond the combined "+
                    "32-site two-hop and 96-site one-hop source caps. "+
                    "Unseen two-hop paths remain UNKNOWN.\n\n";
        }else {
            callsiteRegisters="## One-hop CALL-site A/D register and "+
                "MMIO candidates (GA-02/03)\n\n"+
                "Not evaluated: explicit MC68332 profile required. "+
                "Generic CPU32 does not imply MCU MMIO.\n\n";
            twoHopRegisters="## Bounded two-hop CALL argument/MMIO "+
                "source candidates (GA-02/03)\n\n"+
                "Not evaluated: explicit MC68332 profile required. "+
                "Generic CPU32 does not imply MCU MMIO.\n\n";
        }

        String indirectCallEvidence=mc68332Selected?
            HardwareIndirectCallEvidence.markdown(indirectCandidates,
                indirectUnknownCalls,indirectCandidatesOmitted):
            "## CPU32 adjacent-immediate indirect JSR source candidates (GA-02/03)\n\n"+
            "Not evaluated: explicit MC68332 profile required. "+
            "Generic CPU32 has no verified MCU-specific MMIO mapping.\n\n";

        // A source-proven computed JSR may point to a function with
        // transitive STORE/VBR sites. This is separate, bounded **MAY**
        // evidence: never a direct CALL/RESET/ISR graph edge.
        String indirectMayEffects=mc68332Selected?
            HardwareIndirectMayEffects.analyze(
                indirectCandidates,staticCalls,HardwareIndirectMayEffects.MAX_ROWS)
                .markdown():
            "## Byte-witnessed indirect JSR transitive MAY effects (GA-02/03/11)\n\n"+
            "Not evaluated: explicit MC68332 profile required. "+
            "Generic CPU32 cannot imply MCU-specific MMIO effects.\n\n";

        String interproceduralMm=mc68332Selected?
            HardwareInterproceduralMmEffects.analyze(
                mmEffectNodes,mmCallSites,evidencedFunctions,4,100,80).markdown():
            "## Interprocedural SIMCR/MM candidates by CALL instruction\n\n"+
            "Generic CPU32: manual MC68332 profile selection required.\n\n";

        ResetCandidates reset=resetStaticCandidates(program,staticCalls,evidencedFunctions);
        String relocatedVbr=mc68332Selected?
            GhidraInterruptVectorService.analyzeRelocatedSourceTables(
                program,monitor,vbrSourceSites,vbrSourceSitesOmitted,
                reset.recognized(),reset.incomplete(),reset.visited(),
                staticCalls):
            "## Relocated VBR source-table candidates (GA-11)\n\n"+
            "Not evaluated: MC68332 profile not explicitly selected. "+
            "Generic CPU32 does not imply a device-specific vector table.\n\n";
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
           .append("- Strictly verified leaf CALL return-register sites: ")
               .append(provenLeafCallSites).append(" (read-only static sources; ")
               .append("all peripheral state remains UNKNOWN after CALL).\n")
           .append("- Propagation cap reached: ").append(limited).append("\n")
           .append("- Completed per-function fixed points reused: ")
               .append(reusedFunctions).append("; computed in this pass: ")
               .append(computedFunctions).append(". These are exact-revision ")
               .append("process-local checkpoints, not a partially published ")
               .append("finished report or a runtime RESET trace.\n")
           .append("- Completed per-function fixed points restored from disk: ")
               .append(restoredDiskFunctions).append("; newly saved: ")
               .append(savedDiskFunctions).append(" (at most ")
               .append(HardwareDurableFunctionStages.MAX_DURABLE_FUNCTIONS)
               .append(" function slots in this isolated opt-in pass).\n")
           .append("- Mid-function CFG worklists restored from disk: ")
               .append(restoredMidFunctionWorklists)
               .append("; stored: ").append(savedMidFunctionWorklists)
               .append(" (bounded unfinished computation only).\n\n")
           .append(reset.markdown())
           .append(GhidraInterruptVectorService.analyze(program,monitor,
               reset.recognized(),reset.incomplete(),reset.visited(),staticCalls))
           .append(relocatedVbr)
           .append(detail).append(effects).append(interproceduralMm)
           .append(indirectCallEvidence)
           .append(indirectMayEffects)
           .append(callsiteRegisters).append(twoHopRegisters);
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
            "## Possible local first SIMCR sites\n\nGeneric CPU32: explicit "+
            "MC68332 profile required for these candidate source paths.\n\n");
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
