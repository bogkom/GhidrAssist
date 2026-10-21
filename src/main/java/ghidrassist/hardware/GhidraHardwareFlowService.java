package ghidrassist.hardware;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
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
    private static final Pattern REG=Pattern.compile("(?<![A-Z0-9])([AD][0-7])(?![A-Z0-9])");
    private static final Pattern OFFSET=Pattern.compile("(?<![A-Z0-9])(-?0[Xx][0-9A-F]+|-?[0-9]+)(?![A-Z0-9])");
    public static final class Report {
        public final String markdown;
        public final int functions,indirect,vbr,unresolved,visited;
        public final boolean limited;
        Report(String md,int fn,int indirect,int vbr,int unresolved,int visited,boolean limited){
            markdown=md;functions=fn;this.indirect=indirect;this.vbr=vbr;
            this.unresolved=unresolved;this.visited=visited;this.limited=limited;
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
        return v.isConstant()?v.getOffset():constants.get(v);
    }
    private static Long pcodeStore(Instruction i){
        Map<Varnode,Long> computed=new HashMap<>();
        Long one=null;
        PcodeOp[] ops=i.getPcode();
        if(ops==null)return null;
        for(PcodeOp p:ops){
            Long result=null;int k=p.getOpcode();
            if(k==PcodeOp.STORE && p.getNumInputs()>=3){
                Long ptr=value(p.getInput(1),computed);
                if(ptr!=null){
                    if(one!=null && !one.equals(ptr))return null;
                    one=ptr;
                }
            } else if((k==PcodeOp.COPY||k==PcodeOp.INT_ZEXT||
                    k==PcodeOp.INT_SEXT) && p.getNumInputs()>0){
                result=value(p.getInput(0),computed);
            } else if((k==PcodeOp.INT_ADD||k==PcodeOp.INT_SUB) &&
                    p.getNumInputs()>1){
                Long a=value(p.getInput(0),computed),b=value(p.getInput(1),computed);
                if(a!=null&&b!=null)result=k==PcodeOp.INT_ADD?a+b:a-b;
            }
            Varnode out=p.getOutput();
            if(out!=null){
                if(result!=null)computed.put(out,result&HardwareDataflow.MASK24);
                else computed.remove(out);
            }
        }
        return one==null?null:one&HardwareDataflow.MASK24;
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
            if((m.equals("MOVE")||m.equals("MOVEA")||m.equals("MOVEQ"))&&imm!=null){
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
                    (full.endsWith(".W")||full.endsWith(".L"))){
                return new HardwareDataflow.Step(pc,HardwareDataflow.Kind.COPY_POINTER,
                    dst,src,0,0,null,0,next,full);
            }
            if(imm!=null&&(m.equals("ADDA")||m.equals("SUBA")||
                    m.equals("ADDQ")||m.equals("SUBQ"))){
                return new HardwareDataflow.Step(pc,HardwareDataflow.Kind.ADJUST_POINTER,
                    dst,m.startsWith("SUB")?-imm:imm,0,null,0,next,full);
            }
            return new HardwareDataflow.Step(pc,HardwareDataflow.Kind.CLOBBER_POINTER,
                dst,0,0,null,0,next,full);
        }
        if(last>=0&&writesMemory(m)){
            Long address=absolute(i,last);
            String pointer=indirectReg(i,last);
            Integer word=null;String from=m.equals("MOVE")?src:null;
            int width=full.endsWith(".W")?16:full.endsWith(".L")?32:
                full.endsWith(".B")?8:0;
            if(width==16&&m.equals("CLR"))word=0;
            if(width==16&&m.equals("MOVE")&&imm!=null)word=(int)(imm&0xffff);
            if(!m.equals("MOVE"))from=null;
            if(address==null && pointer==null)address=pcodeStore(i);
            if(address!=null)return new HardwareDataflow.Step(pc,
                HardwareDataflow.Kind.STORE_DIRECT,null,from,address,0,word,width,next,full);
            if(pointer!=null)return new HardwareDataflow.Step(pc,
                HardwareDataflow.Kind.STORE_INDIRECT,pointer,from,0,
                displacement(i,last),word,width,next,full);
        }
        return new HardwareDataflow.Step(pc,HardwareDataflow.Kind.OTHER,
            null,0,0,null,0,next,full);
    }
    public Report analyze(Program program,TaskMonitor monitor)throws CancelledException{
        if(program==null)throw new IllegalArgumentException("Open Ghidra program required");
        if(monitor==null)monitor=TaskMonitor.DUMMY;
        Map<Long,String> targets=new LinkedHashMap<>();
        HardwareProfiles.Profile p=HardwareProfiles.mc68332();
        for(HardwareProfiles.Register r:p.registers)
            for(int mm=0;mm<2;mm++)targets.put(p.absoluteAddress(r,mm),r.name);
        StringBuilder detail=new StringBuilder();
        int foundFunctions=0,indirect=0,vbr=0,unresolved=0,visited=0,shown=0;
        boolean limited=false;
        FunctionIterator funs=program.getFunctionManager().getFunctions(true);
        while(funs.hasNext()){
            monitor.checkCancelled();
            Function fun=funs.next();
            List<HardwareDataflow.Step> steps=new ArrayList<>();
            InstructionIterator it=program.getListing().getInstructions(fun.getBody(),true);
            while(it.hasNext()){
                monitor.checkCancelled();
                steps.add(translate(it.next(),fun));
            }
            if(steps.isEmpty())continue;
            HardwareDataflow.Result result=HardwareDataflow.analyze(
                fun.getEntryPoint().getOffset(),steps,targets.keySet(),
                Math.min(30000,Math.max(300,steps.size()*20)));
            visited+=result.reachedNodes;
            limited|=result.truncated;
            List<HardwareDataflow.Snapshot> found=new ArrayList<>();
            for(HardwareDataflow.Snapshot hit:result.snapshots){
                if(hit.kind==HardwareDataflow.Kind.VBR_FROM_REGISTER){
                    found.add(hit);vbr++;
                } else if(hit.effectiveAddress!=null &&
                        targets.containsKey(hit.effectiveAddress)){
                    found.add(hit);
                    if(hit.indirect)indirect++;
                } else if(hit.kind==HardwareDataflow.Kind.STORE_INDIRECT &&
                        hit.effectiveAddress==null){
                    unresolved++;
                }
            }
            if(found.isEmpty()&&!result.truncated)continue;
            foundFunctions++;
            if(shown>=350)continue;
            detail.append("### ").append(fun.getName()).append(" at ")
                .append(fun.getEntryPoint()).append("\n\n");
            int callers=0;
            ReferenceIterator refs=program.getReferenceManager()
                .getReferencesTo(fun.getEntryPoint());
            while(refs.hasNext())if(refs.next().getReferenceType().isCall())callers++;
            detail.append("- CFG nodes reached: ").append(result.reachedNodes)
                .append("; direct call references: ").append(callers)
                .append("; propagation limit: ").append(result.truncated).append("\n");
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
                        .append(hit.indirect?" [A-register indirect]":" [direct/P-code]")
                        .append(" value ")
                        .append(hit.writtenWord==null?"UNKNOWN":
                            ChipSelectModel.hex(hit.writtenWord,4));
                    int mm=hit.effectiveAddress<0x800000?0:1;
                    long base=mm==0?0x7ff000L:0xfff000L;
                    if(name.equals("SIMCR")&&hit.writtenWord!=null)
                        detail.append(" ; candidate MM=")
                            .append((hit.writtenWord&0x40)!=0?1:0);
                    if(name.startsWith("CSBAR") && hit.writtenWord!=null){
                        int cs=name.endsWith("BT")?-1:
                            Integer.parseInt(name.substring(5));
                        String suffix=cs<0?"BT":String.valueOf(cs);
                        long offset=cs<0?0:4L*(cs+1);
                        Integer or=hit.knownPeripheralWords.get(base+0xa4a+offset);
                        Integer spar=hit.knownPeripheralWords.get(
                            base+(cs<=5?0xa44:0xa46));
                        ChipSelectModel.Window win=new ChipSelectModel.Decoder(
                            "MC68332","manual hypothesis").window(cs,
                            hit.writtenWord,or,spar);
                        detail.append(" ; candidate ").append(win.toSummary());
                    }
                }
                detail.append("\n");
            }
            detail.append("\n");
        }
        StringBuilder out=new StringBuilder();
        out.append("## CFG/P-code hardware evidence (read-only)\n\n")
           .append("Only predecessor-agreed intraprocedural constants survive branch joins. ")
           .append("Calls invalidate propagated registers and peripheral state; ")
           .append("indirect jumps, pointer aliases and real execution are not proven.\n\n")
           .append("- Evidence functions: ").append(foundFunctions).append("\n")
           .append("- Reachable instruction nodes: ").append(visited).append("\n")
           .append("- Register-indirect matched writes: ").append(indirect).append("\n")
           .append("- VBR control-register sites: ").append(vbr).append("\n")
           .append("- Unresolved register-based stores: ").append(unresolved).append("\n")
           .append("- Propagation cap reached: ").append(limited).append("\n\n")
           .append(detail);
        if(shown>=350)out.append("\n[Detailed report bounded at 350 sites.]\n");
        return new Report(out.toString(),foundFunctions,indirect,vbr,unresolved,visited,limited);
    }
}
