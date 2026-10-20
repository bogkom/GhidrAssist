// Read-only exploratory CPU32 P-code / pointer-flow probe.
// Works without installing or rebuilding the GhidrAssist extension.
//@category GhidrAssist.Hardware

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.List;

/**
 * Finds P-code STORE operations with constant pointers and probable 68k
 * register-indirect destination accesses preceded by local address-register
 * assignments. Register tracking is intentionally heuristic and stops at
 * function boundaries, control flow or unknown register modifications.
 * No control-flow merge or executable semantics are proved.
 */
public class GhidrAssist_Pcode_Address_Probe extends GhidraScript {
    private static String hex(long v){
        return String.format(Locale.ROOT,"0x%06X",v & 0xffffffL);
    }
    private static String opcode(Instruction insn){
        String m=insn.getMnemonicString().toUpperCase(Locale.ROOT);
        int d=m.indexOf('.');
        return d<0?m:m.substring(0,d);
    }
    private static Long varConst(Varnode v,Map<Varnode,Long> values) {
        if(v==null)return null;
        if(v.isConstant())return v.getOffset();
        return values.get(v);
    }
    private static String firstRegister(Instruction i,int op) {
        if(op<0 || op>=i.getNumOperands())return null;
        Object[] objs=i.getOpObjects(op);
        if(objs==null)return null;
        for(Object obj:objs) if(obj instanceof Register r){
            String name=r.getName().toUpperCase(Locale.ROOT);
            if(name.matches("[AD][0-7]") || name.equals("VBR"))return name;
        }
        return null;
    }
    private static Long directImmediate(Instruction i,int index){
        String text=i.getDefaultOperandRepresentation(index);
        if(text==null)return null;
        Object[] objs=i.getOpObjects(index);
        if(objs==null)return null;
        if(text.trim().startsWith("#")){
            Scalar s=i.getScalar(index);
            return s==null?null:s.getUnsignedValue();
        }
        if(opcode(i).equals("LEA")){
            for(Object o:objs)if(o instanceof Address a)return a.getOffset();
        }
        return null;
    }
    private static Long registerMemoryTarget(Instruction insn,Map<String,Long> known){
        int last=insn.getNumOperands()-1;
        if(last<0)return null;
        String target=insn.getDefaultOperandRepresentation(last);
        if(target==null||!target.contains("(")||!target.contains(")"))return null;
        String addrReg=firstRegister(insn,last);
        if(addrReg==null||!addrReg.matches("A[0-7]"))return null;
        Long base=known.get(addrReg);
        if(base==null)return null;
        int disp=0;
        Object[] objects=insn.getOpObjects(last);
        if(objects!=null)
            for(Object o:objects)if(o instanceof Scalar scalar){
                // Do not make claims for scaled-index or complex forms.
                if(target.toUpperCase(Locale.ROOT).matches(".*[DI][0-7].*"))return null;
                disp=scalar.getSignedValue() > Integer.MAX_VALUE ?
                    0 : (int)scalar.getSignedValue();
            }
        return (base+disp)&0xffffffL;
    }
    private static Set<Long> loadTargets(java.io.File source)throws Exception{
        Set<Long> targets=new HashSet<>();
        targets.add(0xfffa00L);targets.add(0x7ffa00L);
        if(source==null)return targets;
        Path file=source.toPath().getParent().resolve("hardware_profiles.tsv");
        if(!Files.isRegularFile(file))return targets;
        int lineNo=0;
        for(String line:Files.readAllLines(file,StandardCharsets.UTF_8)){
            lineNo++;
            if(line.isBlank()||line.trim().startsWith("#"))continue;
            String[] cols=line.split("\t",-1);
            if(cols.length!=7)
                throw new IllegalArgumentException("Malformed TSV row "+lineNo);
            if(!cols[1].equals("CPU32"))continue;
            long value=Long.decode(cols[3]);
            if(value<0||value>0xffffffL)
                throw new IllegalArgumentException("Bad 24-bit register address at row "+lineNo);
            targets.add(value);
        }
        return targets;
    }
    private static void propagatePcode(Instruction insn,Set<Long> targets,
            Set<String> emitted, java.util.function.Consumer<String> show){
        Map<Varnode,Long> values=new HashMap<>();
        PcodeOp[] ops=insn.getPcode();
        if(ops==null)return;
        for(PcodeOp op:ops){
            int type=op.getOpcode();
            Long computed=null;
            if((type==PcodeOp.COPY||type==PcodeOp.INT_ZEXT||
                    type==PcodeOp.INT_SEXT) && op.getNumInputs()>0){
                computed=varConst(op.getInput(0),values);
            }else if(type==PcodeOp.INT_ADD && op.getNumInputs()>1){
                Long a=varConst(op.getInput(0),values);
                Long b=varConst(op.getInput(1),values);
                if(a!=null&&b!=null)computed=(a+b)&0xffffffL;
            }else if(type==PcodeOp.INT_SUB && op.getNumInputs()>1){
                Long a=varConst(op.getInput(0),values);
                Long b=varConst(op.getInput(1),values);
                if(a!=null&&b!=null)computed=(a-b)&0xffffffL;
            }else if(type==PcodeOp.STORE && op.getNumInputs()>=3){
                Long ptr=varConst(op.getInput(1),values);
                if(ptr!=null && targets.contains(ptr & 0xffffffL)){
                    String key=insn.getAddress()+"/"+hex(ptr);
                    if(emitted.add(key))
                        show.accept("P-CODE CONSTANT STORE "+insn.getAddress()+
                            " -> "+hex(ptr)+" : "+insn+
                            " (address expression local to instruction)");
                }
            }
            if(op.getOutput()!=null){
                if(computed!=null)values.put(op.getOutput(),computed);
                else values.remove(op.getOutput());
            }
        }
    }
    @Override
    public void run()throws Exception{
        if(currentProgram==null){printerr("Open a program first.");return;}
        Set<Long> targets=loadTargets(getSourceFile());
        println("P-CODE / REGISTER ADDRESS PROBE — READ ONLY");
        println("Program: "+currentProgram.getName()+"; target addresses="+targets.size());
        println("Known register pointers are tentative; CPU32 does not prove an MC68332.");
        Map<String,Long> known=new HashMap<>();
        Set<String> emitted=new HashSet<>();
        String previousFunction=null;
        Address lastEnd=null;
        InstructionIterator it=currentProgram.getListing().getInstructions(true);
        int scanned=0, indirect=0, vbr=0;
        while(it.hasNext()){
            monitor.checkCancelled();
            Instruction insn=it.next();scanned++;
            Function f=currentProgram.getFunctionManager()
                .getFunctionContaining(insn.getAddress());
            String key=f==null?"<orphan>"+insn.getAddress():
                f.getEntryPoint().toString();
            if(!key.equals(previousFunction) || lastEnd==null ||
                    !insn.getAddress().equals(lastEnd.next())){
                known.clear();
            }
            previousFunction=key;
            lastEnd=insn.getMaxAddress();

            // Use only a straight-line contiguous interval. Register-derived
            // hits are possible paths, never proven execution facts.
            Long target=registerMemoryTarget(insn,known);
            if(target!=null && targets.contains(target) &&
                    !insn.getMnemonicString().toUpperCase(Locale.ROOT).startsWith("LEA")){
                String id=insn.getAddress()+"/"+hex(target);
                if(emitted.add(id)){
                    indirect++;
                    println("REGISTER-INDIRECT CANDIDATE "+insn.getAddress()+" -> "+
                        hex(target)+" : "+insn+
                        " [heuristic pointer, function="+(f==null?"?":f.getName())+"]");
                }
            }
            propagatePcode(insn,targets,emitted,this::println);

            String mn=opcode(insn);
            if(mn.equals("MOVEC") && insn.toString().toUpperCase(Locale.ROOT).contains("VBR")){
                vbr++;
                String src=firstRegister(insn,0);
                Long val=src==null?null:known.get(src);
                println("VBR CONTROL-REGISTER SITE "+insn.getAddress()+" "+
                    insn+" : "+(val==null?"UNKNOWN base":hex(val)+" tentative immediate source")+
                    " ; function="+(f==null?"?":f.getName()));
            }
            int last=insn.getNumOperands()-1;
            String reg=firstRegister(insn,last);
            if(reg!=null){
                String operand=insn.getDefaultOperandRepresentation(last);
                // This only handles direct register destination, not (An).
                if(operand!=null && !operand.contains("(") &&
                        reg.matches("[AD][0-7]")){
                    String kind=opcode(insn);
                    Long value=(kind.equals("MOVE")||kind.equals("MOVEA")||
                        kind.equals("LEA")) ? directImmediate(insn,0) : null;
                    if(value!=null)known.put(reg,value&0xffffffL);
                    else known.remove(reg);
                }
            }
            // No pointer state propagated through jumps, calls, exceptions or
            // RETURNs. Other branch entry points remain heuristic limitations.
            if(insn.getFlowType().isJump()||insn.getFlowType().isCall()||
                    insn.getFlowType().isTerminal()){
                known.clear();
            }
        }
        println("Scanned instructions="+scanned+
            "; register-indirect hypotheses="+indirect+"; VBR sites="+vbr+
            "; unique matching p-code/indirect site keys="+emitted.size());
        println("LIMITS: This is NOT whole-program constant propagation; basic-block "+
            "joins, aliases, function pointers, stack spills and memory values remain unknown.");
        println("NO CHANGES to labels, bytes, Ghidra database or external hardware.");
    }
}
