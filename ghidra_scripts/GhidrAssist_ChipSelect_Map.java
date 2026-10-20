// Standalone MC68332 hypothesis-based chip-select map analysis.
// No GhidrAssist extension classes and no database changes.
//@category GhidrAssist.Hardware

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Report independent, conditional chip-select configuration hypotheses for
 * each function. Address matches do NOT identify the exact CPU. There is no
 * path-sensitive data flow yet; even instruction order cannot guarantee runtime
 * state. Never use windows for u-Link NT programming without external checks.
 */
public class GhidrAssist_ChipSelect_Map extends GhidraScript {
    private static final long[] SIZES = {
        2048,8192,16384,65536,131072,262144,524288,1048576
    };

    private static final class Hit {
        final Instruction instruction;
        final String reg;
        final int mm;
        final long target;
        final Long constant;
        Hit(Instruction i, String r, int m, long t) {
            instruction = i; reg = r; mm = m; target = t;
            constant = overwrite(i);
        }
    }
    private static final class Window {
        final String id;
        final long first,last;
        Window(String s,long f,long l){id=s;first=f;last=l;}
    }
    private static String hex(long v,int len) {
        return String.format(Locale.ROOT,"0x%0"+len+"X",v);
    }
    private static String baseMnemonic(Instruction i) {
        String m=i.getMnemonicString().toUpperCase(Locale.ROOT);
        int dot=m.indexOf('.');
        return dot>=0?m.substring(0,dot):m;
    }
    private static boolean absoluteDestination(Instruction i,int operand) {
        if (operand<0 || i.getOpObjects(operand)==null) return false;
        for(Object o:i.getOpObjects(operand))
            if(o instanceof Register) return false;
        String text=i.getDefaultOperandRepresentation(operand);
        return text!=null && !text.contains("#") &&
            !text.toUpperCase(Locale.ROOT).matches(
                ".*(?<![A-Z0-9])(?:A[0-7]|D[0-7]|PC|SP)(?![A-Z0-9]).*");
    }
    private static boolean isStoreSite(Instruction i,long target) {
        String op=baseMnemonic(i);
        if(!(op.equals("MOVE")||op.equals("CLR")||op.equals("ORI")||
             op.equals("ANDI")||op.equals("EORI")||
             op.equals("BSET")||op.equals("BCLR"))) return false;
        int last=i.getNumOperands()-1;
        if(!absoluteDestination(i,last)) return false;
        Object[] o=i.getOpObjects(last);
        if(o==null)return false;
        for(Object v:o){
            if(v instanceof Address a && a.getOffset()==target)return true;
            if(v instanceof Scalar scalar && scalar.getUnsignedValue()==target)return true;
        }
        return false;
    }
    private static Long overwrite(Instruction i) {
        String m=baseMnemonic(i);
        String full=i.getMnemonicString().toUpperCase(Locale.ROOT);
        int n=i.getNumOperands();
        if (!full.endsWith(".W") || !absoluteDestination(i,n-1)) return null;
        if (m.equals("CLR") && n==1) return 0L;
        if (m.equals("MOVE") && n==2) {
            Scalar s=i.getScalar(0);
            String source=i.getDefaultOperandRepresentation(0);
            if(s!=null && source!=null && source.strip().startsWith("#"))
                return s.getUnsignedValue() & 0xffffL;
        }
        return null;
    }
    private static String registerFor(long addr) {
        long offset=addr & 0xfffL;
        return switch ((int)offset) {
            case 0xa00 -> "SIMCR";
            case 0xa04 -> "SYNCR";
            case 0xa44 -> "CSPAR0";
            case 0xa46 -> "CSPAR1";
            case 0xa48 -> "CSBARBT";
            case 0xa4a -> "CSORBT";
            case 0xb04 -> "TRAMBAR";
            default -> {
                if(offset>=0xa4c && offset<=0xa76 && (offset%2)==0) {
                    int index=(int)((offset-0xa4c)/4);
                    yield ((offset-0xa4c)%4)==0?"CSBAR"+index:"CSOR"+index;
                }
                yield null;
            }
        };
    }
    private static void add(Map<String,Hit> found,Instruction i,long address){
        String name=registerFor(address);
        if(name==null) return;
        String key=i.getAddress().toString()+":"+Long.toHexString(address);
        found.putIfAbsent(key,new Hit(i,name,(address & 0x800000L)==0?0:1,address));
    }
    private static String fieldMode(Long spar,int cs) {
        if(spar==null) return "CSPAR UNKNOWN";
        int shift=cs<0?0:cs<=5?(cs+1)*2:(cs-6)*2;
        int code=(int)((spar>>shift)&3);
        if(cs<0 && code==0)
            return "CSBOOT reset mode requires pin/reset-state evidence";
        return switch(code) {
            case 0 -> "discrete function / no CS output (if allowed on this pin)";
            case 1 -> "alternate pin function / no CS output";
            case 2 -> "CS 8-bit port candidate";
            case 3 -> "CS 16-bit port candidate";
            default -> "unknown";
        };
    }
    private static String option(int opt) {
        int byteField=(opt>>13)&3, rw=(opt>>11)&3;
        String mode=switch(rw) {
            case 1 -> "read";case 2 -> "write";case 3 -> "read+write";
            default -> "reserved R/W encoding";
        };
        return "BYTE="+byteField+(byteField==0?" (disabled if 16-bit port)":"")+
            ", R/W="+mode+", SPACE="+((opt>>4)&3)+
            ", IPL="+((opt>>1)&7)+", DSACK="+((opt>>6)&15)+
            ", MODE="+((opt>>15)&1)+", STRB="+((opt>>10)&1)+
            ", AVEC="+(opt&1);
    }

    @Override
    public void run() throws Exception {
        if(currentProgram==null){printerr("Open a program first.");return;}
        String mode=askChoice("MC68332 chip-select candidate decoder",
            "CPU32 is exploratory; selecting MC68332 does NOT prove hardware identity.",
            List.of("CPU32 reconnaissance","MC68332 assumed"),"CPU32 reconnaissance");
        println("CHIP-SELECT WINDOW RECONNAISSANCE (READ ONLY)");
        println("Program: "+currentProgram.getName()+"; "+currentProgram.getLanguageID());
        println("Profile: "+mode+" ; addresses/bitfields from MC68332 manual, conditional only");
        Map<Long,String> targets=new LinkedHashMap<>();
        for(int mm=0;mm<2;mm++){
            long b=mm==0?0x7ff000L:0xfff000L;
            long[] basic={0xa00,0xa04,0xa44,0xa46,0xa48,0xa4a,0xb04};
            for(long offset:basic) targets.put(b+offset,registerFor(b+offset));
            for(long offset=0xa4c;offset<=0xa76;offset+=2)
                targets.put(b+offset,registerFor(b+offset));
        }
        Map<String,Hit> found=new LinkedHashMap<>();
        int xrefs=0;
        for(long numeric:targets.keySet()){
            monitor.checkCancelled();
            Address a=currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(numeric);
            ReferenceIterator r=currentProgram.getReferenceManager().getReferencesTo(a);
            while(r.hasNext()){
                monitor.checkCancelled();
                Reference ref=r.next();xrefs++;
                Instruction i=currentProgram.getListing()
                    .getInstructionContaining(ref.getFromAddress());
                if(i!=null) add(found,i,numeric);
            }
        }
        InstructionIterator it=currentProgram.getListing().getInstructions(true);
        int scanned=0;
        while(it.hasNext()){
            monitor.checkCancelled();
            Instruction i=it.next();scanned++;
            String op=baseMnemonic(i);
            if(!(op.equals("MOVE")||op.equals("CLR")||op.equals("ORI")||
                op.equals("ANDI")||op.equals("EORI")||
                op.equals("BSET")||op.equals("BCLR"))) continue;
            int dest=i.getNumOperands()-1;
            if(!absoluteDestination(i,dest)) continue;
            for(Object o:i.getOpObjects(dest)){
                long value=-1;
                if(o instanceof Address a) value=a.getOffset();
                if(o instanceof Scalar scalar) value=scalar.getUnsignedValue();
                if(targets.containsKey(value)) add(found,i,value);
            }
        }
        println("Instructions="+scanned+"; XREF hits="+xrefs+
            "; unique register-site hypotheses="+found.size());
        Map<String,List<Hit>> groups=new TreeMap<>();
        Map<String,Function> funcs=new HashMap<>();
        for(Hit h:found.values()){
            Function f=currentProgram.getFunctionManager()
                .getFunctionContaining(h.instruction.getAddress());
            String key=f==null?"?"+h.instruction.getAddress():f.getEntryPoint().toString();
            groups.computeIfAbsent(key,k->new ArrayList<>()).add(h);
            if(f!=null) funcs.put(key,f);
        }
        for(Map.Entry<String,List<Hit>> item:groups.entrySet()){
            monitor.checkCancelled();
            Function f=funcs.get(item.getKey());
            item.getValue().sort(Comparator.comparing(h->h.instruction.getAddress()));
            println("\nFUNCTION "+(f==null?"<unknown>":f.getName()+" @ "+f.getEntryPoint())+
                " ; relevant sites="+item.getValue().size());
            if(f!=null){
                ReferenceIterator refs=currentProgram.getReferenceManager()
                    .getReferencesTo(f.getEntryPoint());
                int calls=0;
                while(refs.hasNext()){
                    Reference r=refs.next();
                    if(!r.getReferenceType().isCall()) continue;
                    if(calls++<12) println("    CALLER SITE: "+r.getFromAddress());
                }
                if(calls==0) println("    CALLERS: none found directly; reset/indirect path unknown");
                if(calls>12) println("    CALLERS: "+(calls-12)+" further omitted");
            }
            for(int mm=0;mm<=1;mm++){
                Map<String,Long> registers=new LinkedHashMap<>();
                Map<String,Address> evidence=new LinkedHashMap<>();
                Set<String> unresolved=new HashSet<>();
                int seen=0;
                for(Hit h:item.getValue()){
                    if(h.mm!=mm)continue;
                    seen++;
                    if(!isStoreSite(h.instruction,h.target)){
                        println("    "+h.instruction.getAddress()+" "+h.reg+
                            " READ/REFERENCE only: "+h.instruction);
                        continue;
                    }
                    if(h.constant!=null) {
                        registers.put(h.reg,h.constant);
                        evidence.put(h.reg,h.instruction.getAddress());
                    } else {
                        registers.remove(h.reg);
                        unresolved.add(h.reg);
                    }
                    println("    "+h.instruction.getAddress()+" "+
                        h.reg+" "+(h.constant==null?"value UNKNOWN / partial write":
                            "literal "+hex(h.constant,4))+" : "+h.instruction);
                }
                if(seen==0) continue;
                println("    CONDITIONAL ADDRESS VIEW MM="+mm+
                    " (linear Listing order, NOT validated runtime path)");
                if(!unresolved.isEmpty()) println("    Incomplete/changed registers: "+unresolved);
                for(String extra:List.of("SIMCR","SYNCR","TRAMBAR")){
                    if(registers.containsKey(extra))
                        println("    "+extra+"="+hex(registers.get(extra),4)+
                            " from "+evidence.get(extra)+
                            " (actual timing and access permissions unknown)");
                }
                List<Window> windows=new ArrayList<>();
                for(int cs=-1;cs<=10;cs++){
                    String suffix=cs<0?"BT":Integer.toString(cs);
                    String label=cs<0?"CSBOOT":"CS"+cs;
                    Long bar=registers.get("CSBAR"+suffix);
                    if(bar==null)continue;
                    long size=SIZES[(int)(bar & 7L)];
                    long start=((bar & 0xfff8L)<<8)&0xffffffL;
                    start &=~(size-1);
                    long end=start+size-1;
                    Long spar=registers.get(cs<=5?"CSPAR0":"CSPAR1");
                    String pin=fieldMode(spar,cs);
                    Long or=registers.get("CSOR"+suffix);
                    println("    "+label+" CSBAR="+hex(bar,4)+" window="+
                        hex(start,6)+".."+hex(end,6)+" ("+(size/1024)+"KiB)");
                    println("       pin="+pin+"; CSOR="+(or==null?"UNKNOWN":hex(or,4)+" "+option(or.intValue())));
                    println("       code evidence: BAR="+evidence.get("CSBAR"+suffix)+
                        ", OR="+evidence.get("CSOR"+suffix));
                    boolean possible=pin.startsWith("CS ") ||
                        (cs==-1 && pin.contains("reset mode"));
                    // Keep even possibly disabled matches for overlap investigation.
                    // CSOR BYTE is not a universal enable flag (8-bit ports differ).
                    if(possible && or!=null)
                        windows.add(new Window(label,start,end));
                }
                for(int i=0;i<windows.size();i++)
                    for(int j=i+1;j<windows.size();j++){
                        Window a=windows.get(i),b=windows.get(j);
                        if(a.first<=b.last && b.first<=a.last)
                            println("    OVERLAP CANDIDATE "+a.id+"/"+b.id+" "+
                                hex(Math.max(a.first,b.first),6)+".."+
                                hex(Math.min(a.last,b.last),6)+
                                " ; FC/RW/priority/board wiring unresolved");
                    }
                println("    These windows do not prove active flash, RAM, or any u-Link NT access.");
            }
        }
        println("\nVBR RECONNAISSANCE (CPU control register, not SIM)");
        int vbr=0;
        it=currentProgram.getListing().getInstructions(true);
        while(it.hasNext()){
            monitor.checkCancelled();
            Instruction i=it.next();
            String text=i.toString().toUpperCase(Locale.ROOT);
            if(baseMnemonic(i).startsWith("MOVEC") && text.contains("VBR")){
                Function f=currentProgram.getFunctionManager()
                    .getFunctionContaining(i.getAddress());
                println("    VBR instruction "+i.getAddress()+" "+i+" in "+
                    (f==null?"<unknown>":f.getName())+
                    " (base value not proven)");
                vbr++;
            }
        }
        println("VBR instruction candidates: "+vbr);
        println("END: reports are code-site hypotheses, not execution traces.");
        println("No name changes, program edits, external memory accesses or hardware writes.");
        println("Device profile and dynamic CS/window state must be verified before use with u-Link NT.");
    }
}
