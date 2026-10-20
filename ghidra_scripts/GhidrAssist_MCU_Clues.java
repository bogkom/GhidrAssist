// Cross-check CPU32 MCU hypotheses against TPURAM and external CAN evidence.
// Read-only; profiles are reference hypotheses, not a device identification.
//@category GhidrAssist.Hardware

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;

/**
 * Correlate:
 * - MC68332 2 KiB TPURAM at a programmed 2 KiB boundary,
 * - MC68336/376 3.5 KiB TPURAM at a programmed 4 KiB boundary,
 * - MC68332-compatible CS7 address decoding,
 * - possible 82527/CC770 external CAN-register access patterns.
 *
 * This is intentionally not a full path-aware analyzer: it reports CODE SITES.
 * Never derive a physical MCU, bus connection or safe flashing address solely
 * from these findings.
 */
public class GhidrAssist_MCU_Clues extends GhidraScript {
    private static final long SIMCR_MM1=0xFFFA00L;
    private static final long TRAMBAR_MM1=0xFFFB04L;
    private static final long CSBAR7_MM1=0xFFFA68L;
    private static final long CSOR7_MM1=0xFFFA6AL;
    private static final long CAN_BASE=0xFF8800L;
    private static final long CAN_LAST=0xFF88FFL;
    private static final long[] CANDIDATES={SIMCR_MM1,TRAMBAR_MM1,CSBAR7_MM1,CSOR7_MM1};
    private static String hx(long n,int width){
        return String.format(Locale.ROOT,"0x%0"+width+"X",n);
    }
    private static String op(Instruction i){
        String name=i.getMnemonicString().toUpperCase(Locale.ROOT);
        int dot=name.indexOf('.');
        return dot<0?name:name.substring(0,dot);
    }
    private static Long directWordConstant(Instruction i,Address address){
        if(i.getNumOperands()!=2 || !op(i).equals("MOVE") ||
                !i.getMnemonicString().toUpperCase(Locale.ROOT).endsWith(".W"))
            return null;
        if(!i.getDefaultOperandRepresentation(0).trim().startsWith("#"))
            return null;
        boolean target=false;
        Object[] dest=i.getOpObjects(1);
        if(dest!=null){
            for(Object o:dest)
                if(o instanceof Address a && a.equals(address))target=true;
                else if(o instanceof Scalar s &&
                    s.getUnsignedValue()==address.getOffset())target=true;
        }
        if(!target)return null;
        Scalar immediate=i.getScalar(0);
        return immediate==null?null:immediate.getUnsignedValue() & 0xffffL;
    }
    private List<Long> wordStores(long addr)throws Exception{
        Address address=currentProgram.getAddressFactory()
            .getDefaultAddressSpace().getAddress(addr);
        ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(address);
        Set<String> emitted=new HashSet<>();
        List<Long> words=new ArrayList<>();
        while(refs.hasNext()){
            monitor.checkCancelled();
            Reference r=refs.next();
            Instruction i=currentProgram.getListing().getInstructionContaining(r.getFromAddress());
            if(i==null || !emitted.add(i.getAddress().toString()))continue;
            Long value=directWordConstant(i,address);
            if(value==null){
                println("  "+hx(addr,6)+" at "+i.getAddress()+": "+i+
                    " (register semantics unresolved)");
            }else{
                Function f=currentProgram.getFunctionManager()
                    .getFunctionContaining(i.getAddress());
                println("  "+hx(addr,6)+" at "+i.getAddress()+": "+i+
                    " => "+hx(value,4)+" (function="+
                    (f==null?"?":f.getName())+")");
                words.add(value);
            }
        }
        return words;
    }
    private static long[] csbarWindow(int raw){
        long[] sizes={2048L,8192L,16384L,65536L,131072L,262144L,524288L,1048576L};
        long size=sizes[raw & 7];
        long start=(((long)raw & 0xFFF8L)<<8)&0xFFFFFFL;
        start &=~(size-1);
        return new long[]{start,start+size-1};
    }
    @Override
    public void run()throws Exception{
        if(currentProgram==null){printerr("Open a program first.");return;}
        println("==== CPU32 MCU AND EXTERNAL CAN CLUES — READ ONLY ====");
        println("Program: "+currentProgram.getName());
        println("Ghidra language "+currentProgram.getLanguageID()+
            " IS NOT a physical processor identification.");
        println("All addresses and interpretations below are conditional on MC683xx manuals.");
        println("\n1. STATIC REGISTERS (MM=1 HYPOTHESIS)");
        List<Long> mm=wordStores(SIMCR_MM1);
        List<Long> trambar=wordStores(TRAMBAR_MM1);
        List<Long> bar7=wordStores(CSBAR7_MM1);
        List<Long> or7=wordStores(CSOR7_MM1);
        if(!mm.isEmpty())for(long raw:mm){
            println("  SIMCR candidate MM bit 0x0040: "+((raw & 0x40)!=0?"SET":"CLEAR")+
                " in immediate word "+hx(raw,4));
        }
        println("\n2. TPURAM CROSS-PROFILE HYPOTHESIS");
        if(trambar.isEmpty()) println("  No confirmed direct MOVE.W literal to TRAMBAR found.");
        for(long raw:trambar){
            long base32=((raw & 0xfff8L)<<8)&0xffffffL;
            long base36=((raw & 0xfff0L)<<8)&0xffffffL;
            boolean enabled=(raw & 1L)==0;
            println("  TRAMBAR candidate "+hx(raw,4)+", RAMDS="+(raw&1)+
                " (write-once after reset if supported).");
            println("    MC68332: 2 KiB TPURAM "+
                hx(base32,6)+".."+hx(base32+2047,6)+
                "; RAMDS="+(enabled?"0 (enable requested)":"1 (disabled)"));
            println("    MC68336/376: 3.5 KiB TPURAM "+
                hx(base36,6)+".."+hx(base36+3583,6)+
                "; RAMDS="+(enabled?"0 (enable requested)":"1 (disabled)"));
            if(base36==0xfff000L){
                println("    DISTINGUISHING CLUE: MC68336/376 TPURAM would overlap "+
                    "their MM=1 internal module register windows (TouCAN on MC68376 "+
                    "at 0xFFF080, QADC at 0xFFF200, CTM4 at 0xFFF400, and others).");
                println("    Such a TPURAM placement is invalid on those MCUs; "+
                    "the documented overlap inhibits valid RAM enabling.");
                println("    MC68332 2 KiB range ends at 0xFFF7FF, before its "+
                    "SIM/QSM/TPU control register blocks: better mapping candidate.");
            }
        }
        println("  LIMIT: reading initialization code or a function named memory_test "+
            "does NOT prove the test succeeded on actual ECU hardware.");

        println("\n3. EXTERNAL CS7 ADDRESS WINDOW");
        boolean coversCan=false;
        for(long raw:bar7){
            long[] window=csbarWindow((int)raw);
            println("  CSBAR7="+hx(raw,4)+" candidate window "+
                hx(window[0],6)+".."+hx(window[1],6));
            if(window[0]<=CAN_BASE && window[1]>=CAN_LAST)coversCan=true;
        }
        for(long raw:or7)println("  CSOR7="+hx(raw,4)+
            " (bus SPACE, RW, BYTE and CSPAR pin assignment still conditional)");
        println("  CS7 covers candidate 0xFF8800..0xFF88FF: "+coversCan);
        println("  NOTE: matching a CSBAR base is not proof that CS7 is active or that "+
            "a specific external CAN chip is connected.");

        println("\n4. CAN CONTROLLER REGISTER FOOTPRINT AT 0xFF8800");
        Set<String> uniqueInstructionAddresses=new TreeSet<>();
        Set<Integer> blocks=new TreeSet<>();
        int refsFound=0;
        int[] refCounts=new int[16];
        for(long numeric=CAN_BASE;numeric<=CAN_LAST;numeric++){
            monitor.checkCancelled();
            Address a=currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(numeric);
            ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(a);
            while(refs.hasNext()){
                monitor.checkCancelled();
                Reference ref=refs.next();
                Instruction insn=currentProgram.getListing()
                    .getInstructionContaining(ref.getFromAddress());
                if(insn==null)continue;
                String key=insn.getAddress().toString()+"/"+numeric;
                if(!uniqueInstructionAddresses.add(key))continue;
                int slot=(int)((numeric-CAN_BASE)/0x10);
                blocks.add(slot);refCounts[slot]++;refsFound++;
                if(refsFound<=30){
                    Function f=currentProgram.getFunctionManager()
                        .getFunctionContaining(insn.getAddress());
                    println("  "+insn.getAddress()+" -> "+hx(numeric,6)+" "+
                        insn+" (function="+(f==null?"?":f.getName())+")");
                }
            }
        }
        println("  Ghidra direct-XREF instruction/address pairs within first 256 bytes: "+refsFound);
        println("  16-byte slots with references (0x00=global, 0x10..0xF0=possible MO1..MO15): "+blocks);
        for(int slot:blocks)
            println("    slot +"+hx(slot*16,2)+" : "+refCounts[slot]+" XREF site(s)");
        println("  Bosch CC770 / Intel AN82527 memory-map hypothesis: "+
            "15 objects at offsets 0x10..0xF0, spacing 16 bytes.");
        println("  CPU external CS7 base differs from MC68376 internal TouCAN at 0xFFF080 "+
            "(assuming MM=1); these are two different peripheral candidates.");
        println("  Absence of direct-XREF hits does not refute an external CAN chip: "+
            "code may use indirect addressing or a hardware-dependent bus offset.");

        println("\n==== EVIDENCE VERDICT ====");
        println("  MC68332: plausible STRONGER candidate if TPURAM at 0xFFF000 "+
            "must operate successfully, but NOT IDENTIFIED.");
        println("  MC68336/376: MM=1 TPURAM-base conflict is a discriminating "+
            "conditional incompatibility, not proof of physical absence.");
        println("  CAN: external CC770/82527-compatible controller is a testable "+
            "hypothesis; inspect object 1..15 register semantics before naming.");
        println("  No Ghidra symbols, bytes, blocks, projects, hardware "+
            "or CAN devices were modified.");
        println("  Reference MC68332: https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf");
        println("  Reference MC68336/376: https://www.nxp.com/docs/en/user-guide/MC68336376UM.pdf");
        println("  Reference Bosch CC770: controller map needs confirming with original datasheet.");
    }
}
