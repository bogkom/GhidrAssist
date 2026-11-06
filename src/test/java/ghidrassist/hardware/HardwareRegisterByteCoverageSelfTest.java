package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static ghidrassist.hardware.HardwareDataflow.Kind.*;

/**
 * GA-02/03/06: deterministic device-scoped byte-coverage annotations.
 * No actual Ghidra Program, real firmware, manual download or AI calls.
 */
public final class HardwareRegisterByteCoverageSelfTest {
    private static int assertions;
    private HardwareRegisterByteCoverageSelfTest() {}
    private static void check(boolean condition,String message) {
        assertions++;
        if(!condition)throw new AssertionError(message);
    }
    private static void rejects(Runnable test,String message) {
        boolean rejected=false;
        try {test.run();}
        catch(IllegalArgumentException expected) {rejected=true;}
        check(rejected,message);
    }
    private static HardwareRegisterByteCoverage.Store store(
            long call,long pc,Long addr,int bits) {
        return new HardwareRegisterByteCoverage.Store(call,pc,addr,bits);
    }
    private static HardwareRegisterByteCoverage.Hit hit(
            HardwareRegisterByteCoverage.Report report,String name,long base) {
        return report.hits().stream()
            .filter(h->name.equals(h.register()) && h.registerBase()==base)
            .findFirst().orElseThrow(()->new AssertionError(
                "Missing "+name+" at "+Long.toHexString(base)));
    }
    private static HardwareDataflow.Step ret(long pc) {
        return new HardwareDataflow.Step(pc,OTHER,null,0,0,null,0,
            List.of(),"RTS");
    }
    public static void main(String[] ignored) {
        var device=HardwareProfiles.mc68332();
        long simcr1=0xfffa00L,simcr0=0x7ffa00L;
        long csbar7=0xfffa68L,csor6=0xfffa66L;
        var exact=HardwareRegisterByteCoverage.analyze(device,List.of(
            store(0x108,0x640,simcr1,16)));
        var simcr=hit(exact,"SIMCR",simcr1);
        check(exact.sampledStores()==1 && exact.totalHits()==1 &&
            exact.unknownAddressOrWidth()==0 && simcr.coveredBytes()==2 &&
            simcr.wholeRegister() && simcr.exactRange() &&
            "EXACT_BYTE_RANGE".equals(simcr.coverage()),
            "aligned 16-bit SIMCR fully covers exact profile byte range");
        check(exact.markdown("one-hop").contains("STATIC MAY-ALIAS ONLY") &&
            exact.markdown("one-hop").contains("UNVERIFIED") &&
            exact.markdown("one-hop").contains("Apply permission"),
            "profile ranges and PDF pages remain metadata, not execution/Apply");
        var lowByte=HardwareRegisterByteCoverage.analyze(device,List.of(
            store(0x108,0x642,simcr1+1,8)));
        var partial=hit(lowByte,"SIMCR",simcr1);
        check(partial.coveredBytes()==1 && !partial.wholeRegister() &&
            !partial.exactRange() && "PARTIAL_REGISTER".equals(partial.coverage()),
            "MM low-byte STORE is not full SIMCR register value");
        var across=HardwareRegisterByteCoverage.analyze(device,List.of(
            store(0x108,0x644,csor6,32)));
        var left=hit(across,"CSOR6",csor6);
        var right=hit(across,"CSBAR7",csbar7);
        check(across.totalHits()==2 &&
            left.wholeRegister() && right.wholeRegister() &&
            !left.exactRange() && !right.exactRange() &&
            "SPANNING_WHOLE_REGISTER".equals(left.coverage()) &&
            "SPANNING_WHOLE_REGISTER".equals(right.coverage()),
            "MOVE.L crosses two distinct 16-bit register ranges without exact match");
        var span=HardwareRegisterByteCoverage.analyze(device,List.of(
            store(0x108,0x646,simcr1-2,32)));
        var simcrSpan=hit(span,"SIMCR",simcr1);
        check(simcrSpan.coveredBytes()==2 && simcrSpan.wholeRegister() &&
            !simcrSpan.exactRange(),
            "long STORE starting two bytes before SIMCR spans entire register");
        var wrongMap=HardwareRegisterByteCoverage.analyze(device,List.of(
            store(0x108,0x648,simcr0,16)));
        check(hit(wrongMap,"SIMCR",simcr0).exactRange() &&
            wrongMap.hits().stream().noneMatch(h->h.registerBase()==simcr1),
            "MM0 is a separate possible hardware map, not silently MM1");
        var eight=HardwareRegisterByteCoverage.analyze(device,List.of(
            store(0x108,0x64a,0xfffa21L,8)));
        check(hit(eight,"SYPCR",0xfffa21L).exactRange(),
            "profiled eight-bit MCU register has exact one-byte coverage");
        var readOnly=HardwareRegisterByteCoverage.analyze(device,List.of(
            store(0x108,0x64c,0xfffa07L,8)));
        check(hit(readOnly,"RSR",0xfffa07L).exactRange() &&
            readOnly.markdown("one-hop").contains("do NOT establish an accepted"),
            "read-only register overlap never becomes accepted hardware write");
        var controls=HardwareRegisterByteCoverage.analyze(device,List.of(
            store(0x108,0x64e,0x1200L,16),
            store(0x108,0x650,null,16),
            store(0x108,0x652,simcr1,0),
            store(0x108,0x654,simcr1,64)));
        check(controls.totalHits()==0 && controls.noProfiledRegister()==1 &&
            controls.unknownAddressOrWidth()==3 && controls.hits().isEmpty(),
            "unknown addresses/widths and non-profiled known addresses stay unproved");
        rejects(()->HardwareRegisterByteCoverage.analyze(
            HardwareProfiles.cpu32Family(),List.of(store(1,2,simcr1,16))),
            "generic CPU32 cannot silently inherit MC68332 register widths");
        rejects(()->HardwareRegisterByteCoverage.analyze(device,null),
            "null source collection must reject");
        rejects(()->HardwareRegisterByteCoverage.analyze(device,
            java.util.Arrays.asList(store(1,2,simcr1,16),null)),
            "null STORE must not be dropped as harmless");
        rejects(()->store(1,2,0x1000000L,16),
            "foreign 25-bit address cannot alias wrapped MCU24 register");
        rejects(()->store(1,2,-1L,16),
            "negative STORE address cannot become valid");
        rejects(()->HardwareRegisterByteCoverage.analyze(device,
            java.util.Collections.nCopies(
                HardwareRegisterByteCoverage.MAX_STORES+1,
                store(1,2,simcr1,16))),
            "unbounded external source rows must reject");
        var many=new ArrayList<HardwareRegisterByteCoverage.Store>();
        for(int i=0;i<HardwareRegisterByteCoverage.MAX_STORES;i++)
            many.add(store(0x100+i,0x600+i,0xfffd40L,32));
        var capped=HardwareRegisterByteCoverage.analyze(device,many);
        check(capped.totalHits()==4*HardwareRegisterByteCoverage.MAX_STORES &&
            capped.hits().size()==HardwareRegisterByteCoverage.MAX_DISPLAY_HITS &&
            capped.omittedHits()==capped.totalHits()-capped.hits().size() &&
            capped.markdown("two-hop").contains("INCOMPLETE COVERAGE DISPLAY"),
            "exact count and explicit omission when four packed CR bytes per STORE");
        boolean immutable=false;
        try {capped.hits().clear();}
        catch(UnsupportedOperationException expected) {immutable=true;}
        check(immutable,"coverage returned as immutable evidence");
        var reversed=new ArrayList<>(many);
        java.util.Collections.reverse(reversed);
        check(capped.equals(HardwareRegisterByteCoverage.analyze(device,reversed)),
            "classification order independent of external input order");

        // The same annotation consumes genuine one-hop and two-hop solver
        // output; it does not substitute a guessed CALL or inherit a cache.
        var leaf=new HardwareCallsiteRegisterFlow.Callee(0x700,List.of(
            new HardwareDataflow.Step(0x700,STORE_INDIRECT,
                "A1","D0",0,0,null,32,List.of(0x702L),"MOVE.L"),
            ret(0x702)),true);
        var bridge=new HardwareTwoHopRegisterFlow.Bridge(0x640,List.of(
            new HardwareDataflow.Step(0x640,COPY_POINTER,"A1","A0",
                0,0,null,0,List.of(0x642L),"MOVEA.L"),
            new HardwareDataflow.Step(0x642,CALL_BARRIER,null,
                0,0,null,0,List.of(0x648L),"JSR"),
            ret(0x648)),0x642,0x700L,true);
        var outer=new HardwareCallsiteRegisterFlow.Call(
            0x600,0x60c,0x640L,Map.of("A0",csor6,"D0",0x1234L),false);
        var two=HardwareTwoHopRegisterFlow.analyze(
            List.of(outer),List.of(bridge),List.of(leaf),
            Set.of(csbar7,csor6),8);
        check(two.possibleStores()==1 && two.rows().size()==1 &&
            two.rows().get(0).effectiveAddress()==csor6,
            "two-hop CALL solver preserves source STORE before register classification");
        var annotated=HardwareRegisterByteCoverage.analyze(device,
            two.rows().stream().map(c->store(
                c.outerCallPc(),c.storePc(),c.effectiveAddress(),c.bits()))
                .toList());
        check(annotated.totalHits()==2 &&
            hit(annotated,"CSBAR7",csbar7).wholeRegister() &&
            hit(annotated,"CSOR6",csor6).wholeRegister(),
            "two-hop source produces two width-aware metadata overlaps");
        var one=new HardwareCallsiteRegisterFlow.Call(
            0x500,0x50c,0x700L,Map.of("A1",csor6,"D0",0x1234L),false);
        var direct=HardwareCallsiteRegisterFlow.analyze(
            List.of(one),List.of(leaf),Set.of(csbar7,csor6),8);
        var directAnnotated=HardwareRegisterByteCoverage.analyze(device,
            direct.candidates().stream().map(c->store(
                c.callPc(),c.storePc(),c.address(),c.writeBits())).toList());
        check(direct.possibleStoreSites()==1 && directAnnotated.totalHits()==2 &&
            hit(directAnnotated,"CSBAR7",csbar7).wholeRegister(),
            "one-hop source and two-hop source share the same metadata rule");
        System.out.println("HardwareRegisterByteCoverageSelfTest PASS: assertions="+assertions);
    }
}
