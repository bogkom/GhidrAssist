package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

/** GA-02/03/11: no Ghidra, firmware, model or network. */
public final class HardwareIndirectMmMaySelfTest {
    private HardwareIndirectMmMaySelfTest(){}
    private static int assertions;
    private static void check(boolean v,String message) {
        assertions++;
        if(!v)throw new AssertionError(message);
    }
    private static void reject(Runnable r,String message) {
        boolean yes=false;
        try{r.run();}catch(IllegalArgumentException expected){yes=true;}
        check(yes,message);
    }
    private static HardwareIndirectCallEvidence.Site w(long caller,long pc,long target){
        return new HardwareIndirectCallEvidence.Site(caller,caller,pc,target);
    }
    private static HardwareInterproceduralMmEffects.FunctionNode node(long id,
            boolean mm,boolean alias,boolean unknown,Long... calls){
        return new HardwareInterproceduralMmEffects.FunctionNode(
            id,mm,alias,unknown,List.of(calls));
    }
    public static void main(String[] ignored){
        var graph=List.of(
            node(0x700,true,false,false),
            node(0x720,false,false,false),
            node(0x730,false,true,false),
            node(0x740,false,false,true),
            node(0x750,false,false,false,0x760L),
            node(0x760,true,false,false,0x750L),
            node(0x780,false,false,false,0x700L)
        );
        var site=w(0x600,0x606,0x700);
        var yes=HardwareIndirectMmMay.analyze(List.of(site),graph,16);
        check(yes.totalWitnesses()==1 && yes.omittedWitnesses()==0 &&
            yes.rows().get(0).source().mayMm() &&
            !yes.rows().get(0).source().uncertainOrMm()==false,
            "byte-witnessed target can contain potential SIMCR low-byte STORE");
        String positive=yes.markdown();
        check(positive.contains("STATIC_MAY_MM_LOW_BYTE") &&
            positive.contains("NEVER EXECUTION") &&
            positive.contains("NEVER APPLY") &&
            positive.contains("No direct CALL/RESET/ISR edge") &&
            positive.contains("MM0 and MM1 are conditional alternatives"),
            "source MM metadata must not create hardware/RESET/Apply proof");
        var resetNodes=List.of(
            new HardwareCallEffects.FunctionNode(0x600,false,false,true,List.of()),
            new HardwareCallEffects.FunctionNode(0x700,true,false,false,List.of()));
        var reset=HardwareResetFlow.trace(0x600,resetNodes,Set.of(0x700L),5,10,10);
        check(reset.visitedEntries().equals(Set.of(0x600L)) &&
            reset.unresolved() && reset.evidence().isEmpty(),
            "the indirect MM source cannot change direct RESET reachability");
        var closed=HardwareIndirectMmMay.analyze(
            List.of(w(0x610,0x616,0x720)),graph,16);
        check(closed.markdown().contains("NOT_OBSERVED_IN_BOUNDED_SOURCE") &&
            !closed.rows().get(0).source().uncertainOrMm(),
            "closed source subtree is bounded negative not no-MM proof");
        var alias=HardwareIndirectMmMay.analyze(
            List.of(w(0x610,0x616,0x730)),graph,16);
        check(alias.rows().get(0).source().unknownAlias() &&
            alias.markdown().contains("| UNKNOWN | true |"),
            "unknown address/STORE width is UNKNOWN, not MM absence");
        var control=HardwareIndirectMmMay.analyze(
            List.of(w(0x610,0x616,0x740)),graph,16);
        check(control.rows().get(0).source().unknownControl() &&
            control.markdown().contains("| UNKNOWN | false | true |"),
            "unknown CALL/flow propagates into MM uncertainty");
        var missing=HardwareIndirectMmMay.analyze(
            List.of(w(0x610,0x616,0x7f0)),graph,16);
        check(missing.rows().get(0).source().unknownControl() &&
            missing.rows().get(0).source().visited()==0 &&
            missing.markdown().contains("UNKNOWN"),
            "unrecognized function target stays UNKNOWN");
        var cycle=HardwareIndirectMmMay.analyze(
            List.of(w(0x610,0x616,0x750)),graph,16);
        check(cycle.rows().get(0).source().cycle() &&
            cycle.rows().get(0).source().mayMm() &&
            cycle.rows().get(0).source().unknownControl(),
            "cyclic source may contain MM but is never complete");
        var chain=new ArrayList<HardwareInterproceduralMmEffects.FunctionNode>();
        for(int i=0;i<7;i++)
            chain.add(node(0x900+i*2,i==6,false,false,
                i==6?new Long[]{}:new Long[]{0x902L+i*2}));
        var capped=HardwareIndirectMmMay.analyze(
            List.of(w(0x610,0x616,0x900)),chain,16);
        check(!capped.rows().get(0).source().mayMm() &&
            capped.rows().get(0).source().limited() &&
            capped.markdown().contains("| UNKNOWN |"),
            "depth cap cannot become definitive negative MM evidence");
        var ws=new ArrayList<HardwareIndirectCallEvidence.Site>();
        for(int i=0;i<17;i++)
            ws.add(w(0x100+i*16,0x106+i*16,0x700));
        var many=HardwareIndirectMmMay.analyze(ws,graph,16);
        check(many.totalWitnesses()==17 && many.omittedWitnesses()==1 &&
            many.rows().size()==16 &&
            many.markdown().contains("INCOMPLETE INDIRECTION MAY EVIDENCE"),
            "16 row cap retains omission and unknown");
        var reversed=new ArrayList<>(ws);
        Collections.reverse(reversed);
        check(many.equals(HardwareIndirectMmMay.analyze(reversed,graph,16)),
            "order-independent deterministic source reports");
        var empty=HardwareIndirectMmMay.analyze(List.of(),graph,16);
        check(empty.rows().isEmpty() &&
            empty.markdown().contains("NOT proof of no indirect calls"),
            "unverified computed XREF is not byte-witnessed indirect MM source");
        reject(()->HardwareIndirectMmMay.analyze(List.of(site),graph,0),
            "zero row cap rejected");
        reject(()->HardwareIndirectMmMay.analyze(List.of(site),graph,17),
            "unbounded row cap rejected");
        reject(()->HardwareIndirectMmMay.analyze(
            java.util.Arrays.asList(site,null),graph,16),
            "null source rejected");
        reject(()->HardwareIndirectMmMay.analyze(
            List.of(site,site),graph,16),
            "duplicate JSR PC rejected");
        reject(()->HardwareIndirectMmMay.analyze(
            List.of(site),List.of(node(0x700,false,false,false),
                node(0x700,true,false,false)),16),
            "duplicate functions not silently reconciled");
        // Reports can also be constructed by consumers; reject incomplete
        // evidence before Markdown rendering instead of a late NPE.
        reject(()->new HardwareIndirectMmMay.Report(1,0,null),
            "null report rows rejected");
        reject(()->new HardwareIndirectMmMay.Report(1,0,
                java.util.Arrays.asList((HardwareIndirectMmMay.Row)null)),
            "null report row rejected");
        reject(()->new HardwareIndirectMmMay.Report(1,0,
                List.of(new HardwareIndirectMmMay.Row(null,yes.rows().get(0).source()))),
            "missing byte witness rejected");
        reject(()->new HardwareIndirectMmMay.Report(1,0,
                List.of(new HardwareIndirectMmMay.Row(site,null))),
            "missing MM source summary rejected");
        reject(()->new HardwareIndirectMmMay.Report(1,0,
                List.of(new HardwareIndirectMmMay.Row(site,
                    new HardwareInterproceduralMmEffects.Summary(
                        false,false,false,false,false,-1)))),
            "negative examined-node count rejected");
        reject(()->new HardwareIndirectMmMay.Report(0,0,yes.rows()),
            "inconsistent omission/count rejected");
        boolean immutable=false;
        try {many.rows().clear();}
        catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"report row list immutable");
        System.out.println("HardwareIndirectMmMaySelfTest PASS: assertions="+assertions);
    }
}
