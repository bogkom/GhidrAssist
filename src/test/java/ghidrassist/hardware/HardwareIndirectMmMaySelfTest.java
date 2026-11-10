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
        check(positive.contains("MM source chain") &&
            positive.contains("MM_SOURCE -> 0x00000700") &&
            yes.rows().get(0).source().mmWitness().chain()
                .equals(List.of(0x700L)),
            "positive computed JSR now discloses a target-rooted source chain");
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
            alias.markdown().contains("| UNKNOWN | true |") &&
            alias.markdown().contains("STORE_ALIAS -> 0x00000730"),
            "unknown address/STORE width is UNKNOWN with typed alias path");
        var control=HardwareIndirectMmMay.analyze(
            List.of(w(0x610,0x616,0x740)),graph,16);
        check(control.rows().get(0).source().unknownControl() &&
            control.markdown().contains("| UNKNOWN | false | true |") &&
            control.markdown().contains("UNKNOWN_FLOW -> 0x00000740"),
            "unknown CALL/flow is published with observed source target");
        var missing=HardwareIndirectMmMay.analyze(
            List.of(w(0x610,0x616,0x7f0)),graph,16);
        check(missing.rows().get(0).source().unknownControl() &&
            missing.rows().get(0).source().visited()==0 &&
            missing.markdown().contains("MISSING_TARGET -> 0x000007F0"),
            "unrecognized target is explicit checked-missing function, not no-MM");
        var cycle=HardwareIndirectMmMay.analyze(
            List.of(w(0x610,0x616,0x750)),graph,16);
        check(cycle.rows().get(0).source().cycle() &&
            cycle.rows().get(0).source().mayMm() &&
            cycle.rows().get(0).source().unknownControl() &&
            cycle.rows().get(0).source().unknownWitness()==null &&
            cycle.markdown().contains("A cycle-only uncertainty has no"),
            "cyclic source may contain MM but never invents a missing callee chain");
        // End-to-end byte-witnessed computed JSR source report: the
        // depth-4 backedge returns to the already observed target root.
        // It is recursion but NOT a fabricated uninspected MM frontier.
        var rootedLoop=List.of(
            node(0x900,false,false,false,0x902L),
            node(0x902,false,false,false,0x904L),
            node(0x904,false,false,false,0x906L),
            node(0x906,false,false,false,0x908L),
            node(0x908,true,false,false,0x900L));
        var loopReport=HardwareIndirectMmMay.analyze(
            List.of(w(0x610,0x616,0x900)),rootedLoop,16);
        var loopSource=loopReport.rows().get(0).source();
        check(loopSource.mayMm() && loopSource.cycle() &&
            loopSource.unknownControl() &&
            !loopSource.limited() &&
            loopSource.frontierWitness()==null &&
            loopSource.unknownWitness()==null &&
            loopSource.mmWitness().chain().equals(
                List.of(0x900L,0x902L,0x904L,0x906L,0x908L)) &&
            loopReport.markdown().contains("MM_SOURCE -> 0x00000900") &&
            !loopReport.markdown().contains("DEPTH_CUTOFF ->"),
            "byte-verified indirect JSR deep backedge is recursion, not an unvisited source");
        var chain=new ArrayList<HardwareInterproceduralMmEffects.FunctionNode>();
        for(int i=0;i<7;i++)
            chain.add(node(0x900+i*2,i==6,false,false,
                i==6?new Long[]{}:new Long[]{0x902L+i*2}));
        var capped=HardwareIndirectMmMay.analyze(
            List.of(w(0x610,0x616,0x900)),chain,16);
        check(!capped.rows().get(0).source().mayMm() &&
            capped.rows().get(0).source().limited() &&
            capped.markdown().contains("| UNKNOWN |") &&
            capped.markdown().contains("DEPTH_CUTOFF -> 0x00000900"),
            "depth cap remains an explicitly uninspected frontier");
        // One computed JSR reaches an inspected unknown STORE alias and
        // unknown control-flow function, while a different longer route
        // is cut off before a real positive SIMCR source can be examined.
        // Report BOTH the observed UNKNOWN and the skipped frontier.
        var dual=List.of(
            node(0x900,false,false,false,0xA00L,0x902L),
            node(0x902,false,false,false,0x904L),
            node(0x904,false,false,false,0x906L),
            node(0x906,false,false,false,0x908L),
            node(0x908,false,false,false,0x90AL),
            node(0x90A,true,false,false),
            node(0xA00,false,true,true));
        var dualReport=HardwareIndirectMmMay.analyze(
            List.of(w(0x610,0x616,0x900)),dual,16);
        var dualRow=dualReport.rows().get(0);
        var dualSource=dualRow.source();
        String dualText=dualReport.markdown();
        check(!dualSource.mayMm() && dualSource.unknownAlias() &&
            dualSource.unknownControl() && dualSource.limited() &&
            dualSource.aliasWitness().chain().equals(List.of(0x900L,0xA00L)) &&
            dualSource.unknownWitness().chain().equals(List.of(0x900L,0xA00L)) &&
            dualSource.frontierWitness().chain().equals(
                List.of(0x900L,0x902L,0x904L,0x906L,0x908L,0x90AL)),
            "Observed alias and control evidence coexist with uninspected potential MM");
        check(dualText.contains("STORE_ALIAS -> 0x00000900 -> 0x00000A00") &&
            dualText.contains("UNKNOWN_FLOW -> 0x00000900 -> 0x00000A00") &&
            dualText.contains("DEPTH_CUTOFF -> 0x00000900 -> 0x00000902") &&
            dualText.contains("NONE is not proof") &&
            dualText.contains("NOT the calling JSR PC"),
            "All typed indirect source witnesses are visible without executed CALL claims");
        var reverseDual=new ArrayList<>(dual);
        Collections.reverse(reverseDual);
        check(dualReport.equals(HardwareIndirectMmMay.analyze(
            List.of(w(0x610,0x616,0x900)),reverseDual,16)),
            "Source chain selection remains deterministic across function order");
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
        reject(()->new HardwareIndirectMmMay.Report(2,0,
                List.of(yes.rows().get(0),yes.rows().get(0))),
            "Manually constructed report cannot repeat a computed JSR PC");
        var foreignChain=new HardwareInterproceduralMmEffects.SourceWitness(
            HardwareInterproceduralMmEffects.WitnessKind.MM_SOURCE,
            List.of(0x730L));
        var foreignSummary=new HardwareInterproceduralMmEffects.Summary(
            true,false,false,false,false,1,foreignChain,null,null);
        reject(()->new HardwareIndirectMmMay.Row(site,foreignSummary),
            "Computed JSR target must equal source chain root");
        var foreignFrontier=new HardwareInterproceduralMmEffects.SourceWitness(
            HardwareInterproceduralMmEffects.WitnessKind.DEPTH_CUTOFF,
            List.of(0x730L,0x740L));
        var mixedSummary=new HardwareInterproceduralMmEffects.Summary(
            false,false,true,false,true,1,null,null,
            foreignFrontier,foreignFrontier);
        reject(()->new HardwareIndirectMmMay.Row(site,mixedSummary),
            "Uninspected frontier cannot borrow another computed CALL target");
        boolean immutable=false;
        try {many.rows().clear();}
        catch(UnsupportedOperationException expected){immutable=true;}
        check(immutable,"report row list immutable");
        System.out.println("HardwareIndirectMmMaySelfTest PASS: assertions="+assertions);
    }
}
