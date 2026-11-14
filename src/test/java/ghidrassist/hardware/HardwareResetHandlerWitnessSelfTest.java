package ghidrassist.hardware;

import java.util.List;

public final class HardwareResetHandlerWitnessSelfTest {
    private static void check(boolean value,String label) {
        if(!value)throw new AssertionError(label);
    }
    private static void bad(Runnable r) {
        try {r.run();throw new AssertionError("Expected rejection");}
        catch(IllegalArgumentException expected) {}
    }
    private static HardwareCallEffects.FunctionNode n(long id,Long... calls) {
        return new HardwareCallEffects.FunctionNode(id,false,false,false,List.of(calls));
    }
    public static void main(String[] args) {
        var graph=List.of(n(0x100L,0x130L,0x160L),n(0x130L,0x190L),
            n(0x160L,0x190L),n(0x190L));
        var targets=List.of(
            new HardwareVectorResetCorrelation.Target(40,0x190,0x190,true),
            new HardwareVectorResetCorrelation.Target(41,0x190,0x190,true),
            new HardwareVectorResetCorrelation.Target(42,0x192,0x190,false),
            new HardwareVectorResetCorrelation.Target(43,0x300,0x300,true));
        var a=HardwareResetHandlerWitness.inspect(0x100,false,graph,targets);
        check(!a.incomplete() && a.inspected()==4 && a.rows().size()==4,
            "complete static traversal");
        check(a.rows().get(0).chain().equals(List.of(0x100L,0x130L,0x190L)) &&
            a.rows().get(1).chain().equals(a.rows().get(0).chain()),
            "shortest deterministic convergent path and handler aliases");
        check(a.rows().get(2).status()==
            HardwareResetHandlerWitness.Status.INTERIOR_NOT_ENTRY &&
            a.rows().get(3).status()==
            HardwareResetHandlerWitness.Status.NOT_OBSERVED_WITHIN_BOUND,
            "interior pointer and outside complete graph");
        check(a.markdown().contains("STATIC ONLY") &&
            a.markdown().contains("0x00000100 -> 0x00000130 -> 0x00000190"),
            "source evidence and execution disclaimer");
        var reversed=HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(graph.get(3),graph.get(2),graph.get(1),graph.get(0)),targets);
        check(a.equals(reversed),"node ordering deterministic");
        var shuffledEdges=HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(n(0x100L,0x160L,0x130L),n(0x130L,0x190L),
                n(0x160L,0x190L),n(0x190L)),targets);
        check(a.equals(shuffledEdges),
            "CALL edge insertion order must not change shortest witness");
        var competing=HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(n(0x100L,0x160L,0x130L),
                n(0x130L,0x190L),n(0x160L,0x190L),n(0x190L)),targets);
        check(competing.rows().get(0).chain().equals(
            List.of(0x100L,0x130L,0x190L)),
            "equal-length paths use canonical function-entry tie-break");
        var missing=HardwareResetHandlerWitness.inspect(0x500,false,graph,targets);
        check(missing.missingRoot() && missing.incomplete() &&
            missing.rows().get(0).status()==
                HardwareResetHandlerWitness.Status.UNKNOWN_RESET_ROOT,
            "missing RESET is unknown, not unreachable");
        var frontier=HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(n(0x100L,0x130L),n(0x130L,0x999L)),targets);
        check(frontier.incomplete() && !frontier.frontiers().isEmpty() &&
            frontier.rows().get(3).status()==
                HardwareResetHandlerWitness.Status.UNKNOWN_FRONTIER,
            "missing CALL target propagates uncertainty");
        // A known cycle is not an uninspected frontier; a depth cutoff is.
        var cycle=HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(n(0x100L,0x130L),n(0x130L,0x100L)),targets);
        check(!cycle.incomplete() && cycle.frontiers().isEmpty() &&
            cycle.rows().get(0).status()==
                HardwareResetHandlerWitness.Status.NOT_OBSERVED_WITHIN_BOUND,
            "cycle does not manufacture an unknown frontier");
        var deep=new java.util.ArrayList<HardwareCallEffects.FunctionNode>();
        for(int i=0;i<10;i++)
            deep.add(n(0x100L+i*2L,0x102L+i*2L));
        var depth=HardwareResetHandlerWitness.inspect(0x100,false,deep,
            List.of(new HardwareVectorResetCorrelation.Target(
                50,0x112L,0x112L,true)));
        check(depth.incomplete() && depth.inspected()==9 &&
            depth.rows().get(0).status()==
                HardwareResetHandlerWitness.Status.UNKNOWN_FRONTIER &&
            depth.frontiers().get(0).size()==10,
            "depth cutoff preserves uninspected next edge");
        var unresolved=HardwareResetHandlerWitness.inspect(0x100,true,graph,targets);
        check(unresolved.incomplete() && unresolved.rows().get(3).status()==
            HardwareResetHandlerWitness.Status.UNKNOWN_FRONTIER,
            "upstream incomplete RESET cannot prove negative reachability");
        // Unknown indirect flow is attributable to the exact inspected source,
        // not to a guessed target or to a runtime ISR execution.
        var unknownGraph=List.of(
            new HardwareCallEffects.FunctionNode(0x100L,false,false,true,List.of(0x130L)),
            new HardwareCallEffects.FunctionNode(0x130L,false,false,true,List.of()));
        var unknown=HardwareResetHandlerWitness.inspect(0x100,false,unknownGraph,targets);
        check(unknown.incomplete() && unknown.frontiers().isEmpty() &&
            unknown.unresolvedCallSources().equals(List.of(
                List.of(0x100L),List.of(0x100L,0x130L))) &&
            unknown.rows().get(3).status()==
                HardwareResetHandlerWitness.Status.UNKNOWN_FRONTIER,
            "unresolved CALL source provenance survives even without missing edges");
        check(unknown.markdown().contains("UNRESOLVED CALL source: 0x00000100 -> 0x00000130") &&
            !a.markdown().contains("UNRESOLVED CALL source:"),
            "unknown sources are explicit and absent in complete graph");
        var immutable=unknown.unresolvedCallSources();
        bad(()->immutable.add(List.of(0x100L)));
        bad(()->new HardwareResetHandlerWitness.Report(0x100,false,false,0,
            List.of(),List.of(),List.of(List.of())));
        bad(()->HardwareResetHandlerWitness.inspect(0x101,false,graph,targets));
        bad(()->HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(n(0x100L),n(0x100L)),targets));
        bad(()->HardwareResetHandlerWitness.inspect(0x100,false,graph,
            List.of(targets.get(0),targets.get(0))));
        System.out.println("RESET_HANDLER_WITNESS_SOURCE_PASS");
    }
}
