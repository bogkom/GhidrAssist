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
            HardwareResetHandlerWitness.Status.UNKNOWN_HANDLER_NOT_IN_GRAPH,
            "interior pointer and handler absent from complete graph");
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
            frontier.omittedFrontierEdges()==0 &&
            frontier.rows().get(3).status()==
                HardwareResetHandlerWitness.Status.UNKNOWN_FRONTIER,
            "missing CALL target propagates uncertainty");
        // The bounded frontier list is a DISPLAY, never an exhaustive
        // 200k-edge proof. Missing definitions from one RESET node must
        // be counted even after the 100-path receipt cap has been reached.
        var manyMissing=new java.util.ArrayList<Long>();
        for(int i=0;i<150;i++)manyMissing.add(0x200L+i*2L);
        var capped=HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(new HardwareCallEffects.FunctionNode(
                0x100,false,false,false,manyMissing)),
            List.of(new HardwareVectorResetCorrelation.Target(
                50,0x200L,0x200L,true)));
        check(capped.incomplete() && capped.inspected()==1 &&
            capped.frontiers().size()==HardwareResetHandlerWitness.MAX_NODES &&
            capped.omittedFrontierEdges()==50 &&
            capped.rows().get(0).status()==
                HardwareResetHandlerWitness.Status.UNKNOWN_FRONTIER &&
            capped.markdown().contains("omitted frontier edges 50") &&
            capped.markdown().contains("INCOMPLETE FRONTIER INVENTORY") &&
            capped.markdown().contains("omitted targets remain UNKNOWN"),
            "frontier cap declares every omitted direct-CALL edge");
        var reverseMissing=new java.util.ArrayList<>(manyMissing);
        java.util.Collections.reverse(reverseMissing);
        check(HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(new HardwareCallEffects.FunctionNode(
                0x100,false,false,false,reverseMissing)),
            List.of(new HardwareVectorResetCorrelation.Target(
                50,0x200L,0x200L,true))).equals(capped),
            "canonical decoded edges produce deterministic omitted receipts");
        var exactlyCapped=HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(new HardwareCallEffects.FunctionNode(0x100,
                false,false,false,manyMissing.subList(0,100))),List.of());
        check(exactlyCapped.frontiers().size()==100 &&
            exactlyCapped.omittedFrontierEdges()==0 &&
            !exactlyCapped.markdown().contains("INCOMPLETE FRONTIER INVENTORY"),
            "exactly the display cap is not falsely called a dropped source");
        // A known cycle is not an uninspected frontier; a depth cutoff is.
        var cycle=HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(n(0x100L,0x130L),n(0x130L,0x100L)),targets);
        check(!cycle.incomplete() && cycle.frontiers().isEmpty() &&
            cycle.rows().get(0).status()==
                HardwareResetHandlerWitness.Status.UNKNOWN_HANDLER_NOT_IN_GRAPH,
            "cycle does not manufacture an unknown frontier or handler inventory");
        var disconnected=HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(n(0x100L,0x130L),n(0x130L),n(0x300L)),targets);
        check(!disconnected.incomplete() &&
            disconnected.rows().get(3).status()==
                HardwareResetHandlerWitness.Status.NOT_OBSERVED_WITHIN_BOUND,
            "recognized disconnected handler is a bounded negative, not absent evidence");
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
        // Independent positive source effects: paths identify inspected function
        // nodes only; they do not imply that either instruction executed.
        var effectGraph=List.of(
            n(0x100L,0x130L,0x160L),
            new HardwareCallEffects.FunctionNode(0x130L,true,false,false,List.of()),
            new HardwareCallEffects.FunctionNode(0x160L,false,true,false,List.of()));
        var effects=HardwareResetHandlerWitness.inspect(0x100,false,effectGraph,targets);
        check(effects.memoryStoreSources().equals(List.of(List.of(0x100L,0x130L))) &&
            effects.vbrWriteSources().equals(List.of(List.of(0x100L,0x160L))) &&
            effects.markdown().contains("POSSIBLE STORE source: 0x00000100 -> 0x00000130") &&
            effects.markdown().contains("POSSIBLE MOVEC/VBR source: 0x00000100 -> 0x00000160"),
            "independent static STORE and VBR source provenance");
        var reversedEffects=HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(effectGraph.get(2),effectGraph.get(1),effectGraph.get(0)),targets);
        check(effects.equals(reversedEffects),"effect sources invariant under graph order");
        check(a.memoryStoreSources().isEmpty() && a.vbrWriteSources().isEmpty() &&
            unknown.memoryStoreSources().isEmpty() && unknown.vbrWriteSources().isEmpty(),
            "negative controls: no invented STORE or VBR evidence");
        try {effects.vbrWriteSources().get(0).add(0x180L);
            throw new AssertionError("Mutable effect provenance");
        } catch(UnsupportedOperationException expected) {}
        var immutable=unknown.unresolvedCallSources();
        try { immutable.add(List.of(0x100L)); throw new AssertionError("Mutable provenance"); }
        catch(UnsupportedOperationException expected) {}
        bad(()->new HardwareResetHandlerWitness.Report(0x100,false,false,0,
            List.of(),List.of(),List.of(List.of())));
        bad(()->HardwareResetHandlerWitness.inspect(0x101,false,graph,targets));
        bad(()->HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(n(0x100L),n(0x100L)),targets));
        bad(()->HardwareResetHandlerWitness.inspect(0x100,false,graph,
            List.of(targets.get(0),targets.get(0))));
        // The BFS visits at most 100 nodes, but all 50k source entries
        // could otherwise carry an unbounded number of direct CALL edges.
        // Count raw edges *before* admitting an apparently complete graph.
        var maxEdges=List.copyOf(java.util.Collections.nCopies(
            HardwareResetHandlerWitness.MAX_SOURCE_EDGES,0x130L));
        var legal=HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(new HardwareCallEffects.FunctionNode(
                0x100,false,false,false,maxEdges),n(0x130L)),
            List.of());
        check(!legal.incomplete() && legal.inspected()==2 &&
            legal.frontiers().isEmpty(),
            "exact 200k observed direct-edge input remains bounded and valid");
        var tooManyEdges=new java.util.ArrayList<Long>(maxEdges);
        tooManyEdges.add(0x130L);
        bad(()->HardwareResetHandlerWitness.inspect(0x100,false,
            List.of(new HardwareCallEffects.FunctionNode(
                0x100,false,false,false,tooManyEdges),n(0x130L)),
            List.of()));
        // Public report cannot pass a null, foreign, oversized, or
        // wrong-root chain through later evidence publication.
        bad(()->new HardwareResetHandlerWitness.Report(
            0x100,false,false,1,List.of(),List.of(),
            List.of(),List.of(List.of(0x200L)),List.of()));
        bad(()->new HardwareResetHandlerWitness.Report(
            0x100,false,false,1,List.of(),List.of(),
            List.of(),List.of(List.of(0x100L,0x100000000L)),List.of()));
        bad(()->new HardwareResetHandlerWitness.Report(
            0x100,false,false,1,List.of(),List.of(),
            List.of(),List.of(List.of(0x100L,0x131L)),List.of()));
        bad(()->new HardwareResetHandlerWitness.Report(
            0x100,true,true,0,List.of(),List.of(),
            List.of(),List.of(List.of(0x100L)),List.of()));
        bad(()->new HardwareResetHandlerWitness.Report(
            0x101,true,false,1,List.of(),List.of(),List.of()));
        // Public report records are externally reconstructible. A caller
        // must not fabricate COMPLETE with unresolved CALLs, invent source
        // chains beyond inspected nodes, or claim a definite negative
        // handler relationship while a RESET frontier remains open.
        bad(()->new HardwareResetHandlerWitness.Report(
            0x100,false,false,1,List.of(),List.of(),
            List.of(List.of(0x100L))));
        bad(()->new HardwareResetHandlerWitness.Report(
            0x100,false,false,1,List.of(),
            List.of(List.of(0x100L,0x200L)),List.of()));
        bad(()->new HardwareResetHandlerWitness.Report(
            0x100,true,false,1,
            List.of(new HardwareResetHandlerWitness.Row(
                40,0x200L,HardwareResetHandlerWitness.Status.NOT_OBSERVED_WITHIN_BOUND,
                List.of())),
            List.of(List.of(0x100L,0x200L)),List.of()));
        bad(()->new HardwareResetHandlerWitness.Report(
            0x100,false,false,1,
            List.of(new HardwareResetHandlerWitness.Row(
                40,0x200L,HardwareResetHandlerWitness.Status.UNKNOWN_FRONTIER,
                List.of())),List.of(),List.of()));
        bad(()->new HardwareResetHandlerWitness.Report(
            0x100,true,false,1,
            List.of(new HardwareResetHandlerWitness.Row(
                40,0x200L,HardwareResetHandlerWitness.Status.UNKNOWN_RESET_ROOT,
                List.of())),List.of(),List.of()));
        bad(()->new HardwareResetHandlerWitness.Report(
            0x500,true,true,0,
            List.of(new HardwareResetHandlerWitness.Row(
                40,0x200L,HardwareResetHandlerWitness.Status.UNKNOWN_FRONTIER,
                List.of())),List.of(),List.of()));
        bad(()->new HardwareResetHandlerWitness.Report(
            0x100,true,false,1,
            List.of(new HardwareResetHandlerWitness.Row(
                40,0x130L,HardwareResetHandlerWitness.Status.OBSERVED_STATIC_PATH,
                List.of(0x100L,0x130L))),List.of(),List.of()));
        bad(()->new HardwareResetHandlerWitness.Report(
            0x100,true,false,1,List.of(),List.of(),
            List.of(List.of(0x100L,0x130L))));
        bad(()->new HardwareResetHandlerWitness.Report(
            0x100,true,false,3,List.of(),List.of(),
            List.of(List.of(0x100L,0x130L,0x100L))));
        bad(()->new HardwareResetHandlerWitness.Report(
            0x100,true,false,1,List.of(),
            List.of(List.of(0x100L,0x200L)),List.of(),
            List.of(),List.of(),1));
        bad(()->new HardwareResetHandlerWitness.Report(
            0x100,true,false,1,List.of(),List.of(),List.of(),
            List.of(),List.of(),HardwareResetHandlerWitness.MAX_SOURCE_EDGES+1));
        bad(()->new HardwareResetHandlerWitness.Row(
            40,0x100L,HardwareResetHandlerWitness.Status.OBSERVED_STATIC_PATH,
            List.of(0x100L,0x130L,0x100L)));
        check(unknown.omittedFrontierEdges()==0 &&
            a.omittedFrontierEdges()==0 &&
            effects.omittedFrontierEdges()==0 &&
            HardwareResetHandlerWitness.inspect(0x100,false,
            graph,targets).equals(a),
            "source guard rejects forgeries without modifying positive witness");
        System.out.println("RESET_HANDLER_WITNESS_SOURCE_PASS");
    }
}
