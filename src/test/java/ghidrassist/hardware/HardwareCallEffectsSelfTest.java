package ghidrassist.hardware;

import java.util.List;

public final class HardwareCallEffectsSelfTest {
    private static void ok(boolean v,String cause){if(!v)throw new AssertionError(cause);}
    private static HardwareCallEffects.FunctionNode n(long id,boolean store,
            boolean vbr,boolean unknown,Long... callees){
        return new HardwareCallEffects.FunctionNode(id,store,vbr,unknown,
            List.of(callees));
    }
    public static void main(String[] args){
        var graph=List.of(
            n(0,false,false,false,1L,2L),
            n(1,false,true,false,3L),
            n(2,false,false,false,3L),
            n(3,true,false,false)
        );
        var effects=HardwareCallEffects.summarize(0,graph,5,20);
        ok(effects.possibleMemoryStore() && effects.possibleVbrWrite() &&
            !effects.unresolved() && effects.visited()==4,
            "diamond call graph aggregates may-write effects once");
        ok(effects.description().contains("NOT an execution/reset-path proof"),
            "reports never claim a runtime boot route");
        var missing=HardwareCallEffects.summarize(0,List.of(n(0,false,false,false,1L)),5,10);
        ok(missing.unresolved() && !missing.possibleMemoryStore(),
            "missing external callee must not be treated as pure");
        var indirect=HardwareCallEffects.summarize(0,
            List.of(n(0,false,false,true)),5,10);
        ok(indirect.unresolved(),"unresolved indirect call stays uncertain");
        var recursive=HardwareCallEffects.summarize(0,
            List.of(n(0,false,false,false,1L),
                    n(1,false,false,false,0L)),5,10);
        ok(recursive.recursive() && recursive.unresolved(),
            "recursion must not be marked safe/closed");
        var limited=HardwareCallEffects.summarize(0,graph,1,20);
        ok(limited.truncated() && limited.unresolved(),
            "bounded depth must not fake closed graph");
        var countLimited=HardwareCallEffects.summarize(0,graph,10,2);
        ok(countLimited.truncated() && countLimited.unresolved(),
            "bounded node count must remain explicit");
        // A bounded source inventory must not change its observed subset
        // merely because Ghidra enumerates the same CALL references in a
        // different order. The late positive STORE remains UNKNOWN, not
        // a false complete negative, when the canonical smaller target
        // fits the sole remaining budget slot.
        var unsortedRoot=n(0,false,false,false,0x400L,0x100L);
        var sortedRoot=n(0,false,false,false,0x100L,0x400L);
        var orderNodes=List.of(n(0x100L,false,false,false),
            n(0x400L,true,false,false));
        ok(unsortedRoot.directCallees().equals(List.of(0x100L,0x400L)) &&
            unsortedRoot.directCallees().equals(sortedRoot.directCallees()),
            "source direct-CALL adjacency canonically sorted, duplicate edges retained");
        var limitedA=HardwareCallEffects.summarize(0,
            List.of(unsortedRoot,orderNodes.get(1),orderNodes.get(0)),3,2);
        var limitedB=HardwareCallEffects.summarize(0,
            List.of(orderNodes.get(0),sortedRoot,orderNodes.get(1)),3,2);
        ok(limitedA.equals(limitedB) && limitedA.truncated() &&
            limitedA.unresolved() && limitedA.visited()==2 &&
            !limitedA.possibleMemoryStore(),
            "canonical budget selects the same source subset, omitted STORE stays UNKNOWN");
        var fullA=HardwareCallEffects.summarize(0,
            List.of(unsortedRoot,orderNodes.get(1),orderNodes.get(0)),3,3);
        var fullB=HardwareCallEffects.summarize(0,
            List.of(orderNodes.get(0),sortedRoot,orderNodes.get(1)),3,3);
        ok(fullA.equals(fullB) && fullA.possibleMemoryStore() &&
            !fullA.truncated() && !fullA.unresolved(),
            "complete source graph still observes positive MMIO STORE");
        // Depth-first traversal used to cache function 4 first at depth=3,
        // then skip the *shorter* root->4 edge. That wrongly omitted node 5
        // (STORE) despite a bounded two-hop direct-call path.
        var shorter=HardwareCallEffects.summarize(0,List.of(
            n(0,false,false,false,1L,4L),
            n(1,false,false,false,2L),
            n(2,false,false,false,4L),
            n(4,false,true,false,5L),
            n(5,true,false,false)),3,20);
        ok(shorter.possibleMemoryStore() && shorter.possibleVbrWrite() &&
            !shorter.unresolved() && shorter.visited()==5,
            "shortest source-call path must retain all within-budget effects");
        var cycleShort=HardwareCallEffects.summarize(0,List.of(
            n(0,false,false,false,1L,2L),
            n(1,false,false,false,2L),
            n(2,false,false,false,1L)),3,20);
        ok(cycleShort.recursive() && cycleShort.unresolved(),
            "BFS merge must still detect real source-call cycles");
        // Very deep static graph should remain bounded by user limits,
        // not by the JVM call stack.
        java.util.List<HardwareCallEffects.FunctionNode> longChain=
            new java.util.ArrayList<>();
        for(int i=0;i<1500;i++)
            longChain.add(n(i,i==1499,false,false,
                i==1499?new Long[0]:new Long[]{(long)i+1}));
        var deep=HardwareCallEffects.summarize(0,longChain,1500,1600);
        ok(deep.visited()==1500 && deep.possibleMemoryStore() &&
            !deep.truncated() && !deep.unresolved(),
            "deep valid graph must avoid recursion stack exhaustion");
        var noWrites=HardwareCallEffects.summarize(0,
            List.of(n(0,false,false,false,1L),n(1,false,false,false)),5,10);
        ok(!noWrites.possibleMemoryStore() && !noWrites.unresolved(),
            "observed closed call graph without decoded STORE");
        // A root with many DISTINCT resolved callees must not enqueue
        // an unbounded frontier before the maxFunctions cap is checked.
        java.util.List<HardwareCallEffects.FunctionNode> wide=
            new java.util.ArrayList<>();
        java.util.List<Long> wideTargets=new java.util.ArrayList<>();
        for(int i=1;i<=12_000;i++) {
            wideTargets.add((long)i);
            wide.add(n(i,i==12_000,false,false));
        }
        wide.add(new HardwareCallEffects.FunctionNode(
            0,false,false,false,wideTargets));
        var cappedWide=HardwareCallEffects.summarize(0,wide,2,3);
        ok(cappedWide.visited()==3 && cappedWide.truncated() &&
            cappedWide.unresolved() && !cappedWide.possibleMemoryStore(),
            "12k unique CALL destinations must respect scheduled-node budget "
                +"and leave later STORE effect UNKNOWN");
        // 12k duplicate edges to one known leaf are only two unique nodes.
        var duplicate=HardwareCallEffects.summarize(0,List.of(
            new HardwareCallEffects.FunctionNode(0,false,false,false,
                java.util.Collections.nCopies(12_000,1L)),
            n(1,true,false,false)),2,2);
        ok(duplicate.visited()==2 && duplicate.possibleMemoryStore() &&
            !duplicate.truncated() && !duplicate.unresolved(),
            "duplicate fan-in does not trigger false cap");
        var missingWide=new java.util.ArrayList<Long>();
        for(int i=0;i<12000;i++)missingWide.add(0x100000L+i);
        var unknownFrontier=HardwareCallEffects.summarize(0,List.of(
            new HardwareCallEffects.FunctionNode(0,false,false,false,
                missingWide)),2,2);
        ok(unknownFrontier.visited()==1 && unknownFrontier.unresolved() &&
            !unknownFrontier.truncated(),
            "unresolved missing targets remain UNKNOWN without fake scheduled nodes");
        boolean invalidLimit=false;
        try {
            HardwareCallEffects.summarize(0,List.of(n(0,false,false,false)),
                2,HardwareCallEffects.MAX_REQUESTED_FUNCTIONS+1);
        } catch(IllegalArgumentException expected) {invalidLimit=true;}
        ok(invalidLimit,"reject unbounded requested call graph node budget");
        invalidLimit=false;
        try {
            HardwareCallEffects.summarize(-1,List.of(n(0,false,false,false)),2,2);
        } catch(IllegalArgumentException expected) {invalidLimit=true;}
        ok(invalidLimit,"reject negative CALL root");
        // Reject malformed source edges before graph traversal. A valid
        // nonnegative but unrecognized function remains UNKNOWN instead.
        boolean invalidCallee=false;
        try {
            n(0,false,false,false,-1L);
        } catch(IllegalArgumentException expected) {invalidCallee=true;}
        ok(invalidCallee,"negative direct CALL target rejected at source");
        invalidCallee=false;
        try {
            new HardwareCallEffects.FunctionNode(0,false,false,false,
                java.util.Arrays.asList(1L,null));
        } catch(IllegalArgumentException expected) {invalidCallee=true;}
        ok(invalidCallee,"null direct CALL target rejected consistently");
        invalidCallee=false;
        try {
            n(-1,false,false,false);
        } catch(IllegalArgumentException expected) {invalidCallee=true;}
        ok(invalidCallee,"negative function entry remains invalid");
        var unknownPositive=HardwareCallEffects.summarize(0,
            List.of(n(0,false,false,false,0x1000L)),2,10);
        ok(unknownPositive.unresolved() && !unknownPositive.truncated()
                && unknownPositive.visited()==1,
            "valid unresolved positive CALL target stays UNKNOWN");
        var immutableCallees=n(0,false,false,false,1L);
        boolean immutableSource=false;
        try {immutableCallees.directCallees().clear();}
        catch(UnsupportedOperationException expected){immutableSource=true;}
        ok(immutableSource,"validated source callee list remains immutable");
        // GA-01/11: the same original bounded solver now returns typed
        // shortest source-function routes without changing its old flags.
        var evidenced=HardwareCallEffects.inspect(0,graph,5,20);
        ok(evidenced.summary().equals(effects) &&
            evidenced.storeWitness().kind()==
                HardwareCallEffects.WitnessKind.MEMORY_STORE &&
            evidenced.storeWitness().chain().equals(List.of(0L,1L,3L)) &&
            evidenced.vbrWitness().kind()==
                HardwareCallEffects.WitnessKind.MOVEC_VBR &&
            evidenced.vbrWitness().chain().equals(List.of(0L,1L)) &&
            evidenced.observedUnknownWitness()==null &&
            evidenced.frontierWitness()==null,
            "STORE and MOVEC have explicit shortest function-only chains");
        var missingSource=HardwareCallEffects.inspect(0,
            List.of(n(0,false,false,false,5L)),5,10);
        ok(missingSource.summary().unresolved() &&
            !missingSource.summary().truncated() &&
            missingSource.observedUnknownWitness().kind()==
                HardwareCallEffects.WitnessKind.MISSING_TARGET &&
            missingSource.observedUnknownWitness().chain()
                .equals(List.of(0L,5L)) &&
            missingSource.frontierWitness()==null,
            "missing decoded callee is OBSERVED unknown, not an uninspected cap");
        var unknownNode=HardwareCallEffects.inspect(0,
            List.of(n(0,false,false,false,1L),
                    n(1,false,false,true)),5,10);
        ok(unknownNode.observedUnknownWitness().kind()==
                HardwareCallEffects.WitnessKind.UNKNOWN_FLOW &&
            unknownNode.observedUnknownWitness().chain().equals(List.of(0L,1L)),
            "unresolved modeled flow is tied to the actual examined function");
        var depthEvidence=HardwareCallEffects.inspect(0,
            List.of(n(0,false,false,false,1L),
                    n(1,false,false,false,2L),
                    n(2,true,false,false)),1,10);
        ok(depthEvidence.summary().truncated() &&
            !depthEvidence.summary().possibleMemoryStore() &&
            depthEvidence.observedUnknownWitness()==null &&
            depthEvidence.frontierWitness().kind()==
                HardwareCallEffects.WitnessKind.DEPTH_CUTOFF &&
            depthEvidence.frontierWitness().chain()
                .equals(List.of(0L,1L,2L)),
            "late STORE is uninspected, not an observed negative");
        var nodeEvidence=HardwareCallEffects.inspect(0,
            List.of(n(0,false,false,false,1L,2L),
                    n(1,false,false,false),
                    n(2,true,false,false)),5,2);
        ok(nodeEvidence.frontierWitness().kind()==
                HardwareCallEffects.WitnessKind.NODE_CUTOFF &&
            nodeEvidence.frontierWitness().chain().equals(List.of(0L,2L)) &&
            !nodeEvidence.summary().possibleMemoryStore(),
            "queued source limit explicitly retains skipped STORE frontier");
        var longEvidence=HardwareCallEffects.inspect(0,longChain,1500,1600);
        ok(longEvidence.summary().equals(deep) &&
            longEvidence.storeWitness().chain().size()==1500 &&
            longEvidence.storeWitness().chain().get(0)==0L &&
            longEvidence.storeWitness().chain().get(1499)==1499L,
            "long source paths remain source-bounded and nonrecursive");
        var dualGraph=List.of(
            n(0,false,false,false,1L,3L),
            n(1,false,false,false,2L),
            n(2,false,false,false,4L),
            n(3,false,false,true),
            n(4,false,false,false,6L),
            n(6,true,false,false));
        var dual=HardwareCallEffects.inspect(0,dualGraph,2,10);
        ok(dual.summary().unresolved() && dual.summary().truncated() &&
            dual.observedUnknownWitness().chain().equals(List.of(0L,3L)) &&
            dual.observedUnknownWitness().kind()==
                HardwareCallEffects.WitnessKind.UNKNOWN_FLOW &&
            dual.frontierWitness().chain().equals(List.of(0L,1L,2L,4L)),
            "actual UNKNOWN is separate from an uninspected later MM frontier");
        var dualReversed=new java.util.ArrayList<>(dualGraph);
        java.util.Collections.reverse(dualReversed);
        ok(dual.equals(HardwareCallEffects.inspect(0,dualReversed,2,10)),
            "canonical typed paths independent of function inventory ordering");
        var onlyCycle=HardwareCallEffects.inspect(0,List.of(
            n(0,false,false,false,1L),
            n(1,false,false,false,0L)),5,10);
        ok(onlyCycle.summary().recursive() &&
            onlyCycle.observedUnknownWitness()==null &&
            onlyCycle.frontierWitness()==null,
            "cycle uncertainty does not invent a missing/cutoff source path");
        boolean wrongRoot=false;
        try {
            new HardwareCallEffects.Detailed(0,evidenced.summary(),
                new HardwareCallEffects.SourceWitness(
                    HardwareCallEffects.WitnessKind.MEMORY_STORE,List.of(1L)),
                null,null,null);
        }catch(IllegalArgumentException expected){wrongRoot=true;}
        ok(wrongRoot,"foreign-root source proof cannot enter vector correlation");
        boolean wrongKind=false;
        try {
            new HardwareCallEffects.Detailed(0,evidenced.summary(),
                new HardwareCallEffects.SourceWitness(
                    HardwareCallEffects.WitnessKind.MOVEC_VBR,List.of(0L)),
                null,null,null);
        }catch(IllegalArgumentException expected){wrongKind=true;}
        ok(wrongKind,"contradictory source category cannot masquerade as STORE");
        System.out.println("HardwareCallEffectsSelfTest OK");
    }
}
