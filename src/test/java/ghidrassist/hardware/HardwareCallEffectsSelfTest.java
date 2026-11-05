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
        System.out.println("HardwareCallEffectsSelfTest OK");
    }
}
