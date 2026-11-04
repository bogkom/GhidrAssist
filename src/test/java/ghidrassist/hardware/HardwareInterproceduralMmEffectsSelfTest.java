package ghidrassist.hardware;

import java.util.List;

public final class HardwareInterproceduralMmEffectsSelfTest {
    private HardwareInterproceduralMmEffectsSelfTest(){}
    private static void ok(boolean b,String why){if(!b)throw new AssertionError(why);}
    private static HardwareInterproceduralMmEffects.FunctionNode node(
            long id,boolean mm,boolean alias,boolean unknown,Long... calls){
        return new HardwareInterproceduralMmEffects.FunctionNode(
            id,mm,alias,unknown,List.of(calls));
    }
    private static HardwareInterproceduralMmEffects.CallSite call(
            long caller,long pc,Long callee){
        return new HardwareInterproceduralMmEffects.CallSite(caller,pc,callee);
    }
    private static HardwareInterproceduralMmEffects.Report run(
            List<HardwareInterproceduralMmEffects.FunctionNode> graph,
            List<HardwareInterproceduralMmEffects.CallSite> sites,
            int depth,int count,int maxRows){
        return HardwareInterproceduralMmEffects.analyze(
            graph,sites,List.of(0x100L),depth,count,maxRows);
    }
    public static void main(String[] ignored){
        var diamond=List.of(
            node(0x100,false,false,false,0x130L,0x160L),
            node(0x130,false,false,false,0x190L),
            node(0x160,false,false,false,0x190L),
            node(0x190,true,false,false));
        var calls=List.of(call(0x100,0x108,0x130L),
            call(0x100,0x110,0x160L));
        var evidence=run(diamond,calls,4,20,20);
        ok(evidence.rows().size()==2 &&
            evidence.rows().get(0).summary().mayMm() &&
            evidence.rows().get(0).summary().visited()==2 &&
            !evidence.rows().get(0).summary().cycle() &&
            !evidence.rows().get(0).summary().unknownControl(),
            "convergent static CALL paths expose shared may-MM site");
        ok(evidence.markdown().contains("NOT execution") &&
            evidence.markdown().contains("latched MM"),
            "no runtime/latched-MM inference");
        var missing=run(List.of(node(0x100,false,false,false)),
            List.of(calls.get(0)),4,20,20);
        ok(missing.rows().get(0).summary().unknownControl(),
            "missing callee must not be interpreted as pure");
        var alias=run(List.of(node(0x130,false,true,false)),
            List.of(calls.get(0)),4,20,20);
        ok(alias.rows().get(0).summary().unknownAlias() &&
            alias.rows().get(0).summary().uncertainOrMm(),
            "unknown effective STORE address may alias SIMCR");
        ok(HardwareInterproceduralMmEffects.unknownMemoryWrite(
                0xfffa00L,0) &&
            HardwareInterproceduralMmEffects.unknownMemoryWrite(
                0xfff9feL,64) &&
            HardwareInterproceduralMmEffects.unknownMemoryWrite(null,16) &&
            !HardwareInterproceduralMmEffects.unknownMemoryWrite(0xfffa00L,8) &&
            !HardwareInterproceduralMmEffects.unknownMemoryWrite(0xfffa00L,16) &&
            !HardwareInterproceduralMmEffects.unknownMemoryWrite(0xfffa00L,32),
            "known destination with unmodeled P-code STORE width must not be"
                +"classified as harmless to SIMCR");
        var unknownWidth=run(List.of(node(0x130,false,
            HardwareInterproceduralMmEffects.unknownMemoryWrite(
                0xfffa00L,0),false)),List.of(calls.get(0)),4,20,20);
        ok(unknownWidth.rows().get(0).summary().unknownAlias() &&
            unknownWidth.rows().get(0).summary().uncertainOrMm(),
            "unmodeled-width direct callee STORE cannot prove no MM effects");
        var indirect=run(diamond,List.of(call(0x100,0x108,null)),4,20,20);
        ok(indirect.rows().get(0).summary().unknownControl(),
            "indirect unresolved CALL remains unknown");
        var cycle=run(List.of(node(0x130,false,false,false,0x160L),
            node(0x160,false,false,false,0x130L)),
            List.of(calls.get(0)),4,20,20);
        ok(cycle.rows().get(0).summary().cycle() &&
            cycle.rows().get(0).summary().unknownControl(),
            "cyclic call graph not classified closed");
        var depth=run(diamond,List.of(calls.get(0)),0,20,20);
        ok(depth.rows().get(0).summary().limited() &&
            !depth.rows().get(0).summary().mayMm() &&
            depth.rows().get(0).summary().uncertainOrMm(),
            "depth budget must prevent negative effect claims");
        ok(run(diamond,List.of(calls.get(0)),4,1,20)
            .rows().get(0).summary().limited(),"node cap explicit");
        var closed=run(List.of(node(0x130,false,false,false)),
            List.of(calls.get(0)),4,20,20);
        ok(!closed.rows().get(0).summary().uncertainOrMm(),
            "closed modeled callee has no observed MM source");
        var capped=run(diamond,calls,4,20,1);
        ok(capped.rows().size()==1 && capped.omitted()==1,
            "row cap reports omitted call sites");
        boolean fail=false;
        try{call(0x100,0x108,-1L);}
        catch(IllegalArgumentException expected){fail=true;}
        ok(fail,"reject negative target");
        fail=false;
        try{run(List.of(node(0x130,false,false,false),
            node(0x130,false,false,false)),List.of(calls.get(0)),4,20,20);}
        catch(IllegalArgumentException expected){fail=true;}
        ok(fail,"reject duplicate functions");
        // More than a few thousand nodes can all be reachable in one
        // BFS step (root fan-out), yet form a much deeper DFS cross-edge
        // chain. Recursive cycle detection can overflow the Java stack.
        final int fanout=6500;
        long first=0x2000L;
        var edges=new java.util.ArrayList<Long>();
        var graph=new java.util.ArrayList<
            HardwareInterproceduralMmEffects.FunctionNode>();
        for(int i=0;i<fanout;i++){
            long entry=first+2L*i;
            edges.add(entry);
            graph.add(node(entry,i==fanout-1,false,false,
                i==fanout-1?new Long[]{}:new Long[]{entry+2L}));
        }
        graph.add(new HardwareInterproceduralMmEffects.FunctionNode(
            0x130L,false,false,false,edges));
        var wide=run(graph,List.of(calls.get(0)),2,fanout+1,20)
            .rows().get(0).summary();
        ok(wide.visited()==fanout+1 && wide.mayMm() &&
            !wide.cycle() && !wide.limited() &&
            !wide.unknownControl(),
            "iterative cycle audit handles 6500-node shallow-BFS/deep-DFS DAG");
        // Introduce the back edge only in a fresh synthetic graph.
        var withCycle=new java.util.ArrayList<>(graph);
        withCycle.set(fanout-1,node(first+2L*(fanout-1),
            true,false,false,first));
        var cyclic=run(withCycle,List.of(calls.get(0)),2,
            fanout+1,20).rows().get(0).summary();
        ok(cyclic.visited()==fanout+1 && cyclic.mayMm() &&
            cyclic.cycle() && cyclic.unknownControl() &&
            !cyclic.limited(),
            "iterative DFS must still find long true call cycles");
        var truncated=run(graph,List.of(calls.get(0)),2,5,20)
            .rows().get(0).summary();
        ok(truncated.visited()==5 && !truncated.mayMm() &&
            truncated.limited() && truncated.unknownControl() &&
            truncated.uncertainOrMm(),
            "capped BFS cannot claim absence of MM in unvisited function");
        // Previously a many-to-one fan-in could enqueue thousands of
        // duplicate work records despite a maxCount of just two nodes.
        var duplicateTargets=new HardwareInterproceduralMmEffects
            .FunctionNode(0x130L,false,false,false,
                java.util.Collections.nCopies(12000,0x160L));
        var duplicateSafe=run(List.of(duplicateTargets,
                node(0x160,true,false,false)),
            List.of(calls.get(0)),2,2,20).rows().get(0).summary();
        ok(duplicateSafe.visited()==2 && duplicateSafe.mayMm() &&
            !duplicateSafe.limited() && !duplicateSafe.cycle(),
            "repeated same callee must not consume unique BFS work cap");
        var missingTargets=new java.util.ArrayList<Long>();
        for(int i=0;i<12000;i++)missingTargets.add(0x100000L+i);
        var missingWide=run(List.of(new HardwareInterproceduralMmEffects
                .FunctionNode(0x130L,false,false,false,missingTargets)),
            List.of(calls.get(0)),2,3,20).rows().get(0).summary();
        ok(missingWide.visited()==1 && !missingWide.mayMm() &&
            missingWide.limited() && missingWide.unknownControl(),
            "unseen/unknown fan-out is explicitly incomplete under node cap");
        System.out.println("HardwareInterproceduralMmEffectsSelfTest OK");
    }
}
