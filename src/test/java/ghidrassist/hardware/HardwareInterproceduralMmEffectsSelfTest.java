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
        ok(evidence.rows().get(0).summary().mmWitness().chain()
                .equals(List.of(0x130L,0x190L)) &&
            evidence.rows().get(1).summary().mmWitness().chain()
                .equals(List.of(0x160L,0x190L)) &&
            evidence.markdown().contains("MM source chain=MM_SOURCE:0x00000130 -> 0x00000190"),
            "convergent CALL candidates expose bounded shortest witness chains");
        // A capped batch must not privilege whichever Ghidra reference
        // happened to be enumerated first. One branch includes a possible
        // SIMCR/MM STORE; the other is a closed source leaf. Both input
        // orders produce the SAME bounded MAY result and uncertainty.
        var lowFirst=node(0x130,false,false,false,0x160L,0x400L);
        var highFirst=node(0x130,false,false,false,0x400L,0x160L);
        var orderGraph=List.of(lowFirst,
            node(0x160,true,false,false),
            node(0x400,false,false,false));
        var reverseGraph=List.of(highFirst,
            node(0x400,false,false,false),
            node(0x160,true,false,false));
        ok(lowFirst.calls().equals(highFirst.calls()) &&
            lowFirst.calls().equals(List.of(0x160L,0x400L)),
            "One stable numeric CALL target inventory regardless of source enumeration");
        var sourceCall=List.of(call(0x100,0x108,0x130L));
        var boundedA=run(orderGraph,sourceCall,3,2,5);
        var boundedB=run(reverseGraph,sourceCall,3,2,5);
        ok(boundedA.equals(boundedB) &&
            boundedA.rows().get(0).summary().visited()==2 &&
            boundedA.rows().get(0).summary().mayMm() &&
            boundedA.rows().get(0).summary().limited() &&
            boundedA.rows().get(0).summary().unknownControl(),
            "Limited BFS preserves deterministic positive MAY and explicit unknown horizon");
        ok(run(orderGraph,sourceCall,3,3,5).equals(
                run(reverseGraph,sourceCall,3,3,5)) &&
            !run(orderGraph,sourceCall,3,3,5)
                .rows().get(0).summary().limited(),
            "Closed full-budget interprocedural evidence remains order independent");
        var duplicateSourceGraph=List.of(new HardwareInterproceduralMmEffects.FunctionNode(
            0x130L,false,false,false,List.of(0x400L,0x160L,0x160L)),
            node(0x160,true,false,false),
            node(0x400,false,false,false));
        ok(run(duplicateSourceGraph,sourceCall,3,2,5).rows().get(0).summary()
                .equals(boundedA.rows().get(0).summary()),
            "Repeated CALL target does not consume additional distinct-node budget");
        // An omitted MM leaf remains UNKNOWN, not a negative closed proof:
        // sorted address priority is only reproducibility, not execution.
        var highMm=run(List.of(
            node(0x130,false,false,false,0x400L,0x160L),
            node(0x160,false,false,false),
            node(0x400,true,false,false)),sourceCall,3,2,5);
        ok(!highMm.rows().get(0).summary().mayMm() &&
            highMm.rows().get(0).summary().mmWitness()==null &&
            highMm.rows().get(0).summary().unknownWitness().kind()==
                HardwareInterproceduralMmEffects.WitnessKind.NODE_CUTOFF &&
            highMm.rows().get(0).summary().unknownWitness().chain()
                .equals(List.of(0x130L,0x400L)) &&
            highMm.rows().get(0).summary().limited() &&
            highMm.rows().get(0).summary().uncertainOrMm(),
            "Skipped later MM candidate retains UNKNOWN/LIMITED, not absence of MM");

        var missing=run(List.of(node(0x100,false,false,false)),
            List.of(calls.get(0)),4,20,20);
        ok(missing.rows().get(0).summary().unknownControl() &&
            missing.rows().get(0).summary().unknownWitness().kind()==
                HardwareInterproceduralMmEffects.WitnessKind.MISSING_TARGET &&
            missing.rows().get(0).summary().unknownWitness().chain()
                .equals(List.of(0x130L)),
            "missing callee must not be interpreted as pure");
        var alias=run(List.of(node(0x130,false,true,false)),
            List.of(calls.get(0)),4,20,20);
        ok(alias.rows().get(0).summary().unknownAlias() &&
            alias.rows().get(0).summary().aliasWitness().kind()==
                HardwareInterproceduralMmEffects.WitnessKind.STORE_ALIAS &&
            alias.rows().get(0).summary().aliasWitness().chain()
                .equals(List.of(0x130L)) &&
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
        ok(indirect.rows().get(0).summary().unknownControl() &&
            indirect.rows().get(0).summary().unknownWitness()==null,
            "unresolved CALL has no invented callee source chain");
        var cycle=run(List.of(node(0x130,false,false,false,0x160L),
            node(0x160,false,false,false,0x130L)),
            List.of(calls.get(0)),4,20,20);
        ok(cycle.rows().get(0).summary().cycle() &&
            cycle.rows().get(0).summary().unknownControl(),
            "cyclic call graph not classified closed");
        var depth=run(diamond,List.of(calls.get(0)),0,20,20);
        ok(depth.rows().get(0).summary().limited() &&
            !depth.rows().get(0).summary().mayMm() &&
            depth.rows().get(0).summary().unknownWitness().kind()==
                HardwareInterproceduralMmEffects.WitnessKind.DEPTH_CUTOFF &&
            depth.rows().get(0).summary().unknownWitness().chain()
                .equals(List.of(0x130L,0x190L)) &&
            depth.rows().get(0).summary().uncertainOrMm(),
            "depth budget must prevent negative effect claims");
        ok(run(diamond,List.of(calls.get(0)),4,1,20)
            .rows().get(0).summary().limited(),"node cap explicit");
        // A depth frontier is first discovered at the earlier 0x160
        // sibling, but the later 0x190 function contains directly observed
        // unresolved control flow at a SHORTER source distance. Preserve
        // the frontier independently instead of hiding the observation.
        var mixedGraph=List.of(
            node(0x130,false,false,false,0x190L,0x160L),
            node(0x160,false,false,false,0x300L),
            node(0x190,false,false,true),
            node(0x300,true,false,false));
        var mixed=run(mixedGraph,sourceCall,1,20,20)
            .rows().get(0).summary();
        ok(mixed.unknownWitness().kind()==
                HardwareInterproceduralMmEffects.WitnessKind.UNKNOWN_FLOW &&
            mixed.unknownWitness().chain().equals(List.of(0x130L,0x190L)) &&
            mixed.frontierWitness().kind()==
                HardwareInterproceduralMmEffects.WitnessKind.DEPTH_CUTOFF &&
            mixed.frontierWitness().chain().equals(
                List.of(0x130L,0x160L,0x300L)) &&
            mixed.unknownControl() && mixed.limited() && !mixed.mayMm(),
            "observed UNKNOWN at shallower distance and omitted MM frontier both survive");
        var mixedReordered=run(List.of(mixedGraph.get(2),
                node(0x130,false,false,false,0x160L,0x190L),
                mixedGraph.get(3),mixedGraph.get(1)),sourceCall,1,20,20);
        ok(mixedReordered.rows().get(0).summary().equals(mixed) &&
            mixedReordered.markdown().contains("uninspected frontier chain=") &&
            mixedReordered.markdown().contains("UNKNOWN_FLOW:"),
            "dual source witnesses deterministic across enumeration order and rendered");
        var missingSibling=run(List.of(
                node(0x130,false,false,false,0x190L,0x160L),
                node(0x160,false,false,false,0x300L)),
            sourceCall,1,20,20).rows().get(0).summary();
        ok(missingSibling.unknownWitness().kind()==
                HardwareInterproceduralMmEffects.WitnessKind.MISSING_TARGET &&
            missingSibling.unknownWitness().chain().equals(
                List.of(0x130L,0x190L)) &&
            missingSibling.frontierWitness().chain().equals(
                List.of(0x130L,0x160L,0x300L)),
            "missing target is an observed absence, never confused with unvisited cutoff");
        var nodeFrontier=run(List.of(
                node(0x130,false,false,false,0x190L,0x160L),
                node(0x160,false,false,true),
                node(0x190,true,false,false)),
            sourceCall,2,2,20).rows().get(0).summary();
        ok(nodeFrontier.unknownWitness().kind()==
                HardwareInterproceduralMmEffects.WitnessKind.UNKNOWN_FLOW &&
            nodeFrontier.frontierWitness().kind()==
                HardwareInterproceduralMmEffects.WitnessKind.NODE_CUTOFF &&
            nodeFrontier.frontierWitness().chain().equals(
                List.of(0x130L,0x190L)) &&
            !nodeFrontier.mayMm() && nodeFrontier.limited(),
            "node cap does not suppress visited unknown or invent omitted MM STORE");
        ok(depth.rows().get(0).summary().frontierWitness()!=null &&
            depth.rows().get(0).summary().frontierWitness()
                .equals(depth.rows().get(0).summary().unknownWitness()),
            "legacy cutoff-only unknown witness remains compatible");
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
        // One analysis run must cap total queued targets across distinct
        // call sites, not merely each CALL's own maxCount allowance.
        // Unknown targets consume the same budget as decoded targets.
        int half=HardwareInterproceduralMmEffects.MAX_BATCH_SCHEDULED/2;
        var unknownA=new java.util.ArrayList<Long>();
        var unknownB=new java.util.ArrayList<Long>();
        for(int i=0;i<half-1;i++){
            unknownA.add(0x10000L+i);
            unknownB.add(0x20000L+i);
        }
        var batchGraph=List.of(
            new HardwareInterproceduralMmEffects.FunctionNode(
                0x130L,false,false,false,unknownA),
            new HardwareInterproceduralMmEffects.FunctionNode(
                0x160L,false,false,false,unknownB),
            node(0x190,true,false,false));
        var batchCalls=List.of(
            call(0x100,0x108,0x130L),
            call(0x100,0x110,0x160L),
            call(0x100,0x118,0x190L),
            call(0x100,0x120,0x130L));
        var batch=run(batchGraph,batchCalls,2,10000,20);
        ok(batch.rows().size()==4 && batch.omitted()==0,
            "aggregate-budget regression reports every selected CALL PC");
        var before=batch.rows().get(0).summary();
        var second=batch.rows().get(1).summary();
        var after=batch.rows().get(2).summary();
        var repeated=batch.rows().get(3).summary();
        ok(before.visited()==1 && before.unknownControl() &&
            !before.limited() && second.visited()==1 &&
            second.unknownControl() && !second.limited(),
            "first two distinct roots fully inspect unresolved targets");
        ok(after.visited()==0 && !after.mayMm() &&
            after.mmWitness()==null &&
            after.unknownWitness().kind()==
                HardwareInterproceduralMmEffects.WitnessKind.BATCH_CUTOFF &&
            after.unknownWitness().chain().equals(List.of(0x190L)) &&
            after.limited() && after.unknownControl() &&
            after.uncertainOrMm(),
            "exhaustion before known MM leaf must be explicit UNKNOWN/LIMITED");
        ok(before.equals(repeated),
            "repeated exact CALL target reuses its original evidence under exhaustion");
        ok(batch.markdown().contains("cap=true") &&
            batch.markdown().contains("unknown callee/flow=true"),
            "batch truncation is visible in rendered evidence");
        var reordered=new java.util.ArrayList<>(batchCalls);
        java.util.Collections.reverse(reordered);
        ok(run(batchGraph,reordered,2,10000,20).equals(batch),
            "batch analysis is deterministic regardless of callsite input order");
        var ties=run(List.of(node(0x130,false,false,false),
                node(0x160,true,false,false)),
            List.of(call(0x100,0x108,0x160L),
                call(0x100,0x108,0x130L)),2,20,20);
        ok(ties.rows().get(0).call().target()==0x130L &&
            ties.rows().get(1).call().target()==0x160L,
            "equal caller PCs sort deterministically by target");
        fail=false;
        try {
            HardwareInterproceduralMmEffects.analyze(
                List.of(node(0x130,false,false,false)),
                List.of(calls.get(0)), java.util.Arrays.asList((Long)null),
                2,20,20);
        } catch(IllegalArgumentException expected){fail=true;}
        ok(fail,"null interesting caller is rejected even in mutable lists");
        fail=false;
        try {
            HardwareInterproceduralMmEffects.analyze(
                List.of(node(0x130,false,false,false)),
                List.of(calls.get(0)), List.of(-1L),2,20,20);
        } catch(IllegalArgumentException expected){fail=true;}
        ok(fail,"negative interesting caller is rejected");
        // Allocation order must respect explicitly selected callers.
        // With 16,384 earlier unrelated closed CALL targets, the one
        // later interesting source used to be classified UNKNOWN/LIMITED
        // solely because the shared budget was already exhausted.
        var uninterestingGraph=new java.util.ArrayList<
            HardwareInterproceduralMmEffects.FunctionNode>();
        var uninterestingCalls=new java.util.ArrayList<
            HardwareInterproceduralMmEffects.CallSite>();
        for(int i=0;i<HardwareInterproceduralMmEffects.MAX_BATCH_SCHEDULED;i++){
            long entry=0x40000L+i;
            uninterestingGraph.add(node(entry,false,false,false));
            uninterestingCalls.add(call(0x1L,0x10000L+i,entry));
        }
        uninterestingGraph.add(node(0x130L,true,false,false));
        var selectedSite=call(0x9000L,0x9001L,0x130L);
        uninterestingCalls.add(selectedSite);
        var prioritized=HardwareInterproceduralMmEffects.analyze(
            uninterestingGraph,uninterestingCalls,List.of(0x9000L),
            0,1,1);
        ok(prioritized.rows().size()==1 &&
            prioritized.rows().get(0).call().equals(selectedSite) &&
            prioritized.rows().get(0).summary().mayMm() &&
            prioritized.rows().get(0).summary().visited()==1 &&
            !prioritized.rows().get(0).summary().limited() &&
            prioritized.omitted()==1,
            "selected late SIMCR/MM candidate retains analysis AND report row "
                +"when 16k unrelated earlier sources exhaust finite budget");
        var reversedCalls=new java.util.ArrayList<>(uninterestingCalls);
        java.util.Collections.reverse(reversedCalls);
        ok(HardwareInterproceduralMmEffects.analyze(
                uninterestingGraph,reversedCalls,List.of(0x9000L),
                0,1,1).equals(prioritized),
            "selected priority result deterministic across reversed CALL inputs");
        // Even a valid source graph count may hide an unbounded edge set.
        var tooManyEdges=List.of(new HardwareInterproceduralMmEffects.FunctionNode(
            0x130L,false,false,false,
            java.util.Collections.nCopies(
                HardwareInterproceduralMmEffects.MAX_FUNCTION_EDGES+1,0x160L)));
        fail=false;
        try {
            HardwareInterproceduralMmEffects.analyze(tooManyEdges,
                List.of(calls.get(0)),List.of(0x100L),2,20,20);
        }catch(IllegalArgumentException expected){fail=true;}
        ok(fail,"oversized direct-call adjacency list rejected before traversal");
        ok(prioritized.markdown().contains("Selected source callers receive") &&
            prioritized.markdown().contains("UNKNOWN"),
            "human-facing evidence declares priority, incomplete horizon and scope");
        // Equal-distance witnesses must use canonical CALL target order,
        // not input enumeration order or source Listing reference order.
        var diamondSource=node(0x130L,false,false,false,0x500L,0x200L);
        var reversedSource=node(0x130L,false,false,false,0x200L,0x500L);
        var witnessNodes=List.of(node(0x500L,true,true,false),
            node(0x200L,true,false,true));
        var witnessA=run(List.of(diamondSource,witnessNodes.get(0),
                witnessNodes.get(1)),sourceCall,3,3,10);
        var witnessB=run(List.of(witnessNodes.get(1),reversedSource,
                witnessNodes.get(0)),sourceCall,3,3,10);
        ok(witnessA.equals(witnessB) &&
            witnessA.rows().get(0).summary().mmWitness().chain()
                .equals(List.of(0x130L,0x200L)) &&
            witnessA.rows().get(0).summary().aliasWitness().chain()
                .equals(List.of(0x130L,0x500L)) &&
            witnessA.rows().get(0).summary().unknownWitness().chain()
                .equals(List.of(0x130L,0x200L)),
            "stable independent MM, alias and unknown-flow source witnesses");
        ok(cycle.rows().get(0).summary().cycle() &&
            cycle.rows().get(0).summary().unknownWitness()==null,
            "cycle-only uncertainty remains explicit, without a fake source witness");
        boolean invalid=false;
        try {
            new HardwareInterproceduralMmEffects.SourceWitness(
                HardwareInterproceduralMmEffects.WitnessKind.MM_SOURCE,
                List.of(-1L));
        }catch(IllegalArgumentException expected){invalid=true;}
        ok(invalid,"invalid witness addresses rejected");
        invalid=false;
        try {
            new HardwareInterproceduralMmEffects.Summary(
                false,false,false,false,false,1,
                new HardwareInterproceduralMmEffects.SourceWitness(
                    HardwareInterproceduralMmEffects.WitnessKind.MM_SOURCE,
                    List.of(0x130L)),null,null);
        }catch(IllegalArgumentException expected){invalid=true;}
        ok(invalid,"typed false MM sources cannot carry a positive MM witness");
        invalid=false;
        try {
            new HardwareInterproceduralMmEffects.Summary(
                false,false,true,false,true,1,null,null,
                new HardwareInterproceduralMmEffects.SourceWitness(
                    HardwareInterproceduralMmEffects.WitnessKind.UNKNOWN_FLOW,
                    List.of(0x130L)),
                new HardwareInterproceduralMmEffects.SourceWitness(
                    HardwareInterproceduralMmEffects.WitnessKind.UNKNOWN_FLOW,
                    List.of(0x130L)));
        }catch(IllegalArgumentException expected){invalid=true;}
        ok(invalid,"observed source may not impersonate uninspected frontier");
        invalid=false;
        try {
            new HardwareInterproceduralMmEffects.Summary(
                false,false,true,false,false,1,null,null,null,
                new HardwareInterproceduralMmEffects.SourceWitness(
                    HardwareInterproceduralMmEffects.WitnessKind.NODE_CUTOFF,
                    List.of(0x130L)));
        }catch(IllegalArgumentException expected){invalid=true;}
        ok(invalid,"cutoff cannot be reported with closed/unlimited summary");
        ok(!closed.rows().get(0).summary().uncertainOrMm() &&
            closed.rows().get(0).summary().mmWitness()==null &&
            closed.rows().get(0).summary().aliasWitness()==null &&
            closed.rows().get(0).summary().unknownWitness()==null,
            "closed observed leaf has no source-witness chain");
        System.out.println("HardwareInterproceduralMmEffectsSelfTest OK");
    }
}
