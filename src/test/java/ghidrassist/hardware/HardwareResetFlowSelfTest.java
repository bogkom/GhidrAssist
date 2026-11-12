package ghidrassist.hardware;

import java.util.List;
import java.util.Set;

public final class HardwareResetFlowSelfTest {
    private static void ok(boolean value,String why){
        if(!value)throw new AssertionError(why);
    }
    private static HardwareCallEffects.FunctionNode fn(long entry,boolean store,
            boolean vbr,boolean unknown,Long... calls){
        return new HardwareCallEffects.FunctionNode(entry,store,vbr,unknown,List.of(calls));
    }
    public static void main(String[] args){
        byte[] ecu={0x00,(byte)0xff,(byte)0xf7,(byte)0xfc,
                    0x00,0x00,0x2b,(byte)0xc0};
        var v=HardwareResetFlow.readVector(ecu);
        ok(v.valid() && v.initialSp()==0x00fff7fcL && v.resetPc()==0x2bc0L,
            "read initial SP and reset PC as unsigned big-endian words");
        ok(!HardwareResetFlow.readVector(null).valid() &&
           !HardwareResetFlow.readVector(new byte[]{1,2}).valid(),
            "short/unreadable reset vectors must be UNKNOWN");
        ok(!HardwareResetFlow.readVector(new byte[8]).valid(),
            "zero reset PC is not a valid candidate");
        byte[] odd=ecu.clone();odd[7]=(byte)0xc1;
        ok(!HardwareResetFlow.readVector(odd).valid(),
            "odd reset PC must be rejected");
        byte[] erased=new byte[8];java.util.Arrays.fill(erased,(byte)0xff);
        ok(!HardwareResetFlow.readVector(erased).valid(),
            "erased reset PC cannot masquerade as reset handler");
        // Selected MC68332 is a 24-bit source-image address scope;
        // generic CPU32 remains a 32-bit source survey. A high-PC
        // Ghidra function must NOT become a fabricated device RESET root.
        byte[] upperPc=ecu.clone();
        upperPc[4]=0x01;
        var high=HardwareResetFlow.readVector(upperPc);
        ok(high.valid() && high.resetPc()==0x01002bc0L &&
            HardwareResetFlow.sourceResetPcEligible(high,false) &&
            !HardwareResetFlow.sourceResetPcEligible(high,true),
            "MC68332-only 24-bit source gate preserves generic CPU32 survey");
        ok(HardwareResetFlow.sourceResetPcEligible(v,true) &&
            HardwareResetFlow.sourceResetPcEligible(v,false) &&
            !HardwareResetFlow.sourceResetPcEligible(
                HardwareResetFlow.readVector(odd),true) &&
            !HardwareResetFlow.sourceResetPcEligible(null,true),
            "normal selected 24-bit RESET still eligible, malformed PC not");
        var top=HardwareResetFlow.InitialStackEvidence
            .ONE_PAST_MCU24_TOP_CANDIDATE;
        var aligned=HardwareResetFlow.InitialStackEvidence
            .ALIGNED_BUT_MEMORY_UNVERIFIED;
        var nullSp=HardwareResetFlow.InitialStackEvidence
            .NULL_OR_ERASED_SOURCE;
        var oddSp=HardwareResetFlow.InitialStackEvidence
            .ODD_WORD_ACCESS_RISK;
        var outside=HardwareResetFlow.InitialStackEvidence
            .OUTSIDE_SELECTED_MCU24_CONTEXT;
        ok(HardwareResetFlow.inspectInitialStack(0x00fff7fcL,true)==aligned &&
            HardwareResetFlow.inspectInitialStack(0x00fff7fcL,false)==aligned,
            "realistic even image-zero SSP is only source-aligned, never RAM proof");
        ok(HardwareResetFlow.inspectInitialStack(0,true)==nullSp &&
            HardwareResetFlow.inspectInitialStack(0xffffffffL,true)==nullSp &&
            HardwareResetFlow.inspectInitialStack(0x00001001L,false)==oddSp,
            "zero, erased and odd SSP warnings do not assert executed RESET");
        ok(HardwareResetFlow.inspectInitialStack(0x01000000L,true)==top &&
            HardwareResetFlow.inspectInitialStack(0x01000000L,false)==aligned &&
            HardwareResetFlow.inspectInitialStack(0x02000000L,true)==outside &&
            HardwareResetFlow.inspectInitialStack(0x02000000L,false)==aligned,
            "one-past 24-bit stack top is distinct from invalid PC or wide CPU32");
        byte[] oddStack=ecu.clone();
        oddStack[3]=(byte)0xfd;
        ok(HardwareResetFlow.readVector(oddStack).valid() &&
            HardwareResetFlow.sourceResetPcEligible(
                HardwareResetFlow.readVector(oddStack),true) &&
            HardwareResetFlow.inspectInitialStack(
                HardwareResetFlow.readVector(oddStack).initialSp(),true)==oddSp,
            "odd SSP is a warning; source-valid RESET PC stays separately eligible");
        boolean badStack=false;
        try{HardwareResetFlow.inspectInitialStack(0x100000000L,true);}
        catch(IllegalArgumentException expected){badStack=true;}
        ok(badStack,"SP words beyond unsigned 32-bit rejected");

        // A reset vector pointing inside an existing function cannot
        // borrow the function's earlier JSR/BSR prefix. Otherwise the
        // unexecuted prefix could fabricate reachable MMIO/ISR sites.
        ok(HardwareResetFlow.exactFunctionEntry(0x400L,0x400L) &&
            !HardwareResetFlow.exactFunctionEntry(0x402L,0x400L) &&
            !HardwareResetFlow.exactFunctionEntry(0x400L,0x402L) &&
            !HardwareResetFlow.exactFunctionEntry(0x403L,0x403L) &&
            !HardwareResetFlow.exactFunctionEntry(-1L,-1L) &&
            !HardwareResetFlow.exactFunctionEntry(0x100000000L,0x100000000L),
            "only a valid exact function entry may root RESET CALL evidence");
        var prefixCalls=List.of(
            fn(0x400,false,false,false,0x500L),
            fn(0x500,true,true,false));
        var wronglyRounded=HardwareResetFlow.trace(0x400,prefixCalls,
            List.of(0x500L),6,128,30);
        ok(wronglyRounded.rootRecognized() &&
            wronglyRounded.visitedEntries().contains(0x500L),
            "regression fixture demonstrates false reachable STORE/VBR "+
            "when interior RESET is rounded back to function entry");
        ok(!HardwareResetFlow.exactFunctionEntry(0x402L,0x400L),
            "the Ghidra service must refuse that rounded CALL prefix");

        // A reset function can branch at runtime, so a static graph does NOT
        // establish execution, nor that one numeric address precedes another.
        var calls=List.of(
            fn(0x2bc0,false,false,false,0x4000L,0x3000L),
            fn(0x4000,false,false,false,0x5000L),
            fn(0x3000,false,true,false,0x5000L),
            fn(0x5000,true,false,false)
        );
        var graph=HardwareResetFlow.trace(0x2bc0,calls,List.of(0x3000L,0x5000L),8,50,20);
        ok(graph.rootRecognized() && graph.visitedFunctions()==4 &&
            graph.evidence().size()==2 && !graph.unresolved() && !graph.recursive(),
            "bounded diamond calls must visit nodes once and retain matching evidence");
        ok(graph.evidence().get(0).chain().equals(
            "0x00002BC0 -> 0x00003000"),"one possible direct-call path is preserved");
        ok(graph.evidence().get(1).chain().equals(
            "0x00002BC0 -> 0x00003000 -> 0x00005000"),
            "canonical shortest source CALL chain is independent of reference order");
        var reversedGraph=HardwareResetFlow.trace(0x2bc0,List.of(
            fn(0x5000,true,false,false),
            fn(0x3000,false,true,false,0x5000L),
            fn(0x2bc0,false,false,false,0x3000L,0x4000L),
            fn(0x4000,false,false,false,0x5000L)),
            List.of(0x5000L,0x3000L),8,50,20);
        ok(graph.equals(reversedGraph) &&
            graph.evidence().get(1).chain().equals(
                reversedGraph.evidence().get(1).chain()),
            "RESET source evidence is stable across reversed CALL and node inventories");
        var cappedOrderA=HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,false,0x400L,0x100L),
            fn(0x400,false,false,false),
            fn(0x100,false,false,false)),List.of(0x400L),3,2,10);
        var cappedOrderB=HardwareResetFlow.trace(0,List.of(
            fn(0x100,false,false,false),
            fn(0,false,false,false,0x100L,0x400L),
            fn(0x400,false,false,false)),List.of(0x400L),3,2,10);
        ok(cappedOrderA.equals(cappedOrderB) &&
            cappedOrderA.evidence().isEmpty() && cappedOrderA.truncated() &&
            cappedOrderA.unresolved() && cappedOrderA.visitedFunctions()==2,
            "bounded RESET frontier does not depend on Ghidra reference order");
        var fullOrder=HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,false,0x400L,0x100L),
            fn(0x400,true,false,false),
            fn(0x100,false,false,false)),List.of(0x400L),3,3,10);
        ok(fullOrder.evidence().size()==1 && !fullOrder.truncated(),
            "uncapped source graph retains MMIO candidate despite sorted edges");
        ok(graph.markdown(0x2bc0,0x2bc0).contains("STATIC CANDIDATES ONLY") &&
           graph.markdown(0x2bc0,0x2bc0).contains("Address order is not execution order"),
            "must not claim a runtime execution trace");

        // A report assembled from a different RESET source must never be
        // published under the caller's claimed vector/function coordinates.
        var wrongPublications=List.<Runnable>of(
            ()->graph.markdown(0x2bc2L,0x2bc0L),
            ()->graph.markdown(0x2bc0L,0x3000L),
            ()->graph.markdown(0x3000L,0x3000L),
            ()->graph.markdown(0x2bc1L,0x2bc1L),
            ()->graph.markdown(0x100000000L,0x2bc0L));
        for(Runnable probe:wrongPublications) {
            boolean denied=false;
            try {probe.run();}
            catch(IllegalArgumentException expected){denied=true;}
            ok(denied,"forged RESET publication identity must fail closed");
        }
        ok(graph.markdown(0x2bc0L,0x2bc0L).contains(
            "candidate chain 0x00002BC0"),
            "exact source-root publication remains available");
                var unknownRoot=HardwareResetFlow.trace(0x7000,calls,List.of(0x5000L),8,50,20);
        ok(!unknownRoot.rootRecognized() && unknownRoot.unresolved(),
            "unrecognized root must not claim no initialization");
        var indirect=HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,true,1L),
            fn(1,true,false,false)),List.of(1L),8,50,20);
        ok(indirect.unresolved() && indirect.evidence().size()==1,
            "computed flow uncertainty persists despite known direct candidate");
        var missing=HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,false,7L)),List.of(7L),8,50,20);
        ok(missing.unresolved() && missing.evidence().isEmpty(),
            "missing direct target does not magically have known register writes");
        var recursion=HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,false,1L),
            fn(1,true,false,false,0L)),List.of(1L),8,50,20);
        ok(recursion.recursive() && recursion.unresolved() && recursion.visitedFunctions()==2,
            "recursive edges are not safe closed graphs");
        // Already-scheduled targets do not become unknown simply because
        // their referring CALL edge is encountered at the maximum depth.
        var selfAtDepth0=HardwareResetFlow.trace(0,List.of(
            fn(0,true,false,false,0L,0L)),List.of(0L),0,1,3);
        ok(selfAtDepth0.visitedFunctions()==1 &&
            selfAtDepth0.evidence().size()==1 &&
            selfAtDepth0.recursive() && selfAtDepth0.unresolved() &&
            !selfAtDepth0.truncated(),
            "RESET self-loop at depth zero is cycle-only, not an omitted frontier");
        var cycleAtDepth1=HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,false,2L),
            fn(2,true,false,false,0L)),List.of(2L),1,2,3);
        ok(cycleAtDepth1.recursive() && cycleAtDepth1.unresolved() &&
            cycleAtDepth1.visitedFunctions()==2 &&
            !cycleAtDepth1.truncated() && cycleAtDepth1.evidence().size()==1,
            "two-function loop at depth cap is fully observed recursion");
        var sharedAtDepth1=HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,false,2L,4L),
            fn(2,false,false,false,4L),
            fn(4,true,false,false)),List.of(4L),1,3,3);
        ok(!sharedAtDepth1.recursive() &&
            !sharedAtDepth1.unresolved() &&
            !sharedAtDepth1.truncated() &&
            sharedAtDepth1.visitedFunctions()==3 &&
            sharedAtDepth1.evidence().size()==1 &&
            sharedAtDepth1.evidence().get(0).chain()
                .equals("0x00000000 -> 0x00000004"),
            "RESET convergent known target at boundary is not an unknown frontier");
        var absentAtDepth0=HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,false,6L)),List.of(6L),0,2,3);
        ok(absentAtDepth0.visitedFunctions()==1 &&
            absentAtDepth0.unresolved() && !absentAtDepth0.truncated() &&
            absentAtDepth0.evidence().isEmpty(),
            "missing direct-call target is observed UNKNOWN even at depth cap");
        var unseenAtDepth1=HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,false,2L),
            fn(2,false,false,false,4L),
            fn(4,true,false,false)),List.of(4L),1,3,3);
        ok(unseenAtDepth1.truncated() && unseenAtDepth1.unresolved() &&
            unseenAtDepth1.evidence().isEmpty(),
            "only genuinely unexamined decoded function requires RESET depth cap");
        var depth=HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,false,1L),
            fn(1,false,false,false,2L),
            fn(2,false,true,false)),List.of(2L),1,50,20);
        ok(depth.truncated() && depth.unresolved() && depth.evidence().isEmpty(),
            "depth budget must not infer evidence outside explored boundary");
        var budget=HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,false,1L,2L),
            fn(1,true,false,false),
            fn(2,true,false,false)),List.of(1L,2L),8,2,20);
        ok(budget.truncated() && budget.unresolved() &&
            budget.visitedFunctions()==2,
            "node budget truncation must be explicit");
        var rows=HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,false,1L,2L),
            fn(1,true,false,false),
            fn(2,true,false,false)),List.of(1L,2L),8,50,1);
        ok(rows.truncated() && rows.unresolved() && rows.evidence().size()==1,
            "evidence display cap cannot imply complete evidence");
        boolean rejected=false;
        try{HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,false),fn(0,false,false,false)),
            List.of(),8,50,20);}
        catch(IllegalArgumentException expected){rejected=true;}
        ok(rejected,"duplicate function identifiers rejected");
        // A wide fan-in of duplicate CALL destinations must not allocate a
        // queued path for every edge or consume unique-node capacity.
        var duplicateCalls=HardwareResetFlow.trace(0,List.of(
            new HardwareCallEffects.FunctionNode(0,false,false,false,
                java.util.Collections.nCopies(12_000,1L)),
            fn(1,true,false,false)),List.of(1L),2,2,2);
        ok(duplicateCalls.visitedFunctions()==2 &&
            duplicateCalls.evidence().size()==1 &&
            !duplicateCalls.truncated() && !duplicateCalls.unresolved(),
            "12k duplicate direct CALL targets cannot overwhelm BFS queue");

        // Distinct unscheduled destinations beyond budget must become UNKNOWN,
        // never a misleading negative inference of absent hardware effects.
        var fanout=new java.util.ArrayList<Long>();
        var broad=new java.util.ArrayList<HardwareCallEffects.FunctionNode>();
        for(int i=1;i<=5000;i++) {
            fanout.add((long)i);
            broad.add(fn(i,i==5000,false,false));
        }
        broad.add(new HardwareCallEffects.FunctionNode(
            0,false,false,false,fanout));
        var capped=HardwareResetFlow.trace(
            0,broad,List.of(5000L),2,3,3);
        ok(capped.visitedFunctions()==3 && capped.evidence().isEmpty() &&
            capped.truncated() && capped.unresolved(),
            "wide unknown horizon explicitly limited before late STORE");
        // The selected shortest-path BFS tree contains no backedge here,
        // but source CALL edges 1 <-> 2 form real static recursion.
        var crossCycle=HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,false,1L,2L),
            fn(1,false,false,false,2L),
            fn(2,false,false,false,1L)),
            List.of(),3,4,2);
        ok(crossCycle.recursive() && crossCycle.unresolved() &&
            !crossCycle.truncated() && crossCycle.visitedFunctions()==3,
            "cross-edge recursion detected independently of shortest BFS paths");
        // Duplicate edges in a DAG cannot masquerade as a cycle.
        var noCycle=HardwareResetFlow.trace(0,List.of(
            fn(0,false,false,false,1L,1L,2L),
            fn(1,false,false,false,2L),
            fn(2,false,false,false)),
            List.of(),3,4,2);
        ok(!noCycle.recursive() && !noCycle.unresolved() &&
            noCycle.visitedFunctions()==3,
            "convergence and repeated edges alone are not recursion");
        boolean badLimit=false;
        try{HardwareResetFlow.trace(0,List.of(fn(0,false,false,false)),
            List.of(),HardwareResetFlow.MAX_DEPTH+1,1,1);}
        catch(IllegalArgumentException expected){badLimit=true;}
        ok(badLimit,"reject unbounded RESET path depth");
        badLimit=false;
        try{HardwareResetFlow.trace(0,List.of(fn(0,false,false,false)),
            List.of(),1,HardwareResetFlow.MAX_NODES+1,1);}
        catch(IllegalArgumentException expected){badLimit=true;}
        ok(badLimit,"reject unbounded distinct-node budget");
        badLimit=false;
        try{HardwareResetFlow.trace(0,List.of(fn(0,false,false,false)),
            java.util.Arrays.asList((Long)null),1,3,1);}
        catch(IllegalArgumentException expected){badLimit=true;}
        ok(badLimit,"reject null source evidence function");
        long cpu32Overflow=0x1_0000_0000L;
        java.util.List<Runnable> invalidResetSources=java.util.List.of(
            ()->HardwareResetFlow.trace(cpu32Overflow,
                List.of(fn(0,false,false,false)),List.of(),1,2,2),
            ()->HardwareResetFlow.trace(0,
                List.of(fn(0,false,false,false)),List.of(cpu32Overflow),1,2,2));
        for(Runnable probe:invalidResetSources) {
            boolean refused=false;
            try {probe.run();}
            catch(IllegalArgumentException expected){refused=true;}
            ok(refused,"RESET cannot publish source identities beyond unsigned CPU32");
        }
        var u32Reset=HardwareResetFlow.trace(0xffffffffL,
            List.of(fn(0xffffffffL,true,false,false)),
            List.of(0xffffffffL),0,1,1);
        ok(u32Reset.rootRecognized() && u32Reset.visitedFunctions()==1 &&
            u32Reset.evidence().size()==1,
            "full unsigned U32 RESET identity stays valid without MC68332 remapping");
        var badResetReports=new java.util.ArrayList<Runnable>();
        badResetReports.add(()->new HardwareResetFlow.Summary(
            true,1,false,false,false,List.of(),Set.of()));
        badResetReports.add(()->new HardwareResetFlow.Summary(
            false,1,true,false,false,List.of(),Set.of(0L)));
        badResetReports.add(()->new HardwareResetFlow.Summary(
            true,1,false,true,false,List.of(),Set.of(0L)));
        badResetReports.add(()->new HardwareResetFlow.Summary(
            true,1,false,false,true,List.of(),Set.of(0L)));
        badResetReports.add(()->new HardwareResetFlow.Evidence(
            0L,"0x00000001",0,true,false));
        badResetReports.add(()->new HardwareResetFlow.Evidence(
            0L,"0x00000000 -> 0x00000001",1,true,false));
        badResetReports.add(()->new HardwareResetFlow.Evidence(
            0L,"0x00000000 -> 0x00000000",0,true,false));
        badResetReports.add(()->new HardwareResetFlow.Summary(
            true,1,false,false,false,
            List.of(new HardwareResetFlow.Evidence(
                1L,"0x00000000 -> 0x00000001",1,true,false)),
            Set.of(1L)));
        badResetReports.add(()->new HardwareResetFlow.Summary(
            true,1,false,false,false,
            List.of(new HardwareResetFlow.Evidence(
                1L,"0x00000001",0,true,false),
                new HardwareResetFlow.Evidence(
                1L,"0x00000001",0,false,true)),
            Set.of(1L)));
        badResetReports.add(()->new HardwareResetFlow.Summary(
            true,0,true,false,false,List.of(),Set.of()));
        badResetReports.add(()->new HardwareResetFlow.Summary(
            false,0,false,false,false,List.of(),Set.of()));
        badResetReports.add(()->new HardwareResetFlow.Summary(
            true,4,false,false,false,List.of(
                new HardwareResetFlow.Evidence(1L,
                    "0x00000000 -> 0x00000001",1,true,false),
                new HardwareResetFlow.Evidence(3L,
                    "0x00000002 -> 0x00000003",1,true,false)),
                Set.of(0L,1L,2L,3L)));
        badResetReports.add(()->new HardwareResetFlow.Summary(
            true,2,false,false,false,List.of(
                new HardwareResetFlow.Evidence(1L,
                    "0x00000000 -> 0x00000002 -> 0x00000001",2,true,false)),
                Set.of(0L,1L)));
        for(Runnable forged:badResetReports) {
            boolean denied=false;
            try {forged.run();}
            catch(IllegalArgumentException expected){denied=true;}
            ok(denied,
                "RESET cannot publish forged source paths, duplicates or visit counts");
        }
        var properReport=HardwareResetFlow.trace(0L,
            List.of(fn(0L,false,false,false,1L),
                    fn(1L,true,false,false)),
            List.of(1L),2,2,2);
        ok(properReport.evidence().size()==1 &&
            properReport.evidence().get(0).chain().equals(
                "0x00000000 -> 0x00000001") &&
            properReport.visitedFunctions()==2,
            "observed RESET source path is consistent with two inspected nodes");
        var rootAbsent=HardwareResetFlow.trace(0L,List.of(),List.of(),0,1,1);
        ok(!rootAbsent.rootRecognized() && rootAbsent.visitedFunctions()==0 &&
            rootAbsent.evidence().isEmpty(),
            "missing RESET root preserves an explicit zero-visit unknown report");
        System.out.println("HardwareResetFlowSelfTest OK");
    }
}
