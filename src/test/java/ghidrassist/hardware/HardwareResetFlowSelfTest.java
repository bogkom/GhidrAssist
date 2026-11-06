package ghidrassist.hardware;

import java.util.List;

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
            "0x00002BC0 -> 0x00004000 -> 0x00005000"),
            "alternate possible call path is preserved, not address-sorted");
        ok(graph.markdown(0x2bc0,0x2bc0).contains("STATIC CANDIDATES ONLY") &&
           graph.markdown(0x2bc0,0x2bc0).contains("Address order is not execution order"),
            "must not claim a runtime execution trace");

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
        System.out.println("HardwareResetFlowSelfTest OK");
    }
}
