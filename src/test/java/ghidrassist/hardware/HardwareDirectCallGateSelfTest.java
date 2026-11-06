package ghidrassist.hardware;

import java.util.List;
import java.util.Set;

/**
 * Deterministic Java21 adversarial source-only CALL/RESET/MM/ISR regression.
 * Actual Ghidra computed JSR with a maliciously helpful CALL reference is
 * also checked independently by the real synthetic headless workflow.
 */
public final class HardwareDirectCallGateSelfTest {
    private HardwareDirectCallGateSelfTest() {}
    private static int checks;
    private static void ok(boolean truth,String reason) {
        checks++;
        if(!truth)throw new AssertionError(reason);
    }
    private static HardwareCallEffects.FunctionNode node(
            long entry,boolean store,boolean vbr,boolean unresolved,Long... calls) {
        return new HardwareCallEffects.FunctionNode(entry,store,vbr,
            unresolved,List.of(calls));
    }
    public static void main(String[] unused) {
        for(int refs:new int[]{-1,0,1,2,100}) {
            ok(!HardwareDirectCallGate.directCandidate(false,false,refs),
                "non-CALL with CALL XREF count="+refs+" is not a graph edge");
            ok(!HardwareDirectCallGate.directCandidate(false,true,refs),
                "non-CALL computed reference is not a decoded CALL");
            ok(!HardwareDirectCallGate.directCandidate(true,true,refs),
                "computed JSR with "+refs+" refs remains UNKNOWN");
            ok(HardwareDirectCallGate.directCandidate(true,false,refs)
                    ==(refs==1),
                "direct CALL requires exactly one decoded flow target");
        }
        ok(!HardwareDirectCallGate.directCandidate(true,true,1),
            "one user-defined COMPUTED_CALL reference is NOT direct flow");
        ok(!HardwareDirectCallGate.directCandidate(true,true,1),
            "separately byte-proven MOVEA+JSR still not a global direct edge");

        // A naive consumer adding the apparently unique Ghidra computed
        // reference to its graph invents RESET-reachable STORE/VBR evidence.
        var falseGraph=List.of(
            node(0x680,false,false,false,0x700L),
            node(0x700,true,true,false));
        var fabricated=HardwareResetFlow.trace(0x680,falseGraph,
            Set.of(0x700L),6,32,10);
        ok(fabricated.visitedEntries().contains(0x700L) &&
            fabricated.evidence().size()==1,
            "fixture exposes the false indirect/RESET promotion");
        // Correct graph preserves the computed call as an unknown edge,
        // not as a silently closed/negative no-effect graph.
        var safeGraph=List.of(
            node(0x680,false,false,true),
            node(0x700,true,true,false));
        var bounded=HardwareResetFlow.trace(0x680,safeGraph,
            Set.of(0x700L),6,32,10);
        ok(bounded.rootRecognized() && bounded.unresolved() &&
            !bounded.truncated() &&
            bounded.visitedEntries().equals(Set.of(0x680L)) &&
            bounded.evidence().isEmpty(),
            "computed JSR unknown target must not reach MMIO/VBR callee");
        var transitive=HardwareCallEffects.summarize(0x680,
            safeGraph,4,20);
        ok(!transitive.possibleMemoryStore() &&
            !transitive.possibleVbrWrite() &&
            transitive.unresolved() && !transitive.truncated(),
            "no observed STORE != negative hardware conclusion");
        var relation=HardwareVectorResetCorrelation.inspect(
            bounded.rootRecognized(),bounded.unresolved(),
            bounded.visitedEntries(),
            List.of(new HardwareVectorResetCorrelation.Target(
                26,0x680,0x680,true)),safeGraph,10);
        ok(relation.sharedResetSubset()==1 &&
            relation.rows().get(0).flowUncertain() &&
            relation.rows().get(0).memoryStoreEffect().equals("UNKNOWN") &&
            relation.rows().get(0).vbrEffect().equals("UNKNOWN"),
            "ISR vector points to RESET-root only with UNKNOWN transitive effects");

        var mm=HardwareInterproceduralMmEffects.analyze(
            List.of(
                new HardwareInterproceduralMmEffects.FunctionNode(
                    0x680L,false,false,true,List.of()),
                new HardwareInterproceduralMmEffects.FunctionNode(
                    0x700L,true,false,false,List.of())),
            List.of(new HardwareInterproceduralMmEffects.CallSite(
                0x680L,0x680L,null)),
            Set.of(0x680L),4,20,10);
        ok(mm.rows().size()==1 &&
            mm.rows().get(0).call().target()==null &&
            mm.rows().get(0).summary().unknownControl() &&
            mm.rows().get(0).summary().uncertainOrMm() &&
            !mm.rows().get(0).summary().mayMm(),
            "one untrusted computed CALL cannot become confirmed MM low-byte STORE");
        ok(mm.markdown().contains("-> UNKNOWN") &&
            mm.markdown().contains("unknown callee/flow=true"),
            "unresolved computed site remains legible in UI");

        // Positive control: genuine decoded direct JSR to exact function
        // entry keeps already-established static reachability.
        ok(HardwareDirectCallGate.directCandidate(true,false,1),
            "direct JSR with one target is retained as a source candidate");
        var directGraph=List.of(
            node(0x600,false,false,false,0x700L),
            node(0x700,true,true,false));
        var directReset=HardwareResetFlow.trace(0x600,directGraph,
            Set.of(0x700L),6,32,10);
        ok(directReset.rootRecognized() && !directReset.unresolved() &&
            directReset.visitedEntries().contains(0x700L) &&
            directReset.evidence().size()==1 &&
            directReset.evidence().get(0).chain()
                .equals("0x00000600 -> 0x00000700"),
            "real direct call remains a *static* RESET source path");
        ok(!directReset.markdown(0x600,0x600).contains(
                "actual execution verified"),
            "direct CALL reachability is never real CPU execution");
        System.out.println("HardwareDirectCallGateSelfTest PASS: assertions="+checks);
    }
}
