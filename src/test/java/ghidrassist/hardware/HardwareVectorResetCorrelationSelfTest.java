package ghidrassist.hardware;

import java.util.List;
import java.util.Set;

/** No firmware or Ghidra dependency; source-only adversarial fixture. */
public final class HardwareVectorResetCorrelationSelfTest {
    private HardwareVectorResetCorrelationSelfTest() {}
    private static int assertions;
    private static void check(boolean yes, String reason) {
        assertions++;
        if (!yes) throw new AssertionError(reason);
    }
    private static void bad(Runnable operation, String reason) {
        boolean failed = false;
        try { operation.run(); }
        catch (IllegalArgumentException expected) { failed = true; }
        check(failed, reason);
    }
    public static void main(String[] args) {
        var graph = List.of(
            new HardwareCallEffects.FunctionNode(0x100, false, false, false,
                List.of(0x130L)),
            new HardwareCallEffects.FunctionNode(0x130, false, true, false,
                List.of(0x160L)),
            new HardwareCallEffects.FunctionNode(0x160, true, false, true,
                List.of()),
            new HardwareCallEffects.FunctionNode(0x220, false, false, false,
                List.of()),
            new HardwareCallEffects.FunctionNode(0x300, false, false, false,
                List.of(0x310L)),
            new HardwareCallEffects.FunctionNode(0x310, true, false, false,
                List.of(0x300L)));
        var reset = HardwareResetFlow.trace(0x100, graph, Set.of(0x160L),
            6, 128, 30);
        check(reset.rootRecognized() && reset.visitedEntries()
            .equals(Set.of(0x100L, 0x130L, 0x160L)), "reset subset");
        var targets = List.of(
            new HardwareVectorResetCorrelation.Target(33, 0x222, 0x220, false),
            new HardwareVectorResetCorrelation.Target(26, 0x130, 0x130, true),
            new HardwareVectorResetCorrelation.Target(32, 0x220, 0x220, true),
            new HardwareVectorResetCorrelation.Target(34, 0x300, 0x300, true));
        var report = HardwareVectorResetCorrelation.inspect(
            reset.rootRecognized(), reset.unresolved(), reset.visitedEntries(),
            targets, graph, 32);
        check(report.recognizedTargets() == 4 && report.exactEntries() == 3
            && report.sharedResetSubset() == 1
            && report.outsideObservedSubset() == 2
            && report.interiorPointers() == 1, "count static relations only");
        check(report.rows().get(0).vectorNumber() == 26,
            "stable vector order independent of input order");
        var shared = report.rows().get(0);
        check(shared.relation() ==
            HardwareVectorResetCorrelation.Relation.IN_RESET_STATIC_CALL_SUBSET,
            "vector points into reset call subtree");
        check(shared.memoryStoreEffect().equals("STATIC_CANDIDATE") &&
              shared.vbrEffect().equals("STATIC_CANDIDATE") &&
              shared.flowUncertain(),
              "callee STORE/VBR are possible, unknown flow remains explicit");
        var outside = report.rows().get(1);
        check(outside.relation() ==
            HardwareVectorResetCorrelation.Relation.OUTSIDE_OBSERVED_RESET_SUBSET
            && outside.memoryStoreEffect().equals("NOT_OBSERVED_IN_BOUNDED_GRAPH"),
            "not observed in reset calls is not proven unreachable");
        var interior = report.rows().get(2);
        check(interior.relation() ==
            HardwareVectorResetCorrelation.Relation.INTERIOR_FUNCTION_POINTER_NOT_ENTRY
            && interior.memoryStoreEffect().equals("UNKNOWN")
            && interior.vbrEffect().equals("UNKNOWN"),
            "never promote interior pointer to handler entry or effects");
        check(report.rows().get(3).flowUncertain()
            && report.rows().get(3).memoryStoreEffect().equals("STATIC_CANDIDATE"),
            "cycles cannot erase possible effects");
        var md = report.markdown();
        check(md.contains("STATIC ONLY") && md.contains("runtime VBR")
            && md.contains("NOT function entries")
            && md.contains("not necessarily MMIO"),
            "no execution, physical map, or hardware latch claim");
        check(!report.relocatedSource() && report.tableAddress()==0 &&
            md.contains("Vector table input: image-zero bytes ONLY") &&
            md.contains("| Vector | Image-zero pointer |"),
            "legacy image-zero inventory must retain its actual source label");
        var relocated = HardwareVectorResetCorrelation.inspectRelocated(
            0x800L,true,false,reset.visitedEntries(),targets,graph,32);
        String relocatedText=relocated.markdown();
        check(relocated.relocatedSource() && relocated.tableAddress()==0x800L &&
            relocated.recognizedTargets()==report.recognizedTargets() &&
            relocated.rows().equals(report.rows()),
            "origin-aware rendering must not change ISR/RESET classification");
        check(relocatedText.contains(
                "relocated MOVEC-to-VBR source-image candidate at 0x00000800") &&
            relocatedText.contains("| Vector | Relocated source-image pointer |") &&
            !relocatedText.contains("image-zero bytes ONLY") &&
            !relocatedText.contains("| Vector | Image-zero pointer |") &&
            relocatedText.contains("runtime VBR and IRQ activation UNKNOWN"),
            "relocated VBR vector words must not be mislabeled image-zero");
        var incompleteRelocated=HardwareVectorResetCorrelation.inspectRelocated(
            0x800L,true,true,reset.visitedEntries(),targets,graph,32);
        check(incompleteRelocated.rows().stream().allMatch(
                HardwareVectorResetCorrelation.Row::flowUncertain) &&
            incompleteRelocated.recognizedTargets()==report.recognizedTargets() &&
            incompleteRelocated.sharedResetSubset()==report.sharedResetSubset() &&
            incompleteRelocated.rows().get(1).memoryStoreEffect().equals(
                "NOT_OBSERVED_IN_BOUNDED_GRAPH"),
            "incomplete RESET graph poisons every row's relation confidence"
                +" without inventing a STORE or changing observed counts");
        var incompleteImageZero=HardwareVectorResetCorrelation.inspect(
            true,true,reset.visitedEntries(),targets,graph,32);
        check(incompleteImageZero.rows().stream().allMatch(
                HardwareVectorResetCorrelation.Row::flowUncertain),
            "image-zero source rows receive the same RESET incompleteness gate");
        var emptyRelocated=HardwareVectorResetCorrelation.inspectRelocated(
            0x800L,true,false,Set.of(),List.of(),graph,32);
        check(emptyRelocated.rows().isEmpty() &&
            emptyRelocated.markdown().contains("relocated source-image inventory") &&
            !emptyRelocated.markdown().contains("image-zero inventory"),
            "empty relocated table keeps true provenance without handlers");
        bad(() -> HardwareVectorResetCorrelation.inspectRelocated(
                0x801L,true,false,Set.of(),targets,graph,32),
            "unaligned relocated source base rejected");
        bad(() -> HardwareVectorResetCorrelation.inspectRelocated(
                0xfffffcL,true,false,Set.of(),targets,graph,32),
            "truncated 24-bit relocated table rejected");
        var limited = HardwareVectorResetCorrelation.inspect(
            true, false, reset.visitedEntries(), targets, graph, 1);
        check(limited.displayTruncated() && limited.recognizedTargets() == 4 &&
            limited.rows().size() == 1 && limited.markdown().contains("Rows truncated"),
            "display caps do not truncate classification counts");
        var missingRoot = HardwareVectorResetCorrelation.inspect(
            false, true, Set.of(0x130L), targets, graph, 32);
        check(missingRoot.sharedResetSubset() == 0 &&
            missingRoot.rows().get(0).relation() ==
                HardwareVectorResetCorrelation.Relation.RESET_ROOT_UNKNOWN,
            "unknown reset forbids false graph relation");
        check(missingRoot.rows().stream().allMatch(
                HardwareVectorResetCorrelation.Row::flowUncertain),
            "unrecognized RESET root must poison row-level flow confidence");
        var unknownCall = HardwareVectorResetCorrelation.inspect(
            true, true, Set.of(), List.of(
                new HardwareVectorResetCorrelation.Target(40, 0x500, 0x500, true)),
            graph, 10);
        check(unknownCall.rows().get(0).memoryStoreEffect().equals("UNKNOWN") &&
            unknownCall.rows().get(0).flowUncertain(),
            "missing call graph node never proves no side effects");
        bad(() -> HardwareVectorResetCorrelation.inspect(true, false, Set.of(),
                List.of(targets.get(0), targets.get(0)), graph, 32),
            "duplicate vector slots rejected");
        bad(() -> new HardwareVectorResetCorrelation.Target(256, 0x100, 0x100, true),
            "invalid slot rejected");
        bad(() -> new HardwareVectorResetCorrelation.Target(2, 0x101, 0x100, false),
            "odd pointer rejected");
        bad(() -> new HardwareVectorResetCorrelation.Target(2, 0x100, 0x100, false),
            "entry assertion must match the pointer");
        bad(() -> HardwareVectorResetCorrelation.inspect(true, false, Set.of(),
                targets, graph, 0), "zero display cap rejected");
        boolean immutable = false;
        try { report.rows().clear(); }
        catch (UnsupportedOperationException expected) { immutable = true; }
        check(immutable, "result is immutable");
        System.out.println("HardwareVectorResetCorrelationSelfTest PASS: assertions="+assertions);
    }
}
