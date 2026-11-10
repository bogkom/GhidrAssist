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
        check(shared.storeSourcePath().equals(
                "MEMORY_STORE -> 0x00000130 -> 0x00000160") &&
            shared.vbrSourcePath().equals(
                "MOVEC_VBR -> 0x00000130") &&
            shared.observedUnknownPath().equals(
                "UNKNOWN_FLOW -> 0x00000130 -> 0x00000160") &&
            shared.frontierPath().equals("NONE"),
            "vector target now names shortest typed STORE/MOVEC and unknown CALL chains");
        var outside = report.rows().get(1);
        check(outside.relation() ==
            HardwareVectorResetCorrelation.Relation.OUTSIDE_OBSERVED_RESET_SUBSET
            && outside.memoryStoreEffect().equals("NOT_OBSERVED_IN_BOUNDED_GRAPH"),
            "not observed in reset calls is not proven unreachable");
        var interior = report.rows().get(2);
        check(interior.relation() ==
            HardwareVectorResetCorrelation.Relation.INTERIOR_FUNCTION_POINTER_NOT_ENTRY
            && interior.memoryStoreEffect().equals("UNKNOWN")
            && interior.vbrEffect().equals("UNKNOWN") &&
            interior.storeSourcePath().equals("NONE") &&
            interior.vbrSourcePath().equals("NONE") &&
            interior.observedUnknownPath().equals("NONE") &&
            interior.frontierPath().equals("NONE"),
            "interior vector pointer cannot borrow complete-function source chains");
        check(report.rows().get(3).flowUncertain()
            && report.rows().get(3).memoryStoreEffect().equals("STATIC_CANDIDATE")
            && report.rows().get(3).storeSourcePath().equals(
                "MEMORY_STORE -> 0x00000300 -> 0x00000310")
            && report.rows().get(3).observedUnknownPath().equals("NONE"),
            "cycles cannot erase possible STORE or invent unknown function chains");
        var md = report.markdown();
        check(md.contains("STATIC ONLY") && md.contains("runtime VBR")
            && md.contains("NOT function entries")
            && md.contains("not necessarily MMIO") &&
            md.contains("STORE source function path") &&
            md.contains("Uninspected depth/node frontier path") &&
            md.contains("not instruction PCs or runtime flows"),
            "typed witnesses never claim execution, physical map or MM latch");
        check(!report.relocatedSource() && report.tableAddress()==0 &&
            md.contains("Vector table input: image-zero bytes ONLY") &&
            md.contains("| Vector | Image-zero pointer |"),
            "legacy image-zero inventory must retain its actual source label");
        var relocated = HardwareVectorResetCorrelation.inspectRelocated(
            0x800L,true,true,reset.visitedEntries(),targets,graph,32);
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
        var completeRelocated=HardwareVectorResetCorrelation.inspectRelocated(
            0x800L,true,false,reset.visitedEntries(),targets,graph,32);
        check(!completeRelocated.rows().get(1).flowUncertain() &&
            incompleteRelocated.rows().get(1).flowUncertain() &&
            completeRelocated.rows().get(1).relation()==
                incompleteRelocated.rows().get(1).relation() &&
            completeRelocated.rows().get(1).memoryStoreEffect().equals(
                incompleteRelocated.rows().get(1).memoryStoreEffect()),
            "row confidence changes with RESET horizon, not static local effect");
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
        bad(() -> new HardwareVectorResetCorrelation.Target(2, 0x100, 0x120, false),
            "an interior vector pointer cannot precede the claimed function entry");
        bad(() -> new HardwareVectorResetCorrelation.Target(2, 0x100, 0x120, true),
            "a later function entry cannot be asserted as an exact vector entry");
        var validInterior = new HardwareVectorResetCorrelation.Target(
            2, 0x120, 0x100, false);
        check(!validInterior.exactEntry() &&
            validInterior.pointer() > validInterior.functionEntry(),
            "forward interior pointer remains a candidate, not a function entry");
        bad(() -> HardwareVectorResetCorrelation.inspect(true, false, Set.of(),
                targets, graph, 0), "zero display cap rejected");
        boolean immutable = false;
        try { report.rows().clear(); }
        catch (UnsupportedOperationException expected) { immutable = true; }
        check(immutable, "result is immutable");
        // Multiple numbered vectors may point to one exact handler. They
        // share a read-only transitive subtree analysis only within this
        // report; vector-specific labels and counts must stay independent.
        var duplicateHandlerSlots=List.of(
            new HardwareVectorResetCorrelation.Target(42,0x130,0x130,true),
            new HardwareVectorResetCorrelation.Target(41,0x130,0x130,true));
        var sharedHandler=HardwareVectorResetCorrelation.inspect(
            true,false,reset.visitedEntries(),duplicateHandlerSlots,graph,16);
        check(sharedHandler.exactEntries()==2 &&
            sharedHandler.recognizedTargets()==2 &&
            sharedHandler.sharedResetSubset()==2 &&
            sharedHandler.rows().get(0).vectorNumber()==41 &&
            sharedHandler.rows().get(1).vectorNumber()==42 &&
            sharedHandler.rows().get(0).memoryStoreEffect().equals(
                sharedHandler.rows().get(1).memoryStoreEffect()) &&
            sharedHandler.rows().get(0).vbrEffect().equals(
                sharedHandler.rows().get(1).vbrEffect()) &&
            sharedHandler.rows().get(0).flowUncertain()==
                sharedHandler.rows().get(1).flowUncertain(),
            "distinct vector slots sharing one handler preserve identical static effect evidence");
        check(sharedHandler.equals(HardwareVectorResetCorrelation.inspect(
                true,false,reset.visitedEntries(),
                List.of(duplicateHandlerSlots.get(1),duplicateHandlerSlots.get(0)),
                graph,16)),
            "vector report deterministic regardless of source input order");
        bad(() -> HardwareVectorResetCorrelation.inspect(
            true,false,reset.visitedEntries(),
            java.util.Arrays.asList((HardwareVectorResetCorrelation.Target)null),
            graph,16),"null candidate rejected before sorting");
        bad(() -> HardwareVectorResetCorrelation.inspect(
            true,false,reset.visitedEntries(),
            java.util.Collections.nCopies(255,duplicateHandlerSlots.get(0)),
            graph,16),"more than 254 recognized vector slots rejected");
        var invalidResetEntries=new java.util.HashSet<Long>();
        invalidResetEntries.add(null);
        bad(() -> HardwareVectorResetCorrelation.inspect(
            true,false,invalidResetEntries,targets,graph,16),
            "null RESET path address cannot be silently accepted");
        bad(() -> HardwareVectorResetCorrelation.inspect(
            true,false,Set.of(-1L),targets,graph,16),
            "negative RESET address fails closed");
        bad(() -> HardwareVectorResetCorrelation.inspect(
            true,false,reset.visitedEntries(),targets,
            java.util.Collections.nCopies(
                HardwareCallEffects.MAX_SOURCE_FUNCTIONS+1,graph.get(0)),16),
            "unbounded transitive effect graph refused before per-handler analysis");
        // Exact vector entries outside the image-zero RESET subtree still
        // have their own independent transitive source evidence; no actual
        // interrupt or active relocated VBR is implied.
        var depthNodes=List.of(
            new HardwareCallEffects.FunctionNode(0x700,false,false,false,
                List.of(0x702L)),
            new HardwareCallEffects.FunctionNode(0x702,false,false,false,
                List.of(0x704L)),
            new HardwareCallEffects.FunctionNode(0x704,false,false,false,
                List.of(0x706L)),
            new HardwareCallEffects.FunctionNode(0x706,false,false,false,
                List.of(0x708L)),
            new HardwareCallEffects.FunctionNode(0x708,false,false,false,
                List.of(0x70AL)),
            new HardwareCallEffects.FunctionNode(0x70A,true,false,false,
                List.of()));
        var depthVector=HardwareVectorResetCorrelation.inspectRelocated(
            0x800L,true,false,Set.of(0x100L),
            List.of(new HardwareVectorResetCorrelation.Target(
                55,0x700L,0x700L,true)),depthNodes,12);
        var depthRow=depthVector.rows().get(0);
        check(depthRow.memoryStoreEffect().equals("UNKNOWN") &&
            depthRow.storeSourcePath().equals("NONE") &&
            depthRow.observedUnknownPath().equals("NONE") &&
            depthRow.frontierPath().equals(
                "DEPTH_CUTOFF -> 0x00000700 -> 0x00000702 -> "+
                "0x00000704 -> 0x00000706 -> 0x00000708 -> 0x0000070A") &&
            depthRow.flowUncertain(),
            "unvisited fifth-hop STORE is a typed frontier, not a false negative");
        var missingVector=HardwareVectorResetCorrelation.inspect(
            true,false,Set.of(0x100L),
            List.of(new HardwareVectorResetCorrelation.Target(
                56,0x500L,0x500L,true)),graph,12);
        check(missingVector.rows().get(0).observedUnknownPath().equals(
                "MISSING_TARGET -> 0x00000500") &&
            missingVector.rows().get(0).frontierPath().equals("NONE") &&
            missingVector.rows().get(0).flowUncertain(),
            "recognized pointer without an included function body remains checked missing");
        var dualNodes=List.of(
            new HardwareCallEffects.FunctionNode(0x900L,false,false,false,
                List.of(0x940L,0x920L)),
            new HardwareCallEffects.FunctionNode(0x920L,false,false,true,
                List.of()),
            new HardwareCallEffects.FunctionNode(0x940L,false,false,false,
                List.of(0x942L)),
            new HardwareCallEffects.FunctionNode(0x942L,false,false,false,
                List.of(0x944L)),
            new HardwareCallEffects.FunctionNode(0x944L,false,false,false,
                List.of(0x946L)),
            new HardwareCallEffects.FunctionNode(0x946L,false,false,false,
                List.of(0x948L)),
            new HardwareCallEffects.FunctionNode(0x948L,true,false,false,
                List.of()));
        var dualVector=HardwareVectorResetCorrelation.inspect(
            true,true,Set.of(0x100L),
            List.of(new HardwareVectorResetCorrelation.Target(
                57,0x900L,0x900L,true)),dualNodes,12);
        var dualRow=dualVector.rows().get(0);
        check(dualRow.observedUnknownPath().equals(
                "UNKNOWN_FLOW -> 0x00000900 -> 0x00000920") &&
            dualRow.frontierPath().equals(
                "DEPTH_CUTOFF -> 0x00000900 -> 0x00000940 -> "+
                "0x00000942 -> 0x00000944 -> 0x00000946 -> 0x00000948") &&
            dualRow.storeSourcePath().equals("NONE") &&
            dualRow.memoryStoreEffect().equals("UNKNOWN"),
            "independent observed UNKNOWN and uninspected MM candidate both visible");
        check(dualVector.equals(HardwareVectorResetCorrelation.inspect(
                true,true,Set.of(0x100L),
                List.of(new HardwareVectorResetCorrelation.Target(
                    57,0x900L,0x900L,true)),
                List.of(dualNodes.get(6),dualNodes.get(4),dualNodes.get(3),
                    dualNodes.get(1),dualNodes.get(0),dualNodes.get(5),
                    dualNodes.get(2)),12)),
            "vector source witnesses independent of function-node listing order");
        var displayCap=HardwareVectorResetCorrelation.inspect(
            true,false,Set.of(0x100L),
            List.of(new HardwareVectorResetCorrelation.Target(
                    58,0x130L,0x130L,true),
                new HardwareVectorResetCorrelation.Target(
                    59,0x700L,0x700L,true)),
            graph,1);
        check(displayCap.recognizedTargets()==2 &&
            displayCap.rows().size()==1 && displayCap.displayTruncated() &&
            displayCap.rows().get(0).storeSourcePath().contains("0x00000160"),
            "vector row cap preserves complete counts and shown source witnesses");
        check(report.displayedStoreCandidates()==2 &&
                report.displayedVbrCandidates()==1 &&
                report.markdown().contains(
                    "DISPLAYED-ONLY STORE candidate roots: 2") &&
                report.markdown().contains(
                    "DISPLAYED-ONLY MOVEC/VBR candidate roots: 1") &&
                report.markdown().contains("omitted rows: 0"),
            "count only displayed exact handler sources, not full vector inventory");
        check(limited.markdown().contains("omitted rows: 3") &&
                limited.displayedStoreCandidates()==1,
            "capped display never publishes uninspected effect totals");
        bad(()->new HardwareVectorResetCorrelation.Row(
                26,0x130L,0x130L,
                HardwareVectorResetCorrelation.Relation.IN_RESET_STATIC_CALL_SUBSET,
                "STATIC_CANDIDATE","UNKNOWN",true,
                "MEMORY_STORE -> 0x00000140","NONE","NONE","NONE"),
            "typed STORE path cannot be attributed to a different root");
        bad(()->new HardwareVectorResetCorrelation.Row(
                26,0x130L,0x130L,
                HardwareVectorResetCorrelation.Relation.IN_RESET_STATIC_CALL_SUBSET,
                "STATIC_CANDIDATE","UNKNOWN",true,
                "MEMORY_STORE -> 0x00000130 | injected","NONE","NONE","NONE"),
            "typed source paths cannot inject Markdown table cells");
        bad(()->new HardwareVectorResetCorrelation.Row(
                26,0x130L,0x130L,
                HardwareVectorResetCorrelation.Relation.IN_RESET_STATIC_CALL_SUBSET,
                "NOT_OBSERVED_IN_BOUNDED_GRAPH","UNKNOWN",true,
                "MEMORY_STORE -> 0x00000130","NONE","NONE","NONE"),
            "observed source and closed STORE effect are contradictory");
        bad(()->new HardwareVectorResetCorrelation.Row(
                33,0x222L,0x220L,
                HardwareVectorResetCorrelation.Relation.INTERIOR_FUNCTION_POINTER_NOT_ENTRY,
                "STATIC_CANDIDATE","UNKNOWN",true,
                "NONE","NONE","NONE","NONE"),
            "interior pointer cannot borrow full-function STORE evidence");
        bad(()->new HardwareVectorResetCorrelation.Row(
                26,0x130L,0x130L,
                HardwareVectorResetCorrelation.Relation.RESET_ROOT_UNKNOWN,
                "UNKNOWN","UNKNOWN",false),
            "unknown RESET root must remain uncertain");
        bad(()->new HardwareVectorResetCorrelation.Row(
                26,0x130L,0x130L,
                HardwareVectorResetCorrelation.Relation.IN_RESET_STATIC_CALL_SUBSET,
                "STATIC_CANDIDATE","UNKNOWN",true,
                "MEMORY_STORE -> 0x00000130"+
                    (" -> 0x00000130").repeat(20),
                "NONE","NONE","NONE"),
            "unbounded witness text rejected before splitting");
        bad(()->new HardwareVectorResetCorrelation.Summary(
                false,0,true,false,4,3,1,2,1,false,null),
            "null vector source inventory rejected without NPE");
        bad(()->new HardwareVectorResetCorrelation.Summary(
                false,0,true,false,4,3,1,2,1,false,
                java.util.Arrays.asList(report.rows().get(0),null,
                    report.rows().get(2),report.rows().get(3))),
            "null vector row rejected with IllegalArgumentException");
        bad(()->new HardwareVectorResetCorrelation.Summary(
                false,0,true,false,4,3,1,2,1,false,
                List.of(report.rows().get(1),report.rows().get(0),
                    report.rows().get(2),report.rows().get(3))),
            "unsorted vector inventory cannot become authoritative");
        bad(()->new HardwareVectorResetCorrelation.Summary(
                false,0,true,false,4,3,2,1,1,false,report.rows()),
            "forged RESET shared/outside totals cannot fit displayed rows");
        bad(()->new HardwareVectorResetCorrelation.Summary(
                false,0,true,false,4,4,1,2,0,false,report.rows()),
            "fake exact/interior inventory partition cannot be published");
        bad(()->new HardwareVectorResetCorrelation.Summary(
                false,0,false,false,4,3,1,2,1,false,report.rows()),
            "unrecognized RESET must have no shared/outside counts");
        // Legacy seven-field row remains constructible without typed paths.
        check(new HardwareVectorResetCorrelation.Row(
                26,0x130L,0x130L,
                HardwareVectorResetCorrelation.Relation.IN_RESET_STATIC_CALL_SUBSET,
                "STATIC_CANDIDATE","UNKNOWN",true)
                .storeSourcePath().equals("NONE"),
            "old seven-field report constructor is source compatible");
        boolean invalidWitness=false;
        try {new HardwareVectorResetCorrelation.Row(2,0x100L,0x100L,
                HardwareVectorResetCorrelation.Relation.RESET_ROOT_UNKNOWN,
                "UNKNOWN","UNKNOWN",true,null,"NONE","NONE","NONE");}
        catch(IllegalArgumentException expected){invalidWitness=true;}
        check(invalidWitness,"null typed source-cell is not a valid vector report");
        System.out.println("HardwareVectorResetCorrelationSelfTest PASS: assertions="+assertions);
    }
}
