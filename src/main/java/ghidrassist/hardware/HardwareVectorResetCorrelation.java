package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * GA-01/02/03/11: compare image-zero vector POINTER CANDIDATES with the
 * bounded RESET direct-call subset and read-only transitive STORE/VBR clues.
 * Neither membership nor absence proves execution, IRQ activity or a VBR.
 */
public final class HardwareVectorResetCorrelation {
    private HardwareVectorResetCorrelation() {}

    public enum Relation {
        IN_RESET_STATIC_CALL_SUBSET,
        OUTSIDE_OBSERVED_RESET_SUBSET,
        INTERIOR_FUNCTION_POINTER_NOT_ENTRY,
        RESET_ROOT_UNKNOWN
    }

    /** Include only pointers that Ghidra resolves to a recognized function. */
    public record Target(int vectorNumber, long pointer, long functionEntry,
                         boolean exactEntry) {
        public Target {
            if (vectorNumber < 2 || vectorNumber > 255 ||
                    pointer <= 0 || pointer >= 0xffffffffL ||
                    pointer > 0xffffffffL || (pointer & 1) != 0 ||
                    functionEntry < 0 || functionEntry > 0xffffffffL ||
                    (functionEntry & 1) != 0 ||
                    exactEntry != (pointer == functionEntry))
                throw new IllegalArgumentException("Invalid recognized vector target");
        }
    }

    public record Row(int vectorNumber, long pointer, long functionEntry,
                      Relation relation, String memoryStoreEffect,
                      String vbrEffect, boolean flowUncertain) {}

    public record Summary(boolean resetRootRecognized, boolean resetGraphIncomplete,
                          int recognizedTargets, int exactEntries,
                          int sharedResetSubset, int outsideObservedSubset,
                          int interiorPointers, boolean displayTruncated,
                          List<Row> rows) {
        public Summary { rows = List.copyOf(rows); }

        public String markdown() {
            StringBuilder out = new StringBuilder();
            out.append("## Vector / RESET static-call relation candidates (GA-01/02/03/11)\n\n")
               .append("- Vector table input: image-zero bytes ONLY; runtime VBR ")
               .append("and IRQ activation UNKNOWN. RESET function recognized: ")
               .append(resetRootRecognized)
               .append("; RESET direct-call graph incomplete: ")
               .append(resetGraphIncomplete)
               .append(".\n")
               .append("- Vector pointers into recognized functions: ")
               .append(recognizedTargets)
               .append("; exact function entries: ").append(exactEntries)
               .append("; shared with observed RESET direct-call subset: ")
               .append(sharedResetSubset)
               .append("; not observed in that bounded subset: ")
               .append(outsideObservedSubset)
               .append("; interior pointers (NOT function entries): ")
               .append(interiorPointers).append(".\n")
               .append("- Transitive memory STORE means any P-code STORE in a ")
               .append("bounded candidate call subtree, not necessarily MMIO. ")
               .append("VBR means a possible static MOVEC site. UNKNOWN / ")
               .append("not observed are NOT evidence of no hardware effects.\n")
               .append("- **STATIC ONLY**: an exception-vector pointer and a ")
               .append("RESET direct-call connection do NOT demonstrate active ")
               .append("VBR, interrupt execution, branch feasibility, first SIMCR ")
               .append("write, latched MM, ISR entry or a physical CS map.\n\n");
            if (rows.isEmpty()) {
                out.append("- No recognized vector-function targets in this bounded ")
                   .append("image-zero inventory; not proof of no exceptions.\n\n");
                return out.toString();
            }
            out.append("| Vector | Image-zero pointer | Containing function | ")
               .append("RESET relation | Memory STORE in static call subtree | ")
               .append("VBR in static call subtree | Flow uncertainty |\n")
               .append("|---|---|---|---|---|---|---|\n");
            for (Row row : rows) {
                out.append("| ").append(row.vectorNumber()).append(" | ")
                   .append(hex(row.pointer())).append(" | ")
                   .append(hex(row.functionEntry())).append(" | ")
                   .append(row.relation()).append(" | ")
                   .append(row.memoryStoreEffect()).append(" | ")
                   .append(row.vbrEffect()).append(" | ")
                   .append(row.flowUncertain()).append(" |\n");
            }
            if (displayTruncated)
                out.append("- Rows truncated by display cap; numeric totals cover ")
                   .append("all recognized vector-function pointers.\n");
            return out.append("\n").toString();
        }
    }

    private static String hex(long value) {
        return String.format(Locale.ROOT, "0x%08X", value);
    }

    private static String effect(boolean possible, HardwareCallEffects.Summary summary) {
        if (summary == null) return "UNKNOWN";
        if (possible) return "STATIC_CANDIDATE";
        if (summary.unresolved() || summary.truncated())
            return "UNKNOWN";
        return "NOT_OBSERVED_IN_BOUNDED_GRAPH";
    }

    public static Summary inspect(boolean resetRootRecognized,
            boolean resetGraphIncomplete, Set<Long> resetVisited,
            List<Target> resolvedVectors,
            Collection<HardwareCallEffects.FunctionNode> graph, int maxRows) {
        if (resetVisited == null || resolvedVectors == null || graph == null ||
                maxRows < 1 || maxRows > 64)
            throw new IllegalArgumentException("Invalid vector/reset correlation input");
        List<Target> sorted = new ArrayList<>(resolvedVectors);
        sorted.sort(Comparator.comparingInt(Target::vectorNumber));
        Set<Integer> slots = new HashSet<>();
        for (Target target : sorted) {
            if (target == null || !slots.add(target.vectorNumber()))
                throw new IllegalArgumentException("Duplicate or null vector target");
        }
        int exact = 0, shared = 0, outside = 0, interior = 0;
        List<Row> rows = new ArrayList<>();
        for (Target target : sorted) {
            Relation relation;
            HardwareCallEffects.Summary effects = null;
            if (!target.exactEntry()) {
                interior++;
                relation = Relation.INTERIOR_FUNCTION_POINTER_NOT_ENTRY;
            } else {
                exact++;
                if (!resetRootRecognized) {
                    relation = Relation.RESET_ROOT_UNKNOWN;
                } else if (resetVisited.contains(target.functionEntry())) {
                    relation = Relation.IN_RESET_STATIC_CALL_SUBSET;
                    shared++;
                } else {
                    relation = Relation.OUTSIDE_OBSERVED_RESET_SUBSET;
                    outside++;
                }
                effects = HardwareCallEffects.summarize(
                    target.functionEntry(), graph, 4, 100);
            }
            if (rows.size() < maxRows)
                rows.add(new Row(target.vectorNumber(), target.pointer(),
                    target.functionEntry(), relation,
                    effect(effects != null && effects.possibleMemoryStore(), effects),
                    effect(effects != null && effects.possibleVbrWrite(), effects),
                    effects == null || effects.unresolved() || effects.truncated()));
        }
        return new Summary(resetRootRecognized, resetGraphIncomplete,
            sorted.size(), exact, shared, outside, interior,
            rows.size() < sorted.size(), rows);
    }
}
