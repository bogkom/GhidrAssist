package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * GA-01/02/03/11: compare image-zero vector POINTER CANDIDATES with the
 * bounded RESET direct-call subset and read-only transitive STORE/VBR clues.
 * Neither membership nor absence proves execution, IRQ activity or a VBR.
 */
public final class HardwareVectorResetCorrelation {
    private HardwareVectorResetCorrelation() {}
    public static final int MAX_RECOGNIZED_VECTOR_TARGETS=254;

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
                    // An interior pointer can only be inside a function
                    // whose entry precedes that pointer; a later entry is
                    // not evidence of a containing function.
                    (!exactEntry && functionEntry >= pointer) ||
                    exactEntry != (pointer == functionEntry))
                throw new IllegalArgumentException("Invalid recognized vector target");
        }
    }

    public record Row(int vectorNumber, long pointer, long functionEntry,
                      Relation relation, String memoryStoreEffect,
                      String vbrEffect, boolean flowUncertain,
                      String storeSourcePath,String vbrSourcePath,
                      String observedUnknownPath,String frontierPath) {
        /** Preserve the original seven-field vector row constructor. */
        public Row(int vectorNumber,long pointer,long functionEntry,
                Relation relation,String memoryStoreEffect,String vbrEffect,
                boolean flowUncertain) {
            this(vectorNumber,pointer,functionEntry,relation,
                memoryStoreEffect,vbrEffect,flowUncertain,
                "NONE","NONE","NONE","NONE");
        }
        public Row {
            if(relation==null || memoryStoreEffect==null ||
                    vbrEffect==null || storeSourcePath==null ||
                    vbrSourcePath==null || observedUnknownPath==null ||
                    frontierPath==null)
                throw new IllegalArgumentException("Missing vector source evidence");
        }
    }

    public record Summary(boolean relocatedSource, long tableAddress,
                          boolean resetRootRecognized, boolean resetGraphIncomplete,
                          int recognizedTargets, int exactEntries,
                          int sharedResetSubset, int outsideObservedSubset,
                          int interiorPointers, boolean displayTruncated,
                          List<Row> rows) {
        public Summary {
            if(tableAddress<0 || (tableAddress&3)!=0 ||
                    relocatedSource && tableAddress>0xffffffL-1023L ||
                    !relocatedSource && tableAddress!=0)
                throw new IllegalArgumentException("Invalid vector source table");
            rows = List.copyOf(rows);
        }

        public String markdown() {
            StringBuilder out = new StringBuilder();
            out.append("## Vector / RESET static-call relation candidates (GA-01/02/03/11)\n\n")
               .append("- Vector table input: ")
               .append(relocatedSource?
                   "relocated MOVEC-to-VBR source-image candidate at "+hex(tableAddress)+
                   " (not an active VBR)":
                   "image-zero bytes ONLY")
               .append("; runtime VBR and IRQ activation UNKNOWN. RESET function recognized: ")
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
               .append("- Typed direct-CALL source paths start at each exact ")
               .append("vector handler entry and identify the shortest ")
               .append("observed candidate STORE/MOVEC function, actually ")
               .append("missing/unknown-flow source, or an independently ")
               .append("uninspected depth/node frontier. NONE does not ")
               .append("prove absence of unmodeled effects. Cycle-only ")
               .append("uncertainty never fabricates a missing CALL. ")
               .append("Paths are not instruction PCs or runtime flows.\n")
               .append("- **STATIC ONLY**: an exception-vector pointer and a ")
               .append("RESET direct-call connection do NOT demonstrate active ")
               .append("VBR, interrupt execution, branch feasibility, first SIMCR ")
               .append("write, latched MM, ISR entry or a physical CS map.\n\n");
            if (rows.isEmpty()) {
                out.append("- No recognized vector-function targets in this bounded ")
                   .append(relocatedSource?
                       "relocated source-image inventory":
                       "image-zero inventory")
                   .append("; not proof of no exceptions.\n\n");
                return out.toString();
            }
            out.append(relocatedSource?
                    "| Vector | Relocated source-image pointer | Containing function | ":
                    "| Vector | Image-zero pointer | Containing function | ")
               .append("RESET relation | Memory STORE in static call subtree | ")
               .append("VBR in static call subtree | Flow uncertainty | ")
               .append("STORE source function path | MOVEC source function path | ")
               .append("Observed unknown or missing function path | ")
               .append("Uninspected depth/node frontier path |\n")
               .append("|---|---|---|---|---|---|---|---|---|---|---|\n");
            for (Row row : rows) {
                out.append("| ").append(row.vectorNumber()).append(" | ")
                   .append(hex(row.pointer())).append(" | ")
                   .append(hex(row.functionEntry())).append(" | ")
                   .append(row.relation()).append(" | ")
                   .append(row.memoryStoreEffect()).append(" | ")
                   .append(row.vbrEffect()).append(" | ")
                   .append(row.flowUncertain()).append(" | ")
                   .append(row.storeSourcePath()).append(" | ")
                   .append(row.vbrSourcePath()).append(" | ")
                   .append(row.observedUnknownPath()).append(" | ")
                   .append(row.frontierPath()).append(" |\n");
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

    private static String witness(HardwareCallEffects.SourceWitness source) {
        if(source==null)return "NONE";
        StringBuilder out=new StringBuilder(source.kind().name());
        // A deep generic direct-CALL survey may have many nodes; the
        // rendered vector correlation uses a max-depth of only four.
        // Keep public rendering bounded even for forged long reports.
        int shown=Math.min(source.chain().size(),16);
        for(int i=0;i<shown;i++)
            out.append(" -> ").append(hex(source.chain().get(i)));
        if(shown<source.chain().size())
            out.append(" -> ... ").append(source.chain().size()-shown)
                .append(" omitted source entries (not an exact full path)");
        return out.toString();
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
        return inspectSource(false,0,resetRootRecognized,resetGraphIncomplete,
            resetVisited,resolvedVectors,graph,maxRows);
    }

    /**
     * Same bounded static correlation, but the vector words came from a
     * candidate MOVEC-to-VBR source-image table, not the image-zero inventory.
     * A mapped handler still does not establish executed MOVEC or active IRQ.
     */
    public static Summary inspectRelocated(long sourceBase,
            boolean resetRootRecognized, boolean resetGraphIncomplete,
            Set<Long> resetVisited, List<Target> resolvedVectors,
            Collection<HardwareCallEffects.FunctionNode> graph,int maxRows) {
        if(sourceBase<0 || (sourceBase&3)!=0 ||
                sourceBase>0xffffffL-1023L)
            throw new IllegalArgumentException("Invalid relocated VBR source base");
        return inspectSource(true,sourceBase,resetRootRecognized,
            resetGraphIncomplete,resetVisited,resolvedVectors,graph,maxRows);
    }

    private static Summary inspectSource(boolean relocatedSource,long sourceBase,
            boolean resetRootRecognized,boolean resetGraphIncomplete,
            Set<Long> resetVisited,List<Target> resolvedVectors,
            Collection<HardwareCallEffects.FunctionNode> graph,int maxRows) {
        if (resetVisited == null || resolvedVectors == null || graph == null ||
                maxRows < 1 || maxRows > 64 ||
                resolvedVectors.size()>MAX_RECOGNIZED_VECTOR_TARGETS ||
                resetVisited.size()>HardwareCallEffects.MAX_SOURCE_FUNCTIONS ||
                graph.size()>HardwareCallEffects.MAX_SOURCE_FUNCTIONS)
            throw new IllegalArgumentException("Invalid bounded vector/reset correlation input");
        for(Long id:resetVisited)
            if(id==null || id<0)
                throw new IllegalArgumentException("Invalid RESET source entry");
        for(Target target:resolvedVectors)
            if(target==null)
                throw new IllegalArgumentException("Null vector candidate");
        List<Target> sorted = new ArrayList<>(resolvedVectors);
        sorted.sort(Comparator.comparingInt(Target::vectorNumber));
        Set<Integer> slots = new HashSet<>();
        for (Target target : sorted) {
            if (target == null || !slots.add(target.vectorNumber()))
                throw new IllegalArgumentException("Duplicate or null vector target");
        }
        int exact = 0, shared = 0, outside = 0, interior = 0;
        // Multiple vector slots may point to the same exact handler. The
        // transitive STORE/VBR effect is read-only and depends on the target,
        // not on the candidate vector number. Cache only in this call.
        Map<Long,HardwareCallEffects.Detailed> effectsByEntry=new HashMap<>();
        List<Row> rows = new ArrayList<>();
        for (Target target : sorted) {
            Relation relation;
            HardwareCallEffects.Detailed detail = null;
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
            }
            if (rows.size() < maxRows) {
                // Only the displayed exact-entry slots need detailed
                // effects; numeric vector relation totals cover all slots.
                // Multiple slots sharing one handler reuse a single
                // in-memory, revision-local source audit.
                if(target.exactEntry())
                    detail=effectsByEntry.computeIfAbsent(target.functionEntry(),
                        entry->HardwareCallEffects.inspect(entry,graph,4,100));
                HardwareCallEffects.Summary effects=detail==null?
                    null:detail.summary();
                rows.add(new Row(target.vectorNumber(), target.pointer(),
                    target.functionEntry(), relation,
                    effect(effects != null && effects.possibleMemoryStore(), effects),
                    effect(effects != null && effects.possibleVbrWrite(), effects),
                    // RESET scope and target-local source evidence are
                    // independent unknown horizons.
                    !resetRootRecognized || resetGraphIncomplete ||
                    effects == null || effects.unresolved() || effects.truncated(),
                    witness(detail==null?null:detail.storeWitness()),
                    witness(detail==null?null:detail.vbrWitness()),
                    witness(detail==null?null:detail.observedUnknownWitness()),
                    witness(detail==null?null:detail.frontierWitness())));
            }
        }
        return new Summary(relocatedSource,sourceBase,
            resetRootRecognized,resetGraphIncomplete,sorted.size(), exact,
            shared, outside, interior,rows.size() < sorted.size(), rows);
    }
}
