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
            // The generic CPU32 source inventory remains 32-bit; these are
            // candidate function identities, not selected-MC68332 addresses.
            new Target(vectorNumber,pointer,functionEntry,pointer==functionEntry);
            if(relation==null || memoryStoreEffect==null ||
                    vbrEffect==null || storeSourcePath==null ||
                    vbrSourcePath==null || observedUnknownPath==null ||
                    frontierPath==null ||
                    !validEffect(memoryStoreEffect) || !validEffect(vbrEffect) ||
                    !validPath(storeSourcePath,functionEntry,"MEMORY_STORE") ||
                    !validPath(vbrSourcePath,functionEntry,"MOVEC_VBR") ||
                    !validPath(observedUnknownPath,functionEntry,
                        "UNKNOWN_FLOW","MISSING_TARGET") ||
                    !validPath(frontierPath,functionEntry,
                        "DEPTH_CUTOFF","NODE_CUTOFF") ||
                    !storeSourcePath.equals("NONE") &&
                        !memoryStoreEffect.equals("STATIC_CANDIDATE") ||
                    !vbrSourcePath.equals("NONE") &&
                        !vbrEffect.equals("STATIC_CANDIDATE") ||
                    !observedUnknownPath.equals("NONE") && !flowUncertain ||
                    !frontierPath.equals("NONE") && !flowUncertain ||
                    relation==Relation.RESET_ROOT_UNKNOWN && !flowUncertain ||
                    relation==Relation.INTERIOR_FUNCTION_POINTER_NOT_ENTRY &&
                        (pointer==functionEntry ||
                         !memoryStoreEffect.equals("UNKNOWN") ||
                         !vbrEffect.equals("UNKNOWN") ||
                         !storeSourcePath.equals("NONE") ||
                         !vbrSourcePath.equals("NONE") ||
                         !observedUnknownPath.equals("NONE") ||
                         !frontierPath.equals("NONE") ||
                         !flowUncertain) ||
                    relation!=Relation.INTERIOR_FUNCTION_POINTER_NOT_ENTRY &&
                        pointer!=functionEntry ||
                    !flowUncertain &&
                        (memoryStoreEffect.equals("UNKNOWN") ||
                         vbrEffect.equals("UNKNOWN")))
                throw new IllegalArgumentException(
                    "Contradictory or unbounded vector/RESET evidence row");
        }
    }

    public record Summary(boolean relocatedSource, long tableAddress,
                          boolean resetRootRecognized, boolean resetGraphIncomplete,
                          int recognizedTargets, int exactEntries,
                          int sharedResetSubset, int outsideObservedSubset,
                          int interiorPointers, boolean displayTruncated,
                          List<Row> rows, int distinctExactHandlers, int handlerAliasSlots) {
        /** Legacy displayed-only constructor; full totals must be supplied by inspectSource. */
        public Summary(boolean relocatedSource,long tableAddress,boolean resetRootRecognized,
                boolean resetGraphIncomplete,int recognizedTargets,int exactEntries,
                int sharedResetSubset,int outsideObservedSubset,int interiorPointers,
                boolean displayTruncated,List<Row> rows) {
            this(relocatedSource,tableAddress,resetRootRecognized,resetGraphIncomplete,
                recognizedTargets,exactEntries,sharedResetSubset,outsideObservedSubset,
                interiorPointers,displayTruncated,rows,
                (int)rows.stream().filter(r->r.relation()!=Relation.INTERIOR_FUNCTION_POINTER_NOT_ENTRY)
                    .map(Row::functionEntry).distinct().count(),
                (int)rows.stream().filter(r->r.relation()!=Relation.INTERIOR_FUNCTION_POINTER_NOT_ENTRY).count()-
                    (int)rows.stream().filter(r->r.relation()!=Relation.INTERIOR_FUNCTION_POINTER_NOT_ENTRY)
                    .map(Row::functionEntry).distinct().count());
        }
        public Summary {
            if(tableAddress<0 || (tableAddress&3)!=0 ||
                    relocatedSource && tableAddress>0xffffffL-1023L ||
                    !relocatedSource && tableAddress!=0 || rows==null ||
                    recognizedTargets<0 ||
                    recognizedTargets>MAX_RECOGNIZED_VECTOR_TARGETS ||
                    exactEntries<0 || interiorPointers<0 ||
                    exactEntries+interiorPointers!=recognizedTargets ||
                    sharedResetSubset<0 || outsideObservedSubset<0 ||
                    resetRootRecognized &&
                        sharedResetSubset+outsideObservedSubset!=exactEntries ||
                    !resetRootRecognized &&
                        (sharedResetSubset!=0 || outsideObservedSubset!=0) ||
                    rows.size()>64 || rows.size()>recognizedTargets ||
                    distinctExactHandlers<0 || distinctExactHandlers>exactEntries ||
                    handlerAliasSlots<0 || distinctExactHandlers+handlerAliasSlots!=exactEntries ||
                    recognizedTargets>0 && rows.isEmpty() ||
                    displayTruncated!=(rows.size()<recognizedTargets) ||
                    rows.stream().anyMatch(java.util.Objects::isNull))
                throw new IllegalArgumentException(
                    "Inconsistent bounded vector/RESET source inventory");
            int last=1,shownExact=0,shownInterior=0,shownShared=0,
                shownOutside=0;
            // Every slot pointing at one exact handler is audited once.
            // Publicly constructed summaries must not give that same
            // function contradictory source evidence in different slots.
            Map<Long,Row> byHandler=new HashMap<>();
            for(Row row:rows) {
                if(row.relation()!=Relation.INTERIOR_FUNCTION_POINTER_NOT_ENTRY) {
                    Row prior=byHandler.putIfAbsent(row.functionEntry(),row);
                    if(prior!=null && !sameHandlerEvidence(prior,row))
                        throw new IllegalArgumentException(
                            "Conflicting source evidence for shared vector handler");
                }
                if(row.vectorNumber()<=last ||
                        row.flowUncertain() != true &&
                            (!resetRootRecognized || resetGraphIncomplete))
                    throw new IllegalArgumentException(
                        "Noncanonical vector slots or false RESET certainty");
                last=row.vectorNumber();
                switch(row.relation()){
                    case INTERIOR_FUNCTION_POINTER_NOT_ENTRY -> shownInterior++;
                    case IN_RESET_STATIC_CALL_SUBSET -> {
                        if(!resetRootRecognized)throw new IllegalArgumentException(
                            "Unrecognized RESET cannot have a call-subset row");
                        shownExact++;shownShared++;
                    }
                    case OUTSIDE_OBSERVED_RESET_SUBSET -> {
                        if(!resetRootRecognized)throw new IllegalArgumentException(
                            "Unrecognized RESET cannot exclude a vector root");
                        shownExact++;shownOutside++;
                    }
                    case RESET_ROOT_UNKNOWN -> {
                        if(resetRootRecognized)throw new IllegalArgumentException(
                            "Recognized RESET cannot have unknown root rows");
                        shownExact++;
                    }
                }
            }
            if(shownExact>exactEntries || shownInterior>interiorPointers ||
                    byHandler.size()>distinctExactHandlers ||
                    shownShared>sharedResetSubset ||
                    shownOutside>outsideObservedSubset)
                throw new IllegalArgumentException(
                    "Displayed row evidence exceeds full-vector inventory");
            rows = List.copyOf(rows);
        }
        /** Distinct exact-entry handlers among displayed rows only. */
        public long displayedDistinctExactHandlers() {
            return rows.stream()
                .filter(r -> r.relation()!=Relation.INTERIOR_FUNCTION_POINTER_NOT_ENTRY)
                .map(Row::functionEntry).distinct().count();
        }
        /** Additional vector slots sharing displayed exact-entry handlers. */
        public long displayedHandlerAliasSlots() {
            return rows.stream()
                .filter(r -> r.relation()!=Relation.INTERIOR_FUNCTION_POINTER_NOT_ENTRY)
                .count() - displayedDistinctExactHandlers();
        }
        public long displayedStoreCandidates() {
            return rows.stream().filter(r->r.relation()!=
                Relation.INTERIOR_FUNCTION_POINTER_NOT_ENTRY &&
                r.memoryStoreEffect().equals("STATIC_CANDIDATE")).count();
        }
        public long displayedVbrCandidates() {
            return rows.stream().filter(r->r.relation()!=
                Relation.INTERIOR_FUNCTION_POINTER_NOT_ENTRY &&
                r.vbrEffect().equals("STATIC_CANDIDATE")).count();
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
               .append(interiorPointers)
               .append("; displayed rows: ").append(rows.size())
               .append("; omitted rows: ").append(recognizedTargets-rows.size())
               .append("; FULL distinct exact handlers: ").append(distinctExactHandlers)
               .append("; FULL repeated exact-handler slots: ").append(handlerAliasSlots)
               .append("; DISPLAYED-ONLY distinct exact handlers: ")
               .append(displayedDistinctExactHandlers())
               .append("; DISPLAYED-ONLY repeated exact-handler slots: ")
               .append(displayedHandlerAliasSlots())
               .append("; DISPLAYED-ONLY STORE candidate vector rows: ")
               .append(displayedStoreCandidates())
               .append("; DISPLAYED-ONLY MOVEC/VBR candidate vector rows: ")
               .append(displayedVbrCandidates()).append(".\n")
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
                out.append("- Rows truncated by display cap; displayed-only handler counts ")
                   .append("may omit aliases beyond the display cap; numeric totals cover ")
                   .append("all recognized vector-function pointers.\n");
            return out.append("\n").toString();
        }
    }

    private static boolean sameHandlerEvidence(Row a,Row b) {
        return a.pointer()==b.pointer() && a.relation()==b.relation() &&
            a.memoryStoreEffect().equals(b.memoryStoreEffect()) &&
            a.vbrEffect().equals(b.vbrEffect()) &&
            a.flowUncertain()==b.flowUncertain() &&
            a.storeSourcePath().equals(b.storeSourcePath()) &&
            a.vbrSourcePath().equals(b.vbrSourcePath()) &&
            a.observedUnknownPath().equals(b.observedUnknownPath()) &&
            a.frontierPath().equals(b.frontierPath());
    }

    private static String hex(long value) {
        return String.format(Locale.ROOT, "0x%08X", value);
    }

    private static boolean validEffect(String effect) {
        return effect.equals("STATIC_CANDIDATE") || effect.equals("UNKNOWN") ||
            effect.equals("NOT_OBSERVED_IN_BOUNDED_GRAPH");
    }
    /** Public report records may not bypass the bounded source path renderer. */
    private static boolean validPath(String value,long root,String... kinds) {
        if("NONE".equals(value))return true;
        // Guard the string before splitting it into untrusted path fragments.
        if(value.length()>160)return false;
        String[] parts=value.split(" -> ",-1);
        if(parts.length<2 || parts.length>7 ||
                !List.of(kinds).contains(parts[0]) ||
                !parts[1].equals(hex(root)))return false;
        for(int i=1;i<parts.length;i++)
            if(!parts[i].matches("0x[0-9A-F]{8}"))return false;
        return true;
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
        Set<Long> fullExactHandlers = new HashSet<>();
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
                fullExactHandlers.add(target.functionEntry());
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
            shared, outside, interior,rows.size() < sorted.size(), rows,
            fullExactHandlers.size(), exact-fullExactHandlers.size());
    }
}
