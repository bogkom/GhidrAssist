package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * GA-02/03/11: static-only SIMCR/MM source candidates below exact vector
 * function entries for an explicitly selected MC68332. A vector pointer
 * does NOT create a CALL/ISR edge, VBR selection or runtime MM write.
 */
public final class HardwareVectorMmMayCorrelation {
    private HardwareVectorMmMayCorrelation() {}
    public static final int MAX_ROWS=32;
    public static final int MAX_ROOT_DEPTH=4;
    public static final int MAX_ROOT_NODES=100;
    private static final long MCU_MAX=0xffffffL;

    public record Row(int vectorNumber,long pointer,long functionEntry,
            HardwareVectorResetCorrelation.Relation resetRelation,
            boolean resetRelationUncertain,String mmLowByte,
            boolean unknownAlias,boolean unknownControl,
            boolean cycle,boolean limited,int examined,
            String mmSource,String aliasSource,String observedUnknownSource,
            String frontierSource) {
        public Row {
            if(vectorNumber<2 || vectorNumber>255 || pointer<=0 ||
                    pointer>MCU_MAX || (pointer&1)!=0 ||
                    functionEntry!=pointer || resetRelation==null ||
                    mmLowByte==null || mmSource==null || aliasSource==null ||
                    observedUnknownSource==null || frontierSource==null ||
                    examined<0 || examined>MAX_ROOT_NODES ||
                    !List.of("STATIC_MAY_MM_LOW_BYTE", "UNKNOWN",
                        "NOT_OBSERVED_IN_BOUNDED_SOURCE").contains(mmLowByte))
                throw new IllegalArgumentException("Invalid vector MM source row");
            boolean may=mmLowByte.equals("STATIC_MAY_MM_LOW_BYTE");
            boolean uncertain=unknownAlias || unknownControl || cycle || limited;
            if(resetRelation==HardwareVectorResetCorrelation.Relation.RESET_ROOT_UNKNOWN
                    && !resetRelationUncertain ||
                    may==mmSource.equals("NONE") ||
                    unknownAlias==aliasSource.equals("NONE") ||
                    limited==frontierSource.equals("NONE") ||
                    cycle && !unknownControl ||
                    limited && !unknownControl ||
                    !unknownControl && !observedUnknownSource.equals("NONE") ||
                    mmLowByte.equals("UNKNOWN")!=(!may && uncertain) ||
                    !validWitness(mmSource,functionEntry,"MM_SOURCE") ||
                    !validWitness(aliasSource,functionEntry,"STORE_ALIAS") ||
                    !validWitness(observedUnknownSource,functionEntry,
                        "UNKNOWN_FLOW","MISSING_TARGET") ||
                    !validWitness(frontierSource,functionEntry,
                        "DEPTH_CUTOFF","NODE_CUTOFF","BATCH_CUTOFF"))
                throw new IllegalArgumentException(
                    "Contradictory or unbounded vector MM evidence");
        }
        /** Uncertainty in the handler's MM source tree, not its RESET relation. */
        public boolean mmEvidenceUncertain() {
            return unknownAlias || unknownControl || cycle || limited;
        }
    }
    public record Report(boolean relocated,long tableBase,
            boolean resetRecognized,boolean resetIncomplete,
            int recognizedTargets,int exactEntries,int interiorPointers,
            int distinctShownRoots,boolean displayTruncated,List<Row> rows) {
        public Report {
            if(tableBase<0 || (tableBase&3)!=0 ||
                    relocated && tableBase>MCU_MAX-1023 ||
                    !relocated && tableBase!=0 ||
                    recognizedTargets<0 ||
                    recognizedTargets>HardwareVectorResetCorrelation.MAX_RECOGNIZED_VECTOR_TARGETS ||
                    exactEntries<0 || interiorPointers<0 ||
                    exactEntries+interiorPointers!=recognizedTargets ||
                    rows==null ||
                    distinctShownRoots<0 || distinctShownRoots>rows.size() ||
                    rows.size()>MAX_ROWS ||
                    rows.stream().anyMatch(java.util.Objects::isNull) ||
                    rows.size()>exactEntries ||
                    exactEntries>0 && rows.isEmpty() ||
                    displayTruncated!=(rows.size()<exactEntries))
                throw new IllegalArgumentException("Inconsistent vector MM report");
            Set<Long> uniqueRoots=new HashSet<>();
            int previousSlot=1;
            for(Row row:rows) {
                if(row.vectorNumber()<=previousSlot ||
                        resetRecognized &&
                        row.resetRelation()==
                            HardwareVectorResetCorrelation.Relation.RESET_ROOT_UNKNOWN ||
                        !resetRecognized &&
                        row.resetRelation()!=
                            HardwareVectorResetCorrelation.Relation.RESET_ROOT_UNKNOWN ||
                        row.resetRelationUncertain()!=
                            (!resetRecognized || resetIncomplete))
                    throw new IllegalArgumentException(
                        "Contradictory vector MM report row");
                previousSlot=row.vectorNumber();
                uniqueRoots.add(row.functionEntry());
            }
            if(uniqueRoots.size()!=distinctShownRoots)
                throw new IllegalArgumentException(
                    "Incorrect distinct inspected handler count");
            rows=List.copyOf(rows);
        }
        public long displayedMay() {
            return rows.stream().filter(r->
                r.mmLowByte().equals("STATIC_MAY_MM_LOW_BYTE")).count();
        }
        public long displayedUnknown() {
            return rows.stream().filter(r->
                r.mmLowByte().equals("UNKNOWN")).count();
        }
        public long displayedNoObservation() {
            return rows.stream().filter(r->
                r.mmLowByte().equals("NOT_OBSERVED_IN_BOUNDED_SOURCE")).count();
        }
        public String markdown() {
            StringBuilder out=new StringBuilder(
                "## MC68332 vector-handler SIMCR/MM low-byte MAY sources (GA-02/03/11)\n\n")
                .append("- **STATIC SOURCE ONLY; explicit MC68332 profile required**. ")
                .append("Vector bytes come from ")
                .append(relocated?"a relocated MOVEC-to-VBR source-image candidate at "+
                    hex(tableBase):"image-zero")
                .append("; neither source is proof of an active VBR or an ")
                .append("executed ISR. No vector pointer is added as a CALL edge.\n")
                .append("- Recognized vector pointers: ").append(recognizedTargets)
                .append("; exact function entries: ").append(exactEntries)
                .append("; interior pointers (not analyzed as complete handlers): ")
                .append(interiorPointers)
                .append("; distinct analyzed exact roots in displayed rows: ")
                .append(distinctShownRoots)
                .append("; displayed exact rows: ").append(rows.size())
                .append("; undisplayed exact rows: ").append(exactEntries-rows.size())
                .append("; DISPLAYED-ONLY MM classifications (not whole table): MAY=")
                .append(displayedMay()).append(", UNKNOWN=")
                .append(displayedUnknown()).append(", NOT_OBSERVED=")
                .append(displayedNoObservation())
                .append("; RESET root recognized: ").append(resetRecognized)
                .append("; RESET direct-CALL graph incomplete: ")
                .append(resetIncomplete).append(".\n")
                .append("- MAY MM is a bounded potential STORE that overlaps the ")
                .append("selected-device SIMCR/MM low byte. MM0/MM1 are ")
                .append("conditional alternatives, NOT a latched first-write ")
                .append("value. Unknown alias/width, missing call targets, ")
                .append("computed flow and depth/node/batch cutoffs remain ")
                .append("UNKNOWN. Source paths are function-entry chains ")
                .append("rooted at the exact vector handler, not decoded ")
                .append("instruction traces or executed calls. NONE is ")
                .append("not proof of no MM effect. RESET relationship ")
                .append("is separately bounded, not execution order. ")
                .append("RESET relation uncertainty describes ONLY RESET ")
                .append("root/graph completeness; handler MM source uncertainty ")
                .append("is a different evidence horizon.\n");
            if(displayTruncated)
                out.append("- **INCOMPLETE VECTOR DISPLAY:** omitted exact handlers ")
                    .append("were not analyzed for MM source effects.\n");
            if(rows.isEmpty())
                return out.append("- No displayed exact handler source. ")
                    .append("This does not prove absent MMIO or interrupts.\n\n").toString();
            out.append("\n| Vector | Source-image pointer | RESET relation | ")
                .append("RESET uncertain | SIMCR/MM MAY | MM source uncertain | ")
                .append("Alias/width unknown | ")
                .append("Unknown control | Cycle | Limited | Inspected functions | ")
                .append("MM source function chain | Alias function chain | ")
                .append("Observed unknown/missing chain | Uninspected frontier chain |\n")
                .append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
            for(Row row:rows)
                out.append("| ").append(row.vectorNumber())
                    .append(" | ").append(hex(row.pointer()))
                    .append(" | ").append(row.resetRelation())
                    .append(" | ").append(row.resetRelationUncertain())
                    .append(" | ").append(row.mmLowByte())
                    .append(" | ").append(row.mmEvidenceUncertain())
                    .append(" | ").append(row.unknownAlias())
                    .append(" | ").append(row.unknownControl())
                    .append(" | ").append(row.cycle())
                    .append(" | ").append(row.limited())
                    .append(" | ").append(row.examined())
                    .append(" | ").append(row.mmSource())
                    .append(" | ").append(row.aliasSource())
                    .append(" | ").append(row.observedUnknownSource())
                    .append(" | ").append(row.frontierSource())
                    .append(" |\n");
            return out.append("\n").toString();
        }
    }
    private static String hex(long id) {
        return String.format(Locale.ROOT,"0x%08X",id);
    }
    /** Fail closed on injected text, unbounded or cross-root source paths. */
    private static boolean validWitness(String value,long root,String... kinds) {
        if("NONE".equals(value))return true;
        String[] parts=value.split(" -> ",-1);
        if(parts.length<2 || parts.length>MAX_ROOT_DEPTH+3 ||
                !List.of(kinds).contains(parts[0]) ||
                !parts[1].equals(hex(root)))return false;
        for(int i=1;i<parts.length;i++)
            if(!parts[i].matches("0x[0-9A-F]{8,16}"))return false;
        return true;
    }
    private static String witness(
            HardwareInterproceduralMmEffects.SourceWitness path) {
        if(path==null)return "NONE";
        StringBuilder result=new StringBuilder(path.kind().name());
        for(long id:path.chain())result.append(" -> ").append(hex(id));
        return result.toString();
    }
    private static String observed(
            HardwareInterproceduralMmEffects.Summary s) {
        var path=s.unknownWitness();
        return path!=null &&
            (path.kind()==HardwareInterproceduralMmEffects.WitnessKind.UNKNOWN_FLOW ||
                path.kind()==HardwareInterproceduralMmEffects.WitnessKind.MISSING_TARGET)?
            witness(path):"NONE";
    }
    private static String mmClass(HardwareInterproceduralMmEffects.Summary s) {
        return s.mayMm()?"STATIC_MAY_MM_LOW_BYTE":
            s.uncertainOrMm()?"UNKNOWN":"NOT_OBSERVED_IN_BOUNDED_SOURCE";
    }
    public static Report inspect(boolean relocated,long tableBase,
            boolean resetRecognized,boolean resetIncomplete,
            Set<Long> resetVisited,
            List<HardwareVectorResetCorrelation.Target> vectorTargets,
            Collection<HardwareInterproceduralMmEffects.FunctionNode> graph,
            int maxRows) {
        if(resetVisited==null || vectorTargets==null || graph==null ||
                maxRows<1 || maxRows>MAX_ROWS ||
                vectorTargets.size()>HardwareVectorResetCorrelation.MAX_RECOGNIZED_VECTOR_TARGETS ||
                resetVisited.size()>HardwareCallEffects.MAX_SOURCE_FUNCTIONS ||
                tableBase<0 || (tableBase&3)!=0 ||
                relocated && tableBase>MCU_MAX-1023 ||
                !relocated && tableBase!=0)
            throw new IllegalArgumentException("Invalid bounded vector MM source inventory");
        for(Long entry:resetVisited)
            if(entry==null || entry<0 || entry>MCU_MAX || (entry&1)!=0)
                throw new IllegalArgumentException("Invalid selected-MCU RESET entry");
        List<HardwareVectorResetCorrelation.Target> sorted=new ArrayList<>(vectorTargets);
        if(sorted.contains(null))
            throw new IllegalArgumentException("Null vector source");
        sorted.sort(Comparator.comparingInt(
            HardwareVectorResetCorrelation.Target::vectorNumber));
        Set<Integer> slots=new HashSet<>();
        Set<Long> selectedRoots=new HashSet<>();
        int exact=0,interior=0;
        List<HardwareVectorResetCorrelation.Target> displayed=new ArrayList<>();
        for(var target:sorted) {
            if(!slots.add(target.vectorNumber()) ||
                    target.pointer()>MCU_MAX ||
                    target.functionEntry()>MCU_MAX)
                throw new IllegalArgumentException(
                    "Duplicate or out-of-range MC68332 vector source");
            if(!target.exactEntry()) {
                interior++;
                continue;
            }
            exact++;
            if(displayed.size()<maxRows) {
                displayed.add(target);
                selectedRoots.add(target.functionEntry());
            }
        }
        // No fabricated CALL-site PC or inferred ISR edge. Every root is
        // independently obtained from an exact source-image pointer.
        // One finite batch budget and immutable per-report root cache.
        Map<Long,HardwareInterproceduralMmEffects.Summary> sources=
            HardwareInterproceduralMmEffects.inspectRoots(
                graph,selectedRoots,MAX_ROOT_DEPTH,MAX_ROOT_NODES);
        List<Row> rows=new ArrayList<>();
        for(var target:displayed) {
            long root=target.functionEntry();
            var s=sources.get(root);
            var relation=!resetRecognized?
                HardwareVectorResetCorrelation.Relation.RESET_ROOT_UNKNOWN:
                resetVisited.contains(root)?
                    HardwareVectorResetCorrelation.Relation.IN_RESET_STATIC_CALL_SUBSET:
                    HardwareVectorResetCorrelation.Relation.OUTSIDE_OBSERVED_RESET_SUBSET;
            rows.add(new Row(target.vectorNumber(),target.pointer(),root,
                relation,!resetRecognized || resetIncomplete,
                mmClass(s),s.unknownAlias(),s.unknownControl(),s.cycle(),s.limited(),
                s.visited(),witness(s.mmWitness()),witness(s.aliasWitness()),
                observed(s),witness(s.frontierWitness())));
        }
        return new Report(relocated,tableBase,resetRecognized,resetIncomplete,
            sorted.size(),exact,interior,sources.size(),displayed.size()<exact,rows);
    }
}
