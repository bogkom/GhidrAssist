package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Read-only, source-only SIMCR/MM MAY classification for already byte-proven
 * CPU32 register-indirect JSR witnesses. Never insert a direct graph edge.
 * Unknown aliases, source graph gaps and finite budgets stay uncertain.
 */
public final class HardwareIndirectMmMay {
    private HardwareIndirectMmMay() {}
    public static final int MAX_ROWS=HardwareIndirectMayEffects.MAX_ROWS;
    private static final int MAX_DEPTH=4;
    private static final int MAX_FUNCTIONS=100;

    public record Row(HardwareIndirectCallEvidence.Site witness,
                      HardwareInterproceduralMmEffects.Summary source) {
        public Row {
            if(witness==null || source==null || source.visited()<0)
                throw new IllegalArgumentException("Invalid indirect MM source row");
            // This report is rooted at a byte-verified computed target.
            // The shared CALL-site solver records function-only descendants
            // starting at that target, NEVER the caller's instruction PC.
            // Reject a synthetic/mismatched witness even if its flags look
            // plausible; such data must not be published as source proof.
            var witnesses=new HardwareInterproceduralMmEffects.SourceWitness[]{
                source.mmWitness(),source.aliasWitness(),
                source.unknownWitness(),source.frontierWitness()};
            for(var path:witnesses)
                if(path!=null && path.chain().get(0)!=witness.target())
                    throw new IllegalArgumentException(
                        "Indirect source chain belongs to another target");
        }
    }
    public record Report(int totalWitnesses,int omittedWitnesses,List<Row> rows) {
        public Report {
            if(rows==null || rows.size()>MAX_ROWS || rows.contains(null) ||
                    totalWitnesses<0 ||
                    totalWitnesses>HardwareIndirectCallEvidence.MAX_SITES ||
                    omittedWitnesses<0 ||
                    totalWitnesses!=rows.size()+omittedWitnesses)
                throw new IllegalArgumentException("Invalid MAY source counts");
            Set<Long> pcs=new HashSet<>();
            for(Row row:rows)
                if(!pcs.add(row.witness().callPc()))
                    throw new IllegalArgumentException(
                        "Duplicate computed JSR source PC in report");
            rows=List.copyOf(rows);
        }
        private static String hex(long value) {
            return String.format(Locale.ROOT,"0x%08X",value);
        }
        private static String witness(
                HardwareInterproceduralMmEffects.SourceWitness path) {
            if(path==null)return "NONE";
            StringBuilder out=new StringBuilder(path.kind().name());
            for(long entry:path.chain())
                out.append(" -> ").append(hex(entry));
            return out.toString();
        }
        private static String observedUnknown(
                HardwareInterproceduralMmEffects.Summary effect) {
            var path=effect.unknownWitness();
            if(path==null ||
                    path.kind()!=HardwareInterproceduralMmEffects.WitnessKind.UNKNOWN_FLOW &&
                    path.kind()!=HardwareInterproceduralMmEffects.WitnessKind.MISSING_TARGET)
                return "NONE";
            return witness(path);
        }
        private static String classification(
                HardwareInterproceduralMmEffects.Summary effect) {
            if(effect.mayMm())return "STATIC_MAY_MM_LOW_BYTE";
            if(effect.uncertainOrMm())return "UNKNOWN";
            return "NOT_OBSERVED_IN_BOUNDED_SOURCE";
        }
        public String markdown() {
            StringBuilder b=new StringBuilder(
                "## Byte-witnessed indirect JSR SIMCR/MM MAY effects (GA-02/03/11)\n\n")
                .append("**STATIC SOURCE-ONLY / NEVER EXECUTION, NEVER APPLY**. ")
                .append("A decoded and byte-verified computed JSR may target ")
                .append("a source subtree containing a possible STORE that ")
                .append("overlaps the MC68332 SIMCR/MM low byte. ")
                .append("MM0 and MM1 are conditional alternatives, NOT latched ")
                .append("hardware state. A source STORE is not an executed write. ")
                .append("No direct CALL/RESET/ISR edge, active VBR, physical CS ")
                .append("mapping or Review/Apply/Undo permission is inferred.\n")
                .append("- Source witnesses: ").append(totalWitnesses)
                .append("; classified: ").append(rows.size())
                .append("; omitted/UNKNOWN: ").append(omittedWitnesses)
                .append(". Unknown STORE address or width, unknown control flow, ")
                .append("unresolved callee, cycles and exhausted depth/node ")
                .append("or shared batch budget remain UNKNOWN; ")
                .append("negative evidence is bounded only. ")
                .append("MM/alias/observed unknown function chains start at ")
                .append("the byte-proven target (NOT the calling JSR PC); ")
                .append("uninspected frontier endpoints were NOT examined. ")
                .append("NONE is not proof that an omitted or unresolved source ")
                .append("cannot exist. A cycle-only uncertainty has no ")
                .append("fabricated callee chain.\n");
            if(omittedWitnesses>0)
                b.append("- **INCOMPLETE INDIRECTION MAY EVIDENCE:** ")
                 .append("omitted candidates cannot prove absence of MMIO.\n");
            if(!rows.isEmpty()){
                b.append("\n| Caller | Computed JSR PC | Byte-witnessed target | ")
                 .append("SIMCR/MM low-byte MAY | Unknown alias/width | ")
                 .append("Unknown CALL/flow | Cycle | Limited | ")
                 .append("Examined functions | Source proof | ")
                 .append("MM source chain | Alias source chain | ")
                 .append("Observed unknown/missing chain | ")
                 .append("Uninspected frontier chain |\n")
                 .append("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
                for(Row r:rows){
                    var w=r.witness();var s=r.source();
                    b.append("| ").append(hex(w.caller()))
                     .append(" | ").append(hex(w.callPc()))
                     .append(" | ").append(hex(w.target()))
                     .append(" | ").append(classification(s))
                     .append(" | ").append(s.unknownAlias())
                     .append(" | ").append(s.unknownControl())
                     .append(" | ").append(s.cycle())
                     .append(" | ").append(s.limited())
                     .append(" | ").append(s.visited())
                     .append(" | ").append(w.provenance())
                     .append(" | ").append(witness(s.mmWitness()))
                     .append(" | ").append(witness(s.aliasWitness()))
                     .append(" | ").append(observedUnknown(s))
                     .append(" | ").append(witness(s.frontierWitness()))
                     .append(" |\n");
                }
            }else
                b.append("- No eligible byte-witnessed indirect JSR source ")
                 .append("observed. NOT proof of no indirect calls.\n");
            return b.append("\n").toString();
        }
    }

    public static Report analyze(
            Collection<HardwareIndirectCallEvidence.Site> witnesses,
            Collection<HardwareInterproceduralMmEffects.FunctionNode> functions,
            int maxRows) {
        if(witnesses==null || functions==null || maxRows<1 ||
                maxRows>MAX_ROWS ||
                witnesses.size()>HardwareIndirectCallEvidence.MAX_SITES ||
                functions.size()>50_000)
            throw new IllegalArgumentException("Invalid bounded indirect MM source");
        List<HardwareIndirectCallEvidence.Site> sorted=new ArrayList<>(witnesses);
        if(sorted.contains(null))
            throw new IllegalArgumentException("Null indirect source");
        sorted.sort(Comparator.comparingLong(HardwareIndirectCallEvidence.Site::caller)
            .thenComparingLong(HardwareIndirectCallEvidence.Site::callPc)
            .thenComparingLong(HardwareIndirectCallEvidence.Site::target));
        Set<Long> uniquePc=new HashSet<>();
        for(var w:sorted)
            if(!uniquePc.add(w.callPc()))
                throw new IllegalArgumentException("Duplicate indirect source PC");
        List<HardwareIndirectCallEvidence.Site> selected=
            sorted.subList(0,Math.min(maxRows,sorted.size()));
        List<HardwareInterproceduralMmEffects.CallSite> calls=
            selected.stream().map(w->new HardwareInterproceduralMmEffects.CallSite(
                w.caller(),w.callPc(),w.target())).toList();
        Set<Long> interesting=new HashSet<>();
        for(var w:selected)interesting.add(w.caller());
        // Reuse existing bounded source graph solver. It allocates the shared
        // exploration budget to only the explicitly selected witnesses.
        var evidence=HardwareInterproceduralMmEffects.analyze(
            functions,calls,interesting,MAX_DEPTH,MAX_FUNCTIONS,maxRows);
        if(evidence.omitted()!=0 || evidence.rows().size()!=selected.size())
            throw new IllegalStateException(
                "Selected indirect CALL witness lost its MAY uncertainty");
        List<Row> rows=new ArrayList<>();
        for(int i=0;i<selected.size();i++){
            var call=evidence.rows().get(i).call();
            var witness=selected.get(i);
            if(call.pc()!=witness.callPc() ||
                    call.function()!=witness.caller() ||
                    !java.util.Objects.equals(call.target(),witness.target()))
                throw new IllegalStateException("Mismatched MAY source witnesses");
            rows.add(new Row(witness,evidence.rows().get(i).summary()));
        }
        return new Report(sorted.size(),sorted.size()-selected.size(),rows);
    }
}
