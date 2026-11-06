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
 * GA-02/03/11: independently read-only, bounded transitive MAY effects of
 * a production byte-verified indirect JSR source witness.
 *
 * This is explicitly NOT a graph edge, a reached RESET/ISR function, an
 * executed call, a known MMIO value, or a durable checkpoint. A source
 * witness is supplied by the existing AutomationCallPaths verifier, never
 * an arbitrary computed CALL reference. Even then, a target may have
 * side effects only IF the CALL executes on a feasible runtime path.
 */
public final class HardwareIndirectMayEffects {
    private HardwareIndirectMayEffects() {}
    public static final int MAX_ROWS=16;
    private static final int DEPTH=4;
    private static final int FUNCTIONS=100;

    public record Row(HardwareIndirectCallEvidence.Site source,
                      HardwareCallEffects.Summary effects) {}

    public record Report(int sourceSites,int examinedSites,int omittedSites,
                         List<Row> rows) {
        public Report {rows=List.copyOf(rows);}
        private static String hex(long n) {
            return String.format(Locale.ROOT,"0x%08X",n);
        }
        private static String evidence(boolean observed,
                HardwareCallEffects.Summary effects) {
            if(observed)return "STATIC_MAY_CANDIDATE";
            if(effects.unresolved() || effects.truncated())
                return "UNKNOWN";
            return "NOT_OBSERVED_IN_BOUNDED_SOURCE";
        }
        public String markdown() {
            StringBuilder out=new StringBuilder(
                "## Byte-witnessed indirect JSR transitive MAY effects (GA-02/03/11)\n\n")
                .append("**DISPLAY ONLY — SOURCE CANDIDATES, NEVER EXECUTION**. ")
                .append("A locally byte-verified MOVEA/JSR instruction witness ")
                .append("can name an exact target but does not create a ")
                .append("direct CALL edge, RESET-reachable function, executed ")
                .append("ISR, active VBR, latched SIMCR/MM or physical CS map. ")
                .append("Memory STORE is any P-code STORE, **not a proven ")
                .append("MMIO access** or accepted hardware write. ")
                .append("No Apply/Undo, analysis revision, global CALL graph ")
                .append("or persisted checkpoint changes.\n")
                .append("- Indirect CALL source witnesses: ").append(sourceSites)
                .append("; examined (up to 16): ").append(examinedSites)
                .append("; omitted (UNKNOWN): ").append(omittedSites)
                .append(". The source verifier's own unresolved calls and ")
                .append("omitted witnesses remain separately authoritative.\n")
                .append("- A negative result means only **NOT_OBSERVED_IN_BOUNDED_SOURCE**. ")
                .append("Unknown callees, graph gaps, recursion and depth/node ")
                .append("limits stay UNKNOWN; no inference of no MMIO/VBR/IRQ.\n");
            if(omittedSites>0)
                out.append("- **INCOMPLETE MAY EFFECT COVERAGE**: more exact ")
                    .append("witnesses than the independent analysis cap.\n");
            if(!rows.isEmpty()) {
                out.append("\n| Caller | Computed JSR PC | Possible exact target | ")
                    .append("Memory STORE MAY | VBR write MAY | Flow unknown | ")
                    .append("Cycle | Limited | Checked functions | Source witness |\n")
                    .append("|---|---|---|---|---|---|---|---|---|---|\n");
                for(Row row:rows) {
                    var s=row.source();
                    var e=row.effects();
                    out.append("| ").append(hex(s.caller()))
                        .append(" | ").append(hex(s.callPc()))
                        .append(" | ").append(hex(s.target()))
                        .append(" | ").append(evidence(e.possibleMemoryStore(),e))
                        .append(" | ").append(evidence(e.possibleVbrWrite(),e))
                        .append(" | ").append(e.unresolved())
                        .append(" | ").append(e.recursive())
                        .append(" | ").append(e.truncated())
                        .append(" | ").append(e.visited())
                        .append(" | ").append(s.provenance())
                        .append(" |\n");
                }
            }else out.append("- No byte-witnessed indirect source target available ")
                .append("for the bounded effect scan; NOT proof of no CALL.\n");
            return out.append("\n").toString();
        }
    }

    /**
     * The list must contain only the already bounded and byte-witnessed
     * candidates from the production Ghidra verifier. The caller decides
     * whether the explicit MCU profile permits displaying this source.
     *
     * Source sorting is deterministic, and caching is **only local to this
     * invocation**, never across Ghidra revisions or different Programs.
     */
    public static Report analyze(Collection<HardwareIndirectCallEvidence.Site> sites,
            Collection<HardwareCallEffects.FunctionNode> graph,int maxRows) {
        if(sites==null || graph==null ||
                sites.size()>HardwareIndirectCallEvidence.MAX_SITES ||
                graph.size()>HardwareCallEffects.MAX_SOURCE_FUNCTIONS ||
                maxRows<1 || maxRows>MAX_ROWS)
            throw new IllegalArgumentException("Invalid bounded indirect effects");
        List<HardwareIndirectCallEvidence.Site> sorted=new ArrayList<>(sites);
        if(sorted.contains(null))
            throw new IllegalArgumentException("Null indirect witness");
        sorted.sort(Comparator.comparingLong(HardwareIndirectCallEvidence.Site::caller)
            .thenComparingLong(HardwareIndirectCallEvidence.Site::callPc)
            .thenComparingLong(HardwareIndirectCallEvidence.Site::target));
        Set<Long> pcs=new HashSet<>();
        for(var s:sorted)
            if(!pcs.add(s.callPc()))
                throw new IllegalArgumentException("Duplicate indirect witness PC");
        List<Row> out=new ArrayList<>();
        Map<Long,HardwareCallEffects.Summary> cache=new HashMap<>();
        for(var site:sorted) {
            if(out.size()>=maxRows)break;
            var effects=cache.computeIfAbsent(site.target(),
                target->HardwareCallEffects.summarize(
                    target,graph,DEPTH,FUNCTIONS));
            out.add(new Row(site,effects));
        }
        return new Report(sorted.size(),out.size(),sorted.size()-out.size(),out);
    }
}
