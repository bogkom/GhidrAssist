package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * GA-02/03: display-only SOURCE provenance for an exactly byte-proven
 * CPU32 MOVEA.L #imm,An followed by at most three NOP/MOVEQ operations
 * and JSR (An), with the same target address register.
 *
 * This class NEVER establishes executed calls, global call-graph edges,
 * MM latch states, or Review/Apply-eligible writes. Other computed targets
 * remain UNKNOWN. The proof itself is shared with AutomationCallPaths.
 */
public final class HardwareIndirectCallEvidence {
    private HardwareIndirectCallEvidence() {}
    public static final int MAX_SITES=96;

    private static final Set<String> PROVENANCES=Set.of(
        "adjacent_movea_immediate","bounded_movea_nop_chain",
        "bounded_movea_safe_chain");
    public record Site(long caller,long movePc,long callPc,long target,
                       String provenance) {
        /** Backward-compatible exact adjacent witness. */
        public Site(long caller,long movePc,long callPc,long target) {
            this(caller,movePc,callPc,target,"adjacent_movea_immediate");
        }
        public Site {
            if(caller<0 || movePc<caller || callPc<=movePc ||
                    target<0 || caller>HardwareDataflow.MASK24 ||
                    movePc>HardwareDataflow.MASK24 ||
                    callPc>HardwareDataflow.MASK24 ||
                    target>HardwareDataflow.MASK24 ||
                    provenance==null || !PROVENANCES.contains(provenance))
                throw new IllegalArgumentException(
                    "Invalid bounded CPU32 indirect CALL provenance");
        }
    }

    public static String markdown(Collection<Site> input,int unresolved,
            int omitted) {
        if(input==null || input.size()>MAX_SITES ||
                unresolved<0 || omitted<0)
            throw new IllegalArgumentException("Unbounded indirect CALL evidence");
        List<Site> sorted=new ArrayList<>(input);
        if(sorted.contains(null))
            throw new IllegalArgumentException("Null indirect CALL evidence");
        sorted.sort(Comparator.comparingLong(Site::caller)
            .thenComparingLong(Site::callPc)
            .thenComparingLong(Site::target));
        Set<Long> uniquePcs=new HashSet<>();
        for(Site s:sorted)
            if(!uniquePcs.add(s.callPc()))
                throw new IllegalArgumentException("Duplicate indirect CALL PC");
        StringBuilder b=new StringBuilder(
            "## CPU32 adjacent-immediate indirect JSR source candidates (GA-02/03)\n\n")
            .append("**STATIC SOURCE-ONLY PROVENANCE — NOT EXECUTION**. ")
            .append("An existing, exact Ghidra function entry was encoded ")
            .append("by a CPU32 MOVEA.L #imm,An, optionally followed by up ")
            .append("to three NOP/MOVEQ instructions before CPU32 JSR (An) " +
            "to the SAME register. No branch, unknown instruction, " +
            "address-register or memory change is modeled. ")
            .append("The complete bounded instruction bytes are verified by the ")
            .append("existing Automation API call-path verifier. ")
            .append("Other computed CALL targets remain UNKNOWN; no new " +
            "function graph edge, ")
            .append("reachable RESET path, active SIMCR/MM, or physical ")
            .append("chip-select mapping is inferred. ")
            .append("No automatic Review/Apply/Undo operation or cache ")
            .append("checkpoint is created.\n")
            .append("- Exact bounded source candidates displayed: ")
            .append(sorted.size())
            .append("; unresolved computed calls: ").append(unresolved)
            .append("; candidates omitted by cap: ").append(omitted)
            .append(". Unknown CALL sites remain UNKNOWN.\n");
        if(omitted>0)b.append("- **INCOMPLETE DISPLAY:** bounded output; ")
            .append("omitted candidate targets are UNKNOWN.\n");
        if(!sorted.isEmpty()){
            b.append("\n| Caller | MOVEA site | JSR site | Possible exact target ")
                .append("| Provenance |\n")
                .append("|---|---|---|---|---|\n");
            for(Site s:sorted)
                b.append("| ").append(hex(s.caller()))
                    .append(" | ").append(hex(s.movePc()))
                    .append(" | ").append(hex(s.callPc()))
                    .append(" | ").append(hex(s.target()))
                    .append(" | ").append(s.provenance()).append(" |\n");
        }else b.append("- No exactly proven indirect JSR candidates. ")
            .append("This does NOT prove the absence of indirect calls.\n");
        return b.append("\n").toString();
    }
    private static String hex(long n) {
        return String.format(Locale.ROOT,"0x%08X",n);
    }
}
