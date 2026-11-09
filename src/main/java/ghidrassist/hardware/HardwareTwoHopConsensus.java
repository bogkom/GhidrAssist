package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Supplier;

/**
 * Read-only reconciliation of independently resolved two-hop CALL source paths.
 * Agreement is *only among sampled outer CALL instructions*, never a global
 * leaf summary, runtime execution, MM activation, or Review/Apply evidence.
 */
public final class HardwareTwoHopConsensus {
    private HardwareTwoHopConsensus(){}
    public static final int MAX_REPORT_ROWS=24;
    public enum State {
        SAMPLED_AGREEMENT, SAMPLED_DIVERGENCE, INCOMPLETE,
        NO_SAMPLED_CALLS, STALE_REVISION
    }
    public record Finding(State state,long leaf,long storePc,
            int sampledOuterCalls,Long address,Integer word,int bits,
            List<HardwareTwoHopRegisterFlow.Candidate> provenance) {
        public Finding {
            if(state==null || leaf<0 || storePc<0 || sampledOuterCalls<0 ||
                    provenance==null ||
                    (state!=State.SAMPLED_AGREEMENT &&
                     (address!=null || word!=null || bits!=0)))
                throw new IllegalArgumentException("Invalid two-hop proof");
            provenance=List.copyOf(provenance);
        }
        public boolean publishableAsHardwareProof(){return false;}
    }
    private static Finding blank(State state,long leaf,long store,int sampled,
            List<HardwareTwoHopRegisterFlow.Candidate> rows) {
        return new Finding(state,leaf,store,sampled,null,null,0,rows);
    }
    private static Finding stale(long leaf,long store) {
        return blank(State.STALE_REVISION,leaf,store,0,List.of());
    }

    /**
     * Both captures are required: a Ghidra program edit during the report
     * must discard *all* purported source provenance, not merely its address.
     */
    public static Finding inspectRevisionBound(
            HardwareAnalysisRevision captured,
            Supplier<HardwareAnalysisRevision> current,
            Collection<HardwareCallsiteRegisterFlow.Call> outer,
            HardwareTwoHopRegisterFlow.Summary summary,long leaf,long store) {
        if(captured==null || current==null)
            throw new IllegalArgumentException("Missing revision guard");
        if(!captured.same(current.get()))return stale(leaf,store);
        Finding finding=inspect(outer,summary,leaf,store);
        if(!captured.same(current.get()))return stale(leaf,store);
        return finding;
    }

    /** Validate a single exact leaf STORE among all supplied outer callers. */
    public static Finding inspect(
            Collection<HardwareCallsiteRegisterFlow.Call> outer,
            HardwareTwoHopRegisterFlow.Summary summary,long leaf,long store) {
        if(outer==null || summary==null || leaf<0 || store<0 ||
                outer.size()>HardwareTwoHopRegisterFlow.MAX_OUTER_CALLS)
            throw new IllegalArgumentException("Invalid outer CALL inventory");
        List<HardwareCallsiteRegisterFlow.Call> calls=new ArrayList<>(outer);
        Set<String> seen=new HashSet<>();
        for(var c:calls)
            if(c==null || !seen.add(c.caller()+":"+c.callPc()))
                throw new IllegalArgumentException("Duplicate/null outer CALL");
        calls.sort(Comparator.comparingLong(HardwareCallsiteRegisterFlow.Call::caller)
            .thenComparingLong(HardwareCallsiteRegisterFlow.Call::callPc));
        if(calls.isEmpty())
            return blank(State.NO_SAMPLED_CALLS,leaf,store,0,List.of());
        List<HardwareTwoHopRegisterFlow.Candidate> rows=new ArrayList<>();
        for(var hit:summary.rows())
            if(hit.leafEntry()==leaf && hit.storePc()==store)rows.add(hit);
        rows.sort(Comparator.comparingLong(
                HardwareTwoHopRegisterFlow.Candidate::outerCaller)
            .thenComparingLong(HardwareTwoHopRegisterFlow.Candidate::outerCallPc));

        boolean incomplete=summary.sampled()!=calls.size() ||
            summary.displayTruncated() ||
            summary.possibleStores()!=summary.rows().size() ||
            summary.rejectedOuter()!=0 || summary.rejectedBridge()!=0 ||
            summary.unresolvedInner()!=0 || summary.rejectedLeaf()!=0 ||
            summary.unknownInnerRegisters()!=0 || summary.solverTruncated()!=0 ||
            summary.unknownAliases()!=0 ||
            rows.size()!=calls.size();
        for(var c:calls) {
            if(c.callerIncomplete() || c.directCallee()==null ||
                    c.agreedRegisters().isEmpty() ||
                    c.agreedRegisters().keySet().stream().allMatch("A7"::equals))
                incomplete=true;
            int hits=0;
            for(var row:rows)
                if(row.outerCaller()==c.caller() &&
                        row.outerCallPc()==c.callPc()) {
                    hits++;
                    // The bridge MUST be exactly the direct outer CALL target.
                    if(!Objects.equals(c.directCallee(),row.bridgeEntry()) ||
                            row.innerCallPc()<row.bridgeEntry() ||
                            row.effectiveAddress()==null ||
                            (row.bits()!=8 && row.bits()!=16 && row.bits()!=32) ||
                            row.priorUnknownCall() || row.priorUnknownStore())
                        incomplete=true;
                }
            if(hits!=1)incomplete=true;
        }
        // Any spurious row or duplicate outer CALL context must suppress
        // agreement even if its target and word happen to match.
        if(incomplete)return blank(State.INCOMPLETE,leaf,store,calls.size(),rows);
        var first=rows.get(0);
        boolean agree=rows.stream().allMatch(row->
            first.effectiveAddress().equals(row.effectiveAddress()) &&
            Objects.equals(first.writtenWord(),row.writtenWord()) &&
            first.bits()==row.bits());
        if(!agree)
            return blank(State.SAMPLED_DIVERGENCE,leaf,store,calls.size(),rows);
        return new Finding(State.SAMPLED_AGREEMENT,leaf,store,calls.size(),
            first.effectiveAddress(),first.writtenWord(),first.bits(),rows);
    }

    private static String hex(long x){
        return String.format(java.util.Locale.ROOT,"0x%08X",x);
    }

    /** Bounded report; missing outer CALLs suppress even unanimous samples. */
    public static String markdown(
            Collection<HardwareCallsiteRegisterFlow.Call> outer,
            HardwareTwoHopRegisterFlow.Summary summary,int omittedOuter,
            int maxRows,HardwareAnalysisRevision captured,
            Supplier<HardwareAnalysisRevision> current) {
        if(outer==null || summary==null || omittedOuter<0 ||
                maxRows<1 || maxRows>MAX_REPORT_ROWS ||
                captured==null || current==null)
            throw new IllegalArgumentException("Unbounded two-hop report");
        StringBuilder b=new StringBuilder();
        b.append("## Two-hop cross-CALL MMIO source agreement (GA-02/03)\n\n")
         .append("- **SOURCE-ONLY MAY-CANDIDATES; NOT HARDWARE PROOF**. ")
         .append("Sampled direct outer CALL -> bridge CALL -> leaf STORE. ")
         .append("An agreement does NOT prove all callers, actual execution, ")
         .append("SIMCR/MM, ISR, physical bus mapping or Review/Apply.\n");
        if(omittedOuter>0)
            b.append("- **INCOMPLETE INPUT:** ").append(omittedOuter)
             .append(" omitted outer CALL sites; sampled agreement withheld.\n");
        TreeMap<Long,TreeSet<Long>> sites=new TreeMap<>();
        for(var r:summary.rows())
            sites.computeIfAbsent(r.leafEntry(),k->new TreeSet<>()).add(r.storePc());
        b.append("\n| Leaf | STORE PC | Outer CALLs | Status | Address | Word | Bits |\n")
         .append("|---|---|---:|---|---|---|---:|\n");
        int displayed=0;
        for(var target:sites.entrySet())
            for(long store:target.getValue()) {
                if(displayed>=maxRows){
                    b.append("- **INCOMPLETE DISPLAY:** extra leaf STORE ")
                     .append("sites omitted by report budget.\n\n");
                    return b.toString();
                }
                Finding hit=inspectRevisionBound(captured,current,outer,summary,
                    target.getKey(),store);
                if(omittedOuter>0 && hit.state()==State.SAMPLED_AGREEMENT)
                    hit=blank(State.INCOMPLETE,target.getKey(),store,
                        hit.sampledOuterCalls(),hit.provenance());
                b.append("| ").append(hex(target.getKey())).append(" | ")
                 .append(hex(store)).append(" | ").append(hit.sampledOuterCalls())
                 .append(" | ").append(hit.state()).append(" | ")
                 .append(hit.address()==null?"UNKNOWN":hex(hit.address()))
                 .append(" | ").append(hit.word()==null?"UNKNOWN":
                    hex(hit.word()&0xffffL))
                 .append(" | ").append(hit.bits()==0?"UNKNOWN":hit.bits())
                 .append(" |\n");
                displayed++;
            }
        if(displayed==0)b.append("| — | — | 0 | NO_SAMPLED_CALLS | ")
            .append("UNKNOWN | UNKNOWN | UNKNOWN |\n");
        return b.append("\n").toString();
    }
}
