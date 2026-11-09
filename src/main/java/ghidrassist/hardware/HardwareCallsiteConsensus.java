package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;

/**
 * GA-02/03/12: conservative, read-only reconciliation of independent
 * one-hop CALL-site source candidates for the SAME callee STORE PC.
 *
 * An agreement is only among the sampled, completely decoded direct
 * CALL contexts supplied to the caller. It is NEVER a globally proven
 * function effect, a physical MMIO write or Review/Apply permission.
 */
public final class HardwareCallsiteConsensus {
    private HardwareCallsiteConsensus() {}

    public enum State {
        SAMPLED_AGREEMENT, SAMPLED_DIVERGENCE, INCOMPLETE, NO_SAMPLED_CALLS,
        STALE_REVISION
    }

    public record Finding(State state,long callee,long storePc,
            int sampledCallSites,Long address,Integer word,int bits,
            List<HardwareCallsiteRegisterFlow.Candidate> provenance) {
        public Finding {
            if(state==null || callee<0 || storePc<0 || sampledCallSites<0 ||
                    provenance==null ||
                    (state!=State.SAMPLED_AGREEMENT &&
                        (address!=null || word!=null || bits!=0)))
                throw new IllegalArgumentException("Invalid CALL reconciliation");
            provenance=List.copyOf(provenance);
        }
        public boolean publishableAsHardwareProof(){return false;}
        public String description(){
            return state+" (source-only sampled CALL-site MAY-candidates, "+
                "not runtime execution, active MM, global CALL coverage "+
                "or Review/Apply authorization)";
        }
    }

    /**
     * Production report section: bounded, never a program-wide side-effect
     * claim. Unsampled caller inputs suppress any apparently unanimous row.
     */
    public static String markdown(
            Collection<HardwareCallsiteRegisterFlow.Call> calls,
            HardwareCallsiteRegisterFlow.Summary summary,
            int omittedCallSites,int maxPairs,
            HardwareAnalysisRevision captured,
            Supplier<HardwareAnalysisRevision> current){
        if(calls==null || summary==null || omittedCallSites<0 ||
                maxPairs<1 || maxPairs>48 || captured==null || current==null)
            throw new IllegalArgumentException("Invalid CALL reconciliation report");
        StringBuilder out=new StringBuilder();
        out.append("## Cross-CALL MMIO source agreement (GA-02/03)\n\n")
            .append("- **SOURCE-ONLY MAY-CANDIDATES, NEVER HARDWARE PROOF**: ")
            .append("an agreement covers only distinct sampled direct CALL ")
            .append("sites for one callee STORE, not all callers, execution, ")
            .append("active SIMCR/MM, or Review/Apply. Unknown input remains ")
            .append("UNKNOWN.\n");
        if(omittedCallSites>0)
            out.append("- **INCOMPLETE SOURCE INVENTORY:** ")
                .append(omittedCallSites)
                .append(" caller contexts not analyzed; agreement withheld.\n");
        java.util.TreeMap<Long,java.util.TreeSet<Long>> locations=
            new java.util.TreeMap<>();
        for(var row:summary.candidates())
            locations.computeIfAbsent(row.callee(),k->new java.util.TreeSet<>())
                .add(row.storePc());
        out.append("\n| Callee | STORE PC | Sampled CALLs | Status | ")
            .append("Candidate address | Word | Bits |\n")
            .append("|---|---|---:|---|---|---|---:|\n");
        int reported=0;
        for(var target:locations.entrySet())
            for(long storePc:target.getValue()){
                int count=0;
                for(var call:calls)
                    if(call!=null && Objects.equals(call.directCallee(),
                            target.getKey()))
                        count++;
                if(count<2)continue;
                if(reported>=maxPairs){
                    out.append("- **INCOMPLETE DISPLAY:** additional CALL ")
                        .append("sites omitted by reconciliation row budget.\n");
                    return out.append("\n").toString();
                }
                Finding observation=inspectRevisionBound(captured,current,
                    calls,summary,target.getKey(),storePc);
                if(omittedCallSites>0 &&
                        observation.state()==State.SAMPLED_AGREEMENT)
                    observation=incomplete(target.getKey(),storePc,
                        observation.sampledCallSites(),
                        observation.provenance());
                out.append("| ").append(hex(target.getKey()))
                    .append(" | ").append(hex(storePc))
                    .append(" | ").append(observation.sampledCallSites())
                    .append(" | ").append(observation.state())
                    .append(" | ").append(observation.address()==null?
                        "UNKNOWN":hex(observation.address()))
                    .append(" | ").append(observation.word()==null?
                        "UNKNOWN":hex(observation.word()&0xffffL))
                    .append(" | ").append(observation.bits()==0?
                        "UNKNOWN":observation.bits())
                    .append(" |\n");
                reported++;
            }
        if(reported==0)
            out.append("| — | — | 0 | NO_SAMPLED_CALLS | UNKNOWN | ")
                .append("UNKNOWN | UNKNOWN |\n");
        return out.append("\n").toString();
    }

    private static String hex(long value) {
        return String.format(java.util.Locale.ROOT,"0x%08X",value);
    }

    /** Fail closed if the caller's Ghidra revision changed while evaluating. */
    public static Finding inspectRevisionBound(
            HardwareAnalysisRevision captured,
            Supplier<HardwareAnalysisRevision> current,
            Collection<HardwareCallsiteRegisterFlow.Call> calls,
            HardwareCallsiteRegisterFlow.Summary summary,
            long callee,long storePc) {
        if(captured==null || current==null)
            throw new IllegalArgumentException("Missing Ghidra revision guard");
        if(!captured.same(current.get()))
            return stale(callee,storePc);
        Finding evaluated=inspect(calls,summary,callee,storePc);
        if(!captured.same(current.get()))
            return stale(callee,storePc);
        return evaluated;
    }
    private static Finding stale(long callee,long storePc){
        return new Finding(State.STALE_REVISION,callee,storePc,0,
            null,null,0,List.of());
    }
    private static Finding incomplete(long callee,long storePc,
            int count,List<HardwareCallsiteRegisterFlow.Candidate> seen){
        return new Finding(State.INCOMPLETE,callee,storePc,count,
            null,null,0,seen);
    }

    /**
     * Reconcile one store site across distinct, sampled CALL PCs.
     * Unresolved aliases, pagination, missing evidence, unverified callees,
     * skipped contexts, incomplete callers or duplicate rows all suppress
     * agreement: absence of a row is not absence of a possible write.
     */
    public static Finding inspect(
            Collection<HardwareCallsiteRegisterFlow.Call> calls,
            HardwareCallsiteRegisterFlow.Summary summary,
            long callee,long storePc){
        if(calls==null || summary==null || callee<0 || storePc<0 ||
                calls.size()>HardwareCallsiteRegisterFlow.MAX_CALL_SITES)
            throw new IllegalArgumentException("Invalid source CALL inventory");
        List<HardwareCallsiteRegisterFlow.Call> selected=new ArrayList<>();
        Set<String> identities=new HashSet<>();
        for(var call:calls) {
            if(call==null || !identities.add(call.caller()+":"+call.callPc()))
                throw new IllegalArgumentException("Duplicate/null source CALL");
            if(Objects.equals(call.directCallee(),callee))
                selected.add(call);
        }
        selected.sort(Comparator.comparingLong(HardwareCallsiteRegisterFlow.Call::caller)
            .thenComparingLong(HardwareCallsiteRegisterFlow.Call::callPc));
        if(selected.isEmpty())
            return new Finding(State.NO_SAMPLED_CALLS,callee,storePc,0,
                null,null,0,List.of());

        List<HardwareCallsiteRegisterFlow.Candidate> evidence=new ArrayList<>();
        for(var hit:summary.candidates())
            if(hit.callee()==callee && hit.storePc()==storePc)
                evidence.add(hit);
        evidence.sort(Comparator.comparingLong(
                HardwareCallsiteRegisterFlow.Candidate::caller)
            .thenComparingLong(HardwareCallsiteRegisterFlow.Candidate::callPc));

        boolean incomplete=summary.sampledCalls()!=calls.size() ||
            summary.omittedRows() ||
            summary.possibleStoreSites()!=summary.candidates().size() ||
            summary.rejectedIncomplete()!=0 ||
            summary.rejectedMissingCallee()!=0 ||
            summary.rejectedNestedOrBadCfg()!=0 ||
            summary.truncatedCalls()!=0 ||
            summary.unresolvedAliases()!=0;
        // At every CALL the input register context is independently
        // predecessor-agreed; do not merge contexts before callee analysis.
        if(!incomplete)for(var call:selected) {
            if(call.callerIncomplete() || call.agreedRegisters().isEmpty() ||
                    call.agreedRegisters().keySet().stream().allMatch("A7"::equals))
                incomplete=true;
            int rows=0;
            for(var hit:evidence) {
                if(hit.caller()==call.caller() && hit.callPc()==call.callPc()){
                    rows++;
                    if(hit.address()==null ||
                            (hit.writeBits()!=8 && hit.writeBits()!=16 &&
                             hit.writeBits()!=32) ||
                            hit.priorUnknownCall() || hit.priorUnknownStore())
                        incomplete=true;
                }
            }
            if(rows!=1)incomplete=true;
        }
        if(evidence.size()!=selected.size())
            incomplete=true;
        // A foreign candidate with the same callee/STORE but not present
        // in this source inventory is not an independently verified caller.
        for(var hit:evidence) {
            if(selected.stream().noneMatch(call ->
                    hit.caller()==call.caller() &&
                    hit.callPc()==call.callPc()))
                incomplete=true;
        }
        if(incomplete)
            return incomplete(callee,storePc,selected.size(),evidence);

        var reference=evidence.get(0);
        boolean equal=evidence.stream().allMatch(hit->
            hit.address().equals(reference.address()) &&
            Objects.equals(hit.writtenWord(),reference.writtenWord()) &&
            hit.writeBits()==reference.writeBits() &&
            hit.kind()==reference.kind());
        if(!equal)
            return new Finding(State.SAMPLED_DIVERGENCE,callee,storePc,
                selected.size(),null,null,0,evidence);
        return new Finding(State.SAMPLED_AGREEMENT,callee,storePc,
            selected.size(),reference.address(),reference.writtenWord(),
            reference.writeBits(),evidence);
    }
}
