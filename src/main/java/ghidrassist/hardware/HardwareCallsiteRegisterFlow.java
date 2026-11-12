package ghidrassist.hardware;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * GA-02/03: read-only, SINGLE direct CALL-site register-context propagation.
 *
 * A source CFG can supply agreed A/D constants at the CALL instruction. The
 * direct callee is then solved in a fresh, uncached intraprocedural context.
 * This is a possible source-level MMIO/alias observation for THAT CALL SITE,
 * never a whole-function effect, execution proof, or Review/Apply approval.
 *
 * No interprocedural fixpoint, recursive CALL chain, indirect CALL target,
 * input-independent post-return proof, live memory or state from GA-12 caches.
 */
public final class HardwareCallsiteRegisterFlow {
    private HardwareCallsiteRegisterFlow() {}
    public static final int MAX_CALL_SITES=96;
    /** Bounded input for one-hop and two-hop closed CALL context solvers. */
    public static final int MAX_TRACKED_ADDRESSES=4096;
    public static final int MAX_CALLEE_STEPS=128;
    public static final int MAX_REPORTED_ROWS=96;
    public static final int MAX_REGISTER_CELLS=16;

    /** Source PCs in this MC68332 lane are aligned CPU32 coordinates. */
    private static boolean sourcePc(long address) {
        return address>=0 && address<=HardwareDataflow.MASK24 &&
            (address&1)==0;
    }

    public record Call(long caller,long callPc,Long directCallee,
                       Map<String,Long> agreedRegisters,boolean callerIncomplete) {
        public Call {
            if(!sourcePc(caller) || !sourcePc(callPc) ||
                    directCallee!=null && !sourcePc(directCallee) ||
                    agreedRegisters==null ||
                    agreedRegisters.size()>MAX_REGISTER_CELLS)
                throw new IllegalArgumentException("Invalid direct CALL context");
            for(var e:agreedRegisters.entrySet())
                if(e.getKey()==null || !e.getKey().matches("[AD][0-7]") ||
                        e.getValue()==null || e.getValue()<0 ||
                        e.getValue()>HardwareDataflow.MASK24)
                    throw new IllegalArgumentException("Bad agreed source register");
            agreedRegisters=Map.copyOf(agreedRegisters);
        }
    }
    /** Fully decoded direct callee Listing and all its CFG successors only. */
    public record Callee(long entry,List<HardwareDataflow.Step> steps,
                         boolean complete) {
        public Callee {
            if(!sourcePc(entry) || steps==null ||
                    steps.size()>MAX_CALLEE_STEPS ||
                    steps.stream().anyMatch(java.util.Objects::isNull))
                throw new IllegalArgumentException("Unbounded callee CFG");
            steps=List.copyOf(steps);
            Set<Long> addresses=new HashSet<>();
            for(HardwareDataflow.Step step:steps) {
                if(!sourcePc(step.address) || !addresses.add(step.address))
                    throw new IllegalArgumentException("Invalid callee source PC");
                for(Long successor:step.successors)
                    if(successor==null || !sourcePc(successor))
                        throw new IllegalArgumentException(
                            "Invalid callee CFG successor");
            }
        }
    }
    public record Candidate(long caller,long callPc,long callee,long storePc,
                            HardwareDataflow.Kind kind,Long address,
                            Integer writtenWord,int writeBits,
                            boolean priorUnknownCall,boolean priorUnknownStore,
                            int sourceRegisterCount) {
        public Candidate {
            if(!sourcePc(caller) || !sourcePc(callPc) || !sourcePc(callee) ||
                    !sourcePc(storePc) ||
                    kind!=HardwareDataflow.Kind.STORE_DIRECT &&
                        kind!=HardwareDataflow.Kind.STORE_INDIRECT ||
                    address!=null && (address<0 ||
                        address>HardwareDataflow.MASK24) ||
                    writtenWord!=null &&
                        (writtenWord<0 || writtenWord>0xffff) ||
                    writeBits!=8 && writeBits!=16 && writeBits!=32 ||
                    sourceRegisterCount<0 ||
                    sourceRegisterCount>MAX_REGISTER_CELLS)
                throw new IllegalArgumentException("Invalid CALL-site STORE candidate");
        }
    }
    public record Summary(int sampledCalls,int directCalls,int contextCalls,
                          int rejectedIncomplete,int rejectedMissingCallee,
                          int rejectedNestedOrBadCfg,int truncatedCalls,
                          int unresolvedAliases,int possibleStoreSites,
                          boolean omittedRows,List<Candidate> candidates) {
        public Summary {
            if(sampledCalls<0 || sampledCalls>MAX_CALL_SITES ||
                    directCalls<0 || directCalls>sampledCalls ||
                    contextCalls<0 || contextCalls>directCalls ||
                    rejectedIncomplete<0 || rejectedMissingCallee<0 ||
                    rejectedNestedOrBadCfg<0 || truncatedCalls<0 ||
                    unresolvedAliases<0 || possibleStoreSites<0 ||
                    candidates==null || candidates.size()>MAX_REPORTED_ROWS ||
                    possibleStoreSites<candidates.size() ||
                    omittedRows!=(possibleStoreSites>candidates.size()) ||
                    candidates.stream().anyMatch(java.util.Objects::isNull))
                throw new IllegalArgumentException("Invalid one-hop CALL summary");
            candidates=List.copyOf(candidates);
        }
        private static String hex(long x){return String.format(java.util.Locale.ROOT,
                "0x%08X",x);}
        public String markdown() {
            StringBuilder out=new StringBuilder();
            out.append("## One-hop CALL-site A/D register and MMIO candidates (GA-02/03)\n\n")
               .append("- **SOURCE-ONLY MAY-CANDIDATES**: each unique direct CALL ")
               .append("uses only predecessor-agreed source A/D registers at ")
               .append("that instruction, then a separate bounded callee CFG ")
               .append("solve. A7 is excluded: CALL changes the stack ")
               .append("pointer before the callee entry. ")
               .append("Calls may execute conditionally or not at all. ")
               .append("No argument convention/actual execution/MC68332 MM ")
               .append("latch or physical bus mapping is inferred.\n")
               .append("- Sampled calls: ").append(sampledCalls)
               .append("; direct entries: ").append(directCalls)
               .append("; known register context: ").append(contextCalls)
               .append("; incomplete caller: ").append(rejectedIncomplete)
               .append("; missing exact callee: ").append(rejectedMissingCallee)
               .append("; unverified/nested CFG: ")
               .append(rejectedNestedOrBadCfg)
               .append("; exceeded solver budget: ").append(truncatedCalls)
               .append("; unknown STORE aliases: ").append(unresolvedAliases)
               .append("; potential tracked STORE sites: ")
               .append(possibleStoreSites).append(".\n")
               .append("- A different caller may pass different values. ")
               .append("Unknown/indirect targets and incomplete paths never ")
               .append("inherit a guessed context. No result is published ")
               .append("as a complete per-function cache checkpoint, ")
               .append("Review/Apply candidate, or hardware observation.\n\n");
            if(!candidates.isEmpty()) {
                out.append("| Caller | CALL PC | Callee | STORE PC | Address candidate | ")
                   .append("Word | Bits | Unknown CALL in callee | ")
                   .append("Unknown STORE in callee | Caller known A/D |\n")
                   .append("|---|---|---|---|---|---|---|---|---|---|\n");
                for(Candidate r:candidates)
                    out.append("| ").append(hex(r.caller()))
                       .append(" | ").append(hex(r.callPc()))
                       .append(" | ").append(hex(r.callee()))
                       .append(" | ").append(hex(r.storePc()))
                       .append(" | ").append(r.address()==null?"UNKNOWN":hex(r.address()))
                       .append(" | ").append(r.writtenWord()==null?"UNKNOWN":
                           hex(r.writtenWord()&0xffffL))
                       .append(" | ").append(r.writeBits())
                       .append(" | ").append(r.priorUnknownCall())
                       .append(" | ").append(r.priorUnknownStore())
                       .append(" | ").append(r.sourceRegisterCount())
                       .append(" |\n");
            } else out.append("- No bounded one-hop register-context MMIO ")
                .append("source candidates; this does NOT prove no MMIO writes.\n");
            if(omittedRows)
                out.append("- **INCOMPLETE DISPLAY:** one-hop output exceeded ")
                   .append("the row budget. Omitted rows are UNKNOWN.\n");
            return out.append("\n").toString();
        }
    }
    /**
     * Shared fail-closed MCU24 input gate for both contextual CALL solvers.
     * Do not silently discard null, out-of-range, or excess addresses:
     * a truncated address set could be mistaken for full MMIO evidence.
     */
    static Set<Long> validatedTargets(Collection<Long> input) {
        if(input==null || input.size()>MAX_TRACKED_ADDRESSES)
            throw new IllegalArgumentException("Unbounded CALL MMIO targets");
        Set<Long> targets=new HashSet<>();
        for(Long address:input) {
            if(address==null || address<0 ||
                    address>HardwareDataflow.MASK24)
                throw new IllegalArgumentException("Invalid CALL MMIO target");
            targets.add(address);
        }
        return targets;
    }

    /**
     * No Ghidra dependency. Caller/callee scopes are explicit and keyed by
     * CALL PC; each caller context gets a new cold CFG solve, never a shared
     * state from another caller or the normal GA-12 durable result cache.
     */
    public static Summary analyze(Collection<Call> calls,
            Collection<Callee> callees,Collection<Long> trackedAddresses,
            int maxRows) {
        if(calls==null || callees==null ||
                calls.size()>MAX_CALL_SITES ||
                callees.size()>MAX_CALL_SITES || maxRows<1 ||
                maxRows>MAX_REPORTED_ROWS)
            throw new IllegalArgumentException("Unbounded CALL-site analysis");
        Map<Long,Callee> targetMap=new HashMap<>();
        for(Callee callee:callees) {
            if(callee==null || targetMap.putIfAbsent(callee.entry(),callee)!=null)
                throw new IllegalArgumentException("Duplicate/null callee");
        }
        Set<Long> tracked=validatedTargets(trackedAddresses);
        List<Call> sorted=new ArrayList<>(calls);
        if(sorted.contains(null))
            throw new IllegalArgumentException("Null CALL");
        sorted.sort(Comparator.comparingLong(Call::caller)
            .thenComparingLong(Call::callPc));
        Set<String> seen=new HashSet<>();
        List<Candidate> output=new ArrayList<>();
        int direct=0,contexts=0,incomplete=0,missing=0,bad=0,
            budget=0,aliases=0,sites=0;
        for(Call call:sorted){
            if(!seen.add(call.caller()+":"+call.callPc()))
                throw new IllegalArgumentException("Duplicate CALL instruction");
            if(call.directCallee()==null) { missing++;continue; }
            direct++;
            if(call.callerIncomplete()) { incomplete++;continue; }
            // CALL/JSR/BSR pushes a return address to the CPU32 stack.
            // Caller A7 is NOT a proven value at the callee entry. Do not
            // propagate it as a pointer even if the caller CFG knew it.
            Map<String,Long> passed=new HashMap<>(call.agreedRegisters());
            passed.remove("A7");
            if(passed.isEmpty())continue;
            contexts++;
            Callee callee=targetMap.get(call.directCallee());
            if(callee==null){missing++;continue;}
            if(!eligible(callee)) {bad++;continue;}
            int iterations=Math.min(30000,Math.max(300,callee.steps().size()*20));
            HardwareDataflow.Result result=HardwareDataflow.analyzeWithEntryRegisters(
                callee.entry(),callee.steps(),tracked,iterations,
                passed);
            if(result.truncated){budget++;continue;}
            for(HardwareDataflow.Snapshot hit:result.snapshots) {
                if(hit.kind!=HardwareDataflow.Kind.STORE_DIRECT &&
                        hit.kind!=HardwareDataflow.Kind.STORE_INDIRECT)continue;
                // A known 24-bit start address with an unknown P-code
                // STORE width is NOT a known non-overlap: an unmodeled
                // long/word write could span the SIMCR MM byte even when
                // its start address is not one of the tracked registers.
                // Preserve an explicit UNKNOWN alias, never fabricate a
                // precise tracked STORE candidate or a known 16-bit word.
                if(hit.effectiveAddress==null ||
                        (hit.writeBits!=8 && hit.writeBits!=16 &&
                         hit.writeBits!=32)) {aliases++;continue;}
                // A long/word STORE starting before a tracked MMIO
                // register can still touch its base; account for all
                // known-width bytes on the 24-bit MCU bus, not only start.
                if(!HardwareDataflow.mayTouchTrackedAddress(
                        hit.effectiveAddress,hit.writeBits,tracked) &&
                        !HardwareDataflow.mayTouchSimcrMmLowByte(
                            hit.effectiveAddress,hit.writeBits))continue;
                sites++;
                if(output.size()<maxRows)
                    output.add(new Candidate(call.caller(),call.callPc(),
                        callee.entry(),hit.instruction,hit.kind,
                        hit.effectiveAddress,hit.writtenWord,
                        hit.writeBits,hit.priorUnknownCall,
                        hit.priorUnknownStore,passed.size()));
            }
        }
        return new Summary(sorted.size(),direct,contexts,incomplete,missing,
            bad,budget,aliases,sites,sites>output.size(),output);
    }
    /** Unknown successor, recursion/nested call, or incomplete Listing fail closed. */
    private static boolean eligible(Callee callee){
        if(!callee.complete() || callee.steps().isEmpty())return false;
        Set<Long> pcs=new HashSet<>();
        for(HardwareDataflow.Step step:callee.steps())
            if(step==null || !pcs.add(step.address) ||
                    step.kind==HardwareDataflow.Kind.CALL_BARRIER)
                return false;
        if(!pcs.contains(callee.entry()))return false;
        for(HardwareDataflow.Step step:callee.steps())
            for(Long next:step.successors)
                if(next==null || !pcs.contains(next))return false;
        return true;
    }
}
