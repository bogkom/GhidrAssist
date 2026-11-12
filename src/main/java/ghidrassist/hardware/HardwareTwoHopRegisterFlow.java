package ghidrassist.hardware;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * GA-02/03: bounded, source-only context propagation through exactly TWO
 * direct calls: source CALL -> fully decoded bridge -> direct leaf CALL.
 *
 * This is a MAY-source per particular outer CALL PC, not a global callee
 * summary or an execution trace. No recursive fixpoint, no cycles, no unknown
 * memory operations and no durable cache or Review/Apply evidence.
 */
public final class HardwareTwoHopRegisterFlow {
    private HardwareTwoHopRegisterFlow(){}
    public static final int MAX_OUTER_CALLS=32;
    public static final int MAX_BRIDGE_STEPS=64;
    public static final int MAX_ROWS=48;
    private static final Pattern BRANCH=Pattern.compile(
        "B(?:RA|CC|CS|EQ|NE|GE|GT|HI|LE|LS|LT|MI|PL|VC|VS)(?:\\.[BWSL])?");
    private static final Pattern RETURNING_CALL=Pattern.compile(
        "JSR|BSR(?:\\.[BWSL])?");
    private static final Pattern UNCONDITIONAL=Pattern.compile(
        "BRA(?:\\.[BWSL])?");
    private static final Set<String> SET=Set.of("MOVE.L","MOVEA.L","MOVEQ","LEA");
    private static final Set<String> COPY=Set.of("MOVE.L","MOVEA.L");

    /**
     * Exact decoded intermediate function. The PC is an actual direct CALL
     * instruction; finalTarget is an exact Ghidra function entry or null.
     */
    public record Bridge(long entry,List<HardwareDataflow.Step> steps,
            long innerCallPc,Long finalTarget,boolean complete) {
        public Bridge {
            if(!sourcePc(entry) || !sourcePc(innerCallPc) ||
                    innerCallPc<entry ||
                    finalTarget!=null && (!sourcePc(finalTarget) ||
                        finalTarget==entry) ||
                    steps==null || steps.size()>MAX_BRIDGE_STEPS ||
                    steps.stream().anyMatch(java.util.Objects::isNull))
                throw new IllegalArgumentException("Invalid two-hop bridge");
            steps=List.copyOf(steps);
            Set<Long> pcs=new HashSet<>();
            for(HardwareDataflow.Step step:steps) {
                if(!sourcePc(step.address) || !pcs.add(step.address))
                    throw new IllegalArgumentException("Invalid bridge source PC");
                for(Long successor:step.successors)
                    if(successor==null || !sourcePc(successor))
                        throw new IllegalArgumentException("Invalid bridge CFG successor");
            }
        }
    }
    public record Candidate(long outerCaller,long outerCallPc,
            long bridgeEntry,long innerCallPc,long leafEntry,long storePc,
            Long effectiveAddress,Integer writtenWord,int bits,
            int knownEntryRegisters,int knownInnerRegisters,
            boolean priorUnknownCall,boolean priorUnknownStore) {
        public Candidate {
            if(!sourcePc(outerCaller) || !sourcePc(outerCallPc) ||
                    !sourcePc(bridgeEntry) || !sourcePc(innerCallPc) ||
                    !sourcePc(leafEntry) || !sourcePc(storePc) ||
                    effectiveAddress!=null && (effectiveAddress<0 ||
                        effectiveAddress>HardwareDataflow.MASK24) ||
                    writtenWord!=null && (writtenWord<0 || writtenWord>0xffff) ||
                    bits!=8 && bits!=16 && bits!=32 ||
                    knownEntryRegisters<0 || knownEntryRegisters>8 ||
                    knownInnerRegisters<0 || knownInnerRegisters>8)
                throw new IllegalArgumentException("Invalid two-hop source candidate");
        }
    }

    public record Summary(int sampled,int eligibleOuter,int rejectedOuter,
            int rejectedBridge,int unresolvedInner,int rejectedLeaf,
            int unknownInnerRegisters,int solverTruncated,int unknownAliases,
            int possibleStores,boolean displayTruncated,List<Candidate> rows) {
        public Summary {
            if(sampled<0 || sampled>MAX_OUTER_CALLS || eligibleOuter<0 ||
                    rejectedOuter<0 || eligibleOuter+rejectedOuter!=sampled ||
                    rejectedBridge<0 || rejectedBridge>eligibleOuter ||
                    unresolvedInner<0 || unresolvedInner>eligibleOuter ||
                    rejectedLeaf<0 || rejectedLeaf>eligibleOuter ||
                    unknownInnerRegisters<0 || unknownInnerRegisters>eligibleOuter ||
                    solverTruncated<0 || solverTruncated>eligibleOuter ||
                    unknownAliases<0 || possibleStores<0 || rows==null ||
                    rows.size()>MAX_ROWS || possibleStores<rows.size() ||
                    displayTruncated!=(possibleStores>rows.size()) ||
                    rows.stream().anyMatch(java.util.Objects::isNull))
                throw new IllegalArgumentException("Invalid two-hop source summary");
            rows=List.copyOf(rows);
        }
        private static String hex(long x){
            return String.format(Locale.ROOT,"0x%08X",x);
        }
        public String markdown(){
            StringBuilder b=new StringBuilder();
            b.append("## Bounded two-hop CALL argument/MMIO source candidates (GA-02/03)\n\n")
             .append("- **SOURCE-ONLY MAY-CANDIDATES — NOT EXECUTION**. ")
             .append("One distinct outer direct CALL -> a fully decoded, ")
             .append("acyclic intermediate function with exactly one direct ")
             .append("CALL -> a closed direct leaf. Every inner A/D register ")
             .append("value must agree at that precise nested CALL site; ")
             .append("conditional branches are not evaluated for feasibility. ")
             .append("CALL stack register A7 is NEVER propagated across ")
             .append("either call boundary.\n")
             .append("- Sampled outer CALLs: ").append(sampled)
             .append("; with source arguments: ").append(eligibleOuter)
             .append("; rejected outer: ").append(rejectedOuter)
             .append("; unsafe/incomplete/recursive bridge: ").append(rejectedBridge)
             .append("; unknown inner target: ").append(unresolvedInner)
             .append("; absent/unsafe leaf: ").append(rejectedLeaf)
             .append("; no agreed inner A/D: ").append(unknownInnerRegisters)
             .append("; CFG solver truncated: ").append(solverTruncated)
             .append("; unknown STORE alias: ").append(unknownAliases)
             .append("; tracked possible STORE sites: ").append(possibleStores)
             .append(".\n")
             .append("- No values from other callers, unknown indirect ")
             .append("targets, unknown P-code effects, memory operations ")
             .append("or further CALLs are merged. No runtime RESET/CALL, ")
             .append("SIMCR/MM latch, physical CS mapping, active VBR/ISR ")
             .append("or Review/Apply entitlement is inferred. Neither ")
             .append("the seeded bridge nor the leaf result is stored ")
             .append("in GA-12 checkpoints or RAG completeness.\n\n");
            if(!rows.isEmpty()){
                b.append("| Outer function | CALL PC | Bridge | Inner CALL PC | ")
                 .append("Leaf | STORE PC | Possible address | Word | Bits | ")
                 .append("Outer A/D | Inner A/D | Unknown leaf CALL | ")
                 .append("Unknown leaf STORE |\n")
                 .append("|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
                for(Candidate c:rows)
                    b.append("| ").append(hex(c.outerCaller()))
                     .append(" | ").append(hex(c.outerCallPc()))
                     .append(" | ").append(hex(c.bridgeEntry()))
                     .append(" | ").append(hex(c.innerCallPc()))
                     .append(" | ").append(hex(c.leafEntry()))
                     .append(" | ").append(hex(c.storePc()))
                     .append(" | ").append(c.effectiveAddress()==null?
                         "UNKNOWN":hex(c.effectiveAddress()))
                     .append(" | ").append(c.writtenWord()==null?"UNKNOWN":
                         hex(c.writtenWord()&0xffffL))
                     .append(" | ").append(c.bits())
                     .append(" | ").append(c.knownEntryRegisters())
                     .append(" | ").append(c.knownInnerRegisters())
                     .append(" | ").append(c.priorUnknownCall())
                     .append(" | ").append(c.priorUnknownStore())
                     .append(" |\n");
            }else b.append("- No two-hop candidates observed within the ")
                .append("bounded source subset; this does NOT prove ")
                .append("absence of calls or MMIO writes.\n");
            if(displayTruncated)
                b.append("- **INCOMPLETE DISPLAY:** additional source STORE ")
                 .append("sites omitted by the fixed output cap.\n");
            return b.append("\n").toString();
        }
    }

    /**
     * CPU32/68000 JSR/BSR pushes return PC on the supervisor or user stack.
     * Even a known A7 just before CALL is NOT the callee's entry value.
     */
    private static Map<String,Long> noStack(Map<String,Long> known){
        if(!known.containsKey("A7"))return known;
        Map<String,Long> copy=new HashMap<>(known);
        copy.remove("A7");
        return Map.copyOf(copy);
    }

    /**
     * Entire bridge must be a closed DAG with a single CALL_BARRIER to the
     * stated direct target; NO memory, VBR or unknown instructions. A finite
     * cycle is rejected rather than summarized by an unproved fixed point.
     */
    /** MC68332 source-address identity, not a runtime active-bus claim. */
    private static boolean sourcePc(long address) {
        return address>=0 && address<=HardwareDataflow.MASK24 &&
            (address&1L)==0;
    }

    /**
     * Only a true CPU32 control-flow instruction can fork or redirect a
     * closed bridge path. P-code register propagation must never run on
     * fake one-successor Bcc, two-successor BRA/NOP, or dangling implicit
     * fallthrough. The caller-supplied steps remain untrusted until the
     * separate real Ghidra instruction decoder verifies them.
     */
    private static boolean sourceSuccessors(HardwareDataflow.Step step) {
        int size=step.successors.size();
        // Opcode/kind disagreement must never reinterpret a branch as
        // a linear register clobber or hide a CPU32 return.
        if(step.kind!=HardwareDataflow.Kind.OTHER &&
                step.kind!=HardwareDataflow.Kind.CALL_BARRIER &&
                ("RTS".equals(step.mnemonic) ||
                 BRANCH.matcher(step.mnemonic).matches()))
            return false;
        if("RTS".equals(step.mnemonic))return
            step.kind==HardwareDataflow.Kind.OTHER && size==0 &&
            (step.sideEffectRegisters.isEmpty() ||
                step.sideEffectRegisters.equals(Set.of("A7")));
        if(step.kind==HardwareDataflow.Kind.CALL_BARRIER)
            return size==1 && RETURNING_CALL.matcher(step.mnemonic).matches() &&
                (step.sideEffectRegisters.isEmpty() ||
                    step.sideEffectRegisters.equals(Set.of("A7")));
        if(step.kind==HardwareDataflow.Kind.OTHER &&
                UNCONDITIONAL.matcher(step.mnemonic).matches())
            return size==1 && step.sideEffectRegisters.isEmpty();
        if(step.kind==HardwareDataflow.Kind.OTHER &&
                BRANCH.matcher(step.mnemonic).matches())
            return size==2 && !step.successors.get(0).equals(
                step.successors.get(1)) && step.sideEffectRegisters.isEmpty();
        // Every NOP and modeled A/D instruction has exactly one successor
        // in an acyclic, fully decoded intermediate CALL bridge.
        return size==1;
    }

    private static boolean safeBridge(Bridge bridge){
        if(!sourcePc(bridge.entry()) || !sourcePc(bridge.innerCallPc()) ||
                bridge.innerCallPc()<bridge.entry() ||
                bridge.finalTarget()!=null &&
                    (!sourcePc(bridge.finalTarget()) ||
                     bridge.finalTarget()==bridge.entry()) ||
                !bridge.complete() || bridge.steps().isEmpty())return false;
        Map<Long,HardwareDataflow.Step> nodes=new HashMap<>();
        Map<Long,Integer> degree=new HashMap<>();
        int calls=0,returns=0,edges=0;
        for(HardwareDataflow.Step step:bridge.steps()){
            if(step==null || !sourcePc(step.address) ||
                    step.address<bridge.entry() ||
                    nodes.putIfAbsent(step.address,step)!=null)
                return false;
            degree.put(step.address,0);
        }
        if(!nodes.containsKey(bridge.entry()))return false;
        for(HardwareDataflow.Step step:bridge.steps()){
            String m=step.mnemonic;
            if(!sourceSuccessors(step))return false;
            if(step.kind==HardwareDataflow.Kind.CALL_BARRIER){
                if(step.address!=bridge.innerCallPc() ||
                        !step.verifiedCallReturns.isEmpty() ||
                        step.successors.size()!=1)return false;
                calls++;
            }else if(step.kind==HardwareDataflow.Kind.SET_POINTER) {
                if(!SET.contains(m) || step.register==null ||
                        !step.register.matches("[AD][0-7]"))return false;
            }else if(step.kind==HardwareDataflow.Kind.COPY_POINTER){
                if(!COPY.contains(m) || step.sourceRegister==null ||
                        !step.sourceRegister.matches("[AD][0-7]") ||
                        step.register==null ||
                        !step.register.matches("[AD][0-7]"))return false;
            }else if(step.kind==HardwareDataflow.Kind.ADJUST_POINTER){
                if(step.register==null || !step.register.matches("[AD][0-7]") ||
                        !(m.startsWith("ADD") || m.startsWith("SUB")) ||
                        step.writeBits==0)return false;
            }else if(step.kind==HardwareDataflow.Kind.CLOBBER_POINTER){
                if(step.register==null || !step.register.matches("[AD][0-7]"))
                    return false;
            }else if(step.kind==HardwareDataflow.Kind.OTHER) {
                if("RTS".equals(m)) {
                    if(!step.successors.isEmpty())return false;
                    returns++;
                }else if(!"NOP".equals(m) && !BRANCH.matcher(m).matches())
                    return false;
            }else return false; // Any STORE, MOVEC, unknown alias or effect.
            for(Long successor:step.successors){
                if(successor==null || !degree.containsKey(successor))
                    return false;
                degree.put(successor,degree.get(successor)+1);
                edges++;
            }
        }
        if(calls!=1 || returns==0 || edges>2*MAX_BRIDGE_STEPS)return false;
        // Topological sort and reachability in one pass. Every byte of the
        // checked bridge must be on a possible path from the exact entry.
        ArrayDeque<Long> ready=new ArrayDeque<>();
        for(var entry:degree.entrySet())
            if(entry.getValue()==0)ready.add(entry.getKey());
        if(ready.size()!=1 || ready.peekFirst()!=bridge.entry())return false;
        int examined=0;
        while(!ready.isEmpty()){
            long pc=ready.removeFirst();examined++;
            for(Long next:nodes.get(pc).successors){
                int left=degree.get(next)-1;
                degree.put(next,left);
                if(left==0)ready.addLast(next);
            }
        }
        return examined==nodes.size();
    }

    /**
     * Each outer CALL context uses a fresh, uncached bridge fixed point and
     * then invokes the existing one-hop closed-leaf validator on the inner
     * CALL. Only potential source STOREs at tracked MC68332 addresses are
     * returned; never a global function summary or Apply proposal.
     */
    public static Summary analyze(Collection<HardwareCallsiteRegisterFlow.Call> outer,
            Collection<Bridge> bridges,
            Collection<HardwareCallsiteRegisterFlow.Callee> leaves,
            Collection<Long> trackedAddresses,int displayLimit){
        if(outer==null || bridges==null || leaves==null ||
                outer.size()>MAX_OUTER_CALLS ||
                bridges.size()>MAX_OUTER_CALLS || leaves.size()>MAX_OUTER_CALLS ||
                displayLimit<1 || displayLimit>MAX_ROWS)
            throw new IllegalArgumentException("Two-hop source budget exceeded");
        // Apply the same source-address validation as the direct CALL lane
        // before running any seeded bridge or leaf fixed point.
        Set<Long> tracked=HardwareCallsiteRegisterFlow
            .validatedTargets(trackedAddresses);
        Map<Long,Bridge> bridgeByEntry=new HashMap<>();
        for(Bridge b:bridges)
            if(b==null || bridgeByEntry.putIfAbsent(b.entry(),b)!=null)
                throw new IllegalArgumentException("Duplicate/null bridge");
        Map<Long,HardwareCallsiteRegisterFlow.Callee> leafByEntry=
            new HashMap<>();
        for(var c:leaves)
            if(c==null || leafByEntry.putIfAbsent(c.entry(),c)!=null)
                throw new IllegalArgumentException("Duplicate/null final leaf");
        List<HardwareCallsiteRegisterFlow.Call> sorted=new ArrayList<>(outer);
        if(sorted.contains(null))
            throw new IllegalArgumentException("Null outer CALL");
        sorted.sort(Comparator.comparingLong(
                HardwareCallsiteRegisterFlow.Call::caller)
            .thenComparingLong(HardwareCallsiteRegisterFlow.Call::callPc));
        Set<String> seen=new HashSet<>();
        int eligible=0,rejected=0,unsafe=0,unresolved=0,badLeaf=0,
            unknownInner=0,truncated=0,unknownAliases=0,possible=0;
        List<Candidate> out=new ArrayList<>();
        for(var call:sorted){
            if(!seen.add(call.caller()+":"+call.callPc()))
                throw new IllegalArgumentException("Duplicate outer CALL");
            if(call.callerIncomplete() || call.directCallee()==null){
                rejected++;continue;
            }
            Map<String,Long> entryRegisters=noStack(call.agreedRegisters());
            if(entryRegisters.isEmpty()){rejected++;continue;}
            eligible++;
            Bridge bridge=bridgeByEntry.get(call.directCallee());
            if(bridge==null || !safeBridge(bridge)){unsafe++;continue;}
            if(bridge.finalTarget()==null){unresolved++;continue;}
            var leaf=leafByEntry.get(bridge.finalTarget());
            if(leaf==null){badLeaf++;continue;}
            int iterations=Math.min(30000,Math.max(300,
                bridge.steps().size()*20));
            var state=HardwareDataflow.analyzeWithEntryRegisters(
                bridge.entry(),bridge.steps(),tracked,iterations,
                entryRegisters);
            if(state.truncated){truncated++;continue;}
            Map<String,Long> inner=noStack(state.knownPointersAtEntry
                .getOrDefault(bridge.innerCallPc(),Map.of()));
            if(inner.isEmpty()){unknownInner++;continue;}
            var nestedCall=new HardwareCallsiteRegisterFlow.Call(
                bridge.entry(),bridge.innerCallPc(),bridge.finalTarget(),
                inner,false);
            var innerEvidence=HardwareCallsiteRegisterFlow.analyze(
                List.of(nestedCall),List.of(leaf),tracked,
                HardwareCallsiteRegisterFlow.MAX_REPORTED_ROWS);
            if(innerEvidence.rejectedNestedOrBadCfg()!=0 ||
                    innerEvidence.rejectedIncomplete()!=0 ||
                    innerEvidence.rejectedMissingCallee()!=0 ||
                    innerEvidence.truncatedCalls()!=0) {
                badLeaf++;continue;
            }
            unknownAliases+=innerEvidence.unresolvedAliases();
            possible+=innerEvidence.possibleStoreSites();
            for(var candidate:innerEvidence.candidates()){
                if(out.size()>=displayLimit)break;
                out.add(new Candidate(call.caller(),call.callPc(),
                    bridge.entry(),bridge.innerCallPc(),leaf.entry(),
                    candidate.storePc(),candidate.address(),
                    candidate.writtenWord(),candidate.writeBits(),
                    entryRegisters.size(),inner.size(),
                    candidate.priorUnknownCall(),
                    candidate.priorUnknownStore()));
            }
        }
        return new Summary(sorted.size(),eligible,rejected,unsafe,
            unresolved,badLeaf,unknownInner,truncated,unknownAliases,
            possible,possible>out.size(),out);
    }
}
