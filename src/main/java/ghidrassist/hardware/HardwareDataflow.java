package ghidrassist.hardware;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Bounded, intraprocedural constant propagation on an explicit CFG.
 *
 * Lattice: UNREACHED -> a known constant -> UNKNOWN, with a separate known
 * value for each A/D register and peripheral word. Joins preserve a constant
 * ONLY if every incoming reachable predecessor agrees. No branch predicate
 * reasoning, no interprocedural propagation and no proof of real execution.
 *
 * Pure Java: synthetic tests do not require a Ghidra install or real firmware.
 */
public final class HardwareDataflow {
    private HardwareDataflow() {}
    public static final long MASK24=0xffffffL;

    public enum Kind {
        OTHER, SET_POINTER, COPY_POINTER, ADJUST_POINTER, CLOBBER_POINTER,
        STORE_DIRECT, STORE_INDIRECT, VBR_FROM_REGISTER, VBR_CONSTANT, CALL_BARRIER
    }
    public static final class Step {
        public final long address;
        public final Kind kind;
        public final String register;
        public final String sourceRegister;
        public final String indexRegister;
        public final int indexBits;
        public final int indexScale;
        public final long operand;
        public final long displacement;
        public final Integer literalWord;
        public final int writeBits;
        public final List<Long> successors;
        public final String mnemonic;
        public final Set<String> sideEffectRegisters;
        public Step(long address,Kind kind,String register,long operand,long displacement,
                    Integer literalWord,int writeBits,Collection<Long> successors,String mnemonic){
            this.address=address;this.kind=Objects.requireNonNull(kind);
            this.register=register;this.sourceRegister=null;
            this.indexRegister=null;this.indexBits=0;this.indexScale=1;
            this.operand=operand;this.displacement=displacement;
            this.literalWord=literalWord;this.writeBits=writeBits;
            this.successors=List.copyOf(successors);this.mnemonic=mnemonic==null?"":mnemonic;
            this.sideEffectRegisters=Set.of();
        }
        public Step(long address,Kind kind,String register,String sourceRegister,long operand,
                    long displacement,Integer literalWord,int writeBits,
                    Collection<Long> successors,String mnemonic){
            this.address=address;this.kind=Objects.requireNonNull(kind);
            this.register=register;this.sourceRegister=sourceRegister;
            this.indexRegister=null;this.indexBits=0;this.indexScale=1;
            this.operand=operand;this.displacement=displacement;
            this.literalWord=literalWord;this.writeBits=writeBits;
            this.successors=List.copyOf(successors);this.mnemonic=mnemonic==null?"":mnemonic;
            this.sideEffectRegisters=Set.of();
        }
        /** Indexed STORE: base + displacement + signed .W/.L index * scale. */
        public Step(long address, String baseRegister, String sourceRegister,
                String indexRegister, int indexBits, int indexScale,
                long displacement, Integer literalWord, int writeBits,
                Collection<Long> successors, String mnemonic) {
            this.address=address;this.kind=Kind.STORE_INDIRECT;
            this.register=baseRegister;this.sourceRegister=sourceRegister;
            if(baseRegister==null || !baseRegister.matches("A[0-7]") ||
                    indexRegister==null || !indexRegister.matches("[AD][0-7]") ||
                    (indexBits!=16 && indexBits!=32) ||
                    (indexScale!=1 && indexScale!=2 &&
                     indexScale!=4 && indexScale!=8))
                throw new IllegalArgumentException("Invalid indexed STORE");
            this.indexRegister=indexRegister;
            this.indexBits=indexBits;this.indexScale=indexScale;
            this.operand=0;this.displacement=displacement;
            this.literalWord=literalWord;this.writeBits=writeBits;
            this.successors=List.copyOf(successors);
            this.mnemonic=mnemonic==null?"":mnemonic;
            this.sideEffectRegisters=Set.of();
        }
        private Step(Step original,Collection<String> sideEffects) {
            this.address=original.address;this.kind=original.kind;
            this.register=original.register;this.sourceRegister=original.sourceRegister;
            this.indexRegister=original.indexRegister;
            this.indexBits=original.indexBits;this.indexScale=original.indexScale;
            this.operand=original.operand;this.displacement=original.displacement;
            this.literalWord=original.literalWord;this.writeBits=original.writeBits;
            this.successors=original.successors;this.mnemonic=original.mnemonic;
            for(String reg:sideEffects)
                if(reg==null || !reg.matches("[AD][0-7]"))
                    throw new IllegalArgumentException("Invalid register side effect");
            this.sideEffectRegisters=Set.copyOf(sideEffects);
        }
        public Step withSideEffects(Collection<String> updatedRegisters) {
            if(updatedRegisters==null || updatedRegisters.isEmpty())return this;
            return new Step(this,updatedRegisters);
        }
    }
    public static final class Snapshot {
        public final long instruction;
        public final Kind kind;
        public final Long effectiveAddress;
        public final Integer writtenWord;
        public final int writeBits;
        public final String pointerRegister;
        public final Long vbr;
        public final Map<Long,Integer> knownPeripheralWords;
        public final boolean indirect;
        /** Number of potential SIMCR writes on paths since FUNCTION entry, saturated at 2+. */
        public final int priorMmCandidateMin, priorMmCandidateMax;
        /** Calls may mutate MCU state outside this function. */
        public final boolean priorUnknownCall;
        /** May have an unrecognized write with an unknown effective address. */
        public final boolean priorUnknownStore;
        private Snapshot(Step step,Long address,Integer value,State before,State after) {
            instruction=step.address;kind=step.kind;effectiveAddress=address;
            writtenWord=value;writeBits=step.writeBits;pointerRegister=step.register;
            vbr=after.vbr;
            knownPeripheralWords=Map.copyOf(after.peripherals);
            indirect=step.kind==Kind.STORE_INDIRECT;
            priorMmCandidateMin=before.mmCandidateMin;
            priorMmCandidateMax=before.mmCandidateMax;
            priorUnknownCall=before.crossedUnknownCall;
            priorUnknownStore=before.crossedUnknownStore;
        }
    }
    public static final class Result {
        public final List<Snapshot> snapshots;
        public final int reachedNodes,iterations;
        public final boolean truncated;
        public final Map<Long,Map<String,Long>> knownPointersAtEntry;
        private Result(List<Snapshot> snapshots,int reachedNodes,int iterations,
                       boolean truncated,Map<Long,Map<String,Long>> pointers){
            this.snapshots=List.copyOf(snapshots);this.reachedNodes=reachedNodes;
            this.iterations=iterations;this.truncated=truncated;
            this.knownPointersAtEntry=Collections.unmodifiableMap(pointers);
        }
    }
    private static final class State {
        private final Map<String,Long> pointers=new HashMap<>();
        private final Map<Long,Integer> peripherals=new HashMap<>();
        private Long vbr;
        private int mmCandidateMin, mmCandidateMax;
        private boolean crossedUnknownCall;
        private boolean crossedUnknownStore;
        private State copy(){
            State s=new State();s.pointers.putAll(pointers);
            s.peripherals.putAll(peripherals);s.vbr=vbr;
            s.mmCandidateMin=mmCandidateMin;s.mmCandidateMax=mmCandidateMax;
            s.crossedUnknownCall=crossedUnknownCall;
            s.crossedUnknownStore=crossedUnknownStore;return s;
        }
        private static <K,V> void intersect(Map<K,V> before,Map<K,V> incoming){
            before.entrySet().removeIf(e->!Objects.equals(incoming.get(e.getKey()),e.getValue()));
        }
        private boolean join(State rhs) {
            State b=copy();
            intersect(pointers,rhs.pointers);
            intersect(peripherals,rhs.peripherals);
            if(!Objects.equals(vbr,rhs.vbr))vbr=null;
            mmCandidateMin=Math.min(mmCandidateMin,rhs.mmCandidateMin);
            mmCandidateMax=Math.max(mmCandidateMax,rhs.mmCandidateMax);
            crossedUnknownCall |= rhs.crossedUnknownCall;
            crossedUnknownStore |= rhs.crossedUnknownStore;
            return !pointers.equals(b.pointers)||!peripherals.equals(b.peripherals)||
                    !Objects.equals(vbr,b.vbr)||
                    mmCandidateMin!=b.mmCandidateMin||
                    mmCandidateMax!=b.mmCandidateMax||
                    crossedUnknownCall!=b.crossedUnknownCall ||
                    crossedUnknownStore!=b.crossedUnknownStore;
        }
    }
    public static Long pcodeInputValue(boolean constant,long literal,Long propagated){
        if(constant)return Long.valueOf(literal);
        return propagated;
    }
    private static Long resolve(Step step,State s) {
        if(step.kind==Kind.STORE_DIRECT) return step.operand&MASK24;
        if(step.kind==Kind.STORE_INDIRECT){
            Long base=s.pointers.get(step.register);
            if(base==null)return null;
            long indexOffset=0;
            if(step.indexRegister!=null) {
                Long index=s.pointers.get(step.indexRegister);
                if(index==null)return null;
                // A .W index is sign-extended before scaling; for .L, the
                // stored 24-bit two's-complement value is sufficient modulo
                // the 24-bit external address bus.
                long signed=step.indexBits==16?(short)(index&0xffffL):index;
                indexOffset=signed*step.indexScale;
            }
            return (base+step.displacement+indexOffset)&MASK24;
        }
        return null;
    }
    private static Long knownStoreValue(Step step,State s) {
        if(step.literalWord!=null)return step.literalWord.longValue();
        return step.sourceRegister==null?null:s.pointers.get(step.sourceRegister);
    }
    /**
     * Addresses are only *candidate* SIMCR aliases for the chosen MC68332
     * profile. A static site is not evidence that MM is mapped there, that
     * the code executes, or that the MM write-once latch is still available.
     */
    private static boolean candidateSimcrStore(Step step, Long address) {
        if (address==null) return false;
        boolean word=step.writeBits==16 &&
            (address==0x7ffa00L || address==0xfffa00L);
        boolean lowByte=step.writeBits==8 &&
            (address==0x7ffa01L || address==0xfffa01L);
        return word || lowByte;
    }

    private static State transfer(Step step,State in,Set<Long> targets){
        State s=in.copy();
        switch(step.kind) {
            case SET_POINTER -> {
                if(step.register!=null)s.pointers.put(step.register,step.operand&MASK24);
            }
            case COPY_POINTER -> {
                if(step.register!=null){
                    Long source=s.pointers.get(step.sourceRegister);
                    if(source==null)s.pointers.remove(step.register);
                    else s.pointers.put(step.register,source);
                }
            }
            case ADJUST_POINTER -> {
                if(step.register!=null){
                    Long v=s.pointers.get(step.register);
                    if(v==null)s.pointers.remove(step.register);
                    else s.pointers.put(step.register,(v+step.operand)&MASK24);
                }
            }
            case CLOBBER_POINTER -> {
                if(step.register!=null)s.pointers.remove(step.register);
            }
            case STORE_DIRECT,STORE_INDIRECT -> {
                Long address=resolve(step,in);
                if(candidateSimcrStore(step,address)) {
                    s.mmCandidateMin=Math.min(2,in.mmCandidateMin+1);
                    s.mmCandidateMax=Math.min(2,in.mmCandidateMax+1);
                }
                if(address==null) {
                    // Unknown pointer/alias can target ANY tracked MMIO.
                    // Otherwise a stale CSBAR value would masquerade as
                    // a valid later hardware configuration.
                    s.peripherals.clear();
                    s.crossedUnknownStore=true;
                } else {
                    // Peripheral snapshots model whole 16-bit registers.
                    // Any overlapping byte, word, long or unknown-size write
                    // invalidates the full register value. Reintroduce a
                    // constant only for an aligned, complete 16-bit write
                    // with a fully known source.
                    int bytes = switch(step.writeBits) {
                        case 8 -> 1;
                        case 16 -> 2;
                        case 32 -> 4;
                        default -> 0;
                    };
                    if(bytes==0) {
                        s.peripherals.clear();
                        s.crossedUnknownStore=true;
                    } else {
                        long last=address+bytes-1;
                        s.peripherals.keySet().removeIf(reg ->
                            address<=reg+1 && reg<=last);
                        if(step.writeBits==16 && targets.contains(address) &&
                                (address&1)==0) {
                            Long known=knownStoreValue(step,in);
                            if(known!=null)
                                s.peripherals.put(address,(int)(known&0xffff));
                        }
                    }
                }
            }
            case VBR_CONSTANT -> s.vbr=step.operand&MASK24;
            case VBR_FROM_REGISTER -> s.vbr=s.pointers.get(step.register);
            case CALL_BARRIER -> {
                // A call may change any peripheral or register; no summary
                // means constants cannot cross this boundary.
                s.pointers.clear();s.peripherals.clear();s.vbr=null;
                s.crossedUnknownCall=true;
            }
            default -> {}
        }
        // Apply implicit auto-index changes AFTER interpreting the current
        // instruction's effective address (post-increment uses old A register).
        // The pre-decrement form is unresolved unless modeled separately, but
        // in either case a stale pointer must not survive to a later STORE.
        for(String reg:step.sideEffectRegisters)s.pointers.remove(reg);
        return s;
    }
    /**
     * Find the least fixed point of reachable CFG edges starting at entry
     * with completely unknown registers. Conservative joins collapse
     * incompatible predecessor values to unknown.
     */
    public static Result analyze(long entry,Collection<Step> steps,
                                 Collection<Long> peripherals,int maxIterations){
        if(maxIterations<1)throw new IllegalArgumentException("Iteration limit must be positive");
        Map<Long,Step> graph=new LinkedHashMap<>();
        for(Step s:steps)
            if(graph.putIfAbsent(s.address,s)!=null)
                throw new IllegalArgumentException("Duplicate instruction address "+s.address);
        Set<Long> targets=new LinkedHashSet<>(peripherals);
        Map<Long,State> input=new HashMap<>();
        ArrayDeque<Long> queue=new ArrayDeque<>();
        Set<Long> queued=new LinkedHashSet<>();
        if(graph.containsKey(entry)){
            input.put(entry,new State());queue.add(entry);queued.add(entry);
        }
        int iterations=0;
        while(!queue.isEmpty() && iterations<maxIterations){
            long pc=queue.removeFirst();queued.remove(pc);
            Step step=graph.get(pc);
            if(step==null)continue;
            State s=transfer(step,input.get(pc),targets);
            iterations++;
            for(Long successor:step.successors){
                if(!graph.containsKey(successor))continue;
                State prior=input.get(successor);
                boolean changed=false;
                if(prior==null){input.put(successor,s.copy());changed=true;}
                else changed=prior.join(s);
                if(changed && queued.add(successor))queue.addLast(successor);
            }
        }
        boolean truncated=!queue.isEmpty();
        // An unfinished fixed point may still have branch-dependent constants
        // from predecessors not yet visited. Publishing them as evidence would
        // be unsound. Return only the truncation marker, never inferred values.
        if(truncated)return new Result(List.of(),input.size(),iterations,true,Map.of());
        List<Snapshot> found=new ArrayList<>();
        Map<Long,Map<String,Long>> pointers=new LinkedHashMap<>();
        for(Step step:graph.values()){
            State before=input.get(step.address);
            if(before==null)continue;
            if(!before.pointers.isEmpty())
                pointers.put(step.address,Map.copyOf(before.pointers));
            if(step.kind==Kind.STORE_DIRECT||step.kind==Kind.STORE_INDIRECT ||
                    step.kind==Kind.VBR_CONSTANT||step.kind==Kind.VBR_FROM_REGISTER){
                Long effective=resolve(step,before);
                State after=transfer(step,before,targets);
                Long value=knownStoreValue(step,before);
                found.add(new Snapshot(step,effective,
                    step.writeBits==16 && value!=null?(int)(value&0xffff):null,
                    before,after));
            }
        }
        return new Result(found,input.size(),iterations,truncated,pointers);
    }
}
