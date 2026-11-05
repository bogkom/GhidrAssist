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
    /** Maximum total CFG successor references in one source-level solve. */
    public static final int MAX_SOURCE_EDGES=200_000;

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
        /** Verified input-independent register constants assigned on leaf return. */
        public final Map<String,Long> verifiedCallReturns;
        public Step(long address,Kind kind,String register,long operand,long displacement,
                    Integer literalWord,int writeBits,Collection<Long> successors,String mnemonic){
            this.address=address;this.kind=Objects.requireNonNull(kind);
            this.register=register;this.sourceRegister=null;
            this.indexRegister=null;this.indexBits=0;this.indexScale=1;
            this.operand=operand;this.displacement=displacement;
            this.literalWord=literalWord;this.writeBits=writeBits;
            this.successors=List.copyOf(successors);this.mnemonic=mnemonic==null?"":mnemonic;
            this.sideEffectRegisters=Set.of();
            this.verifiedCallReturns=Map.of();
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
            this.verifiedCallReturns=Map.of();
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
            this.verifiedCallReturns=Map.of();
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
            this.verifiedCallReturns=original.verifiedCallReturns;
        }
        private Step(Step original,Map<String,Long> provedReturns){
            if(original.kind!=Kind.CALL_BARRIER)
                throw new IllegalArgumentException("Call returns require CALL_BARRIER");
            if(provedReturns==null || provedReturns.size()>14)
                throw new IllegalArgumentException("Invalid leaf return registers");
            for(var e:provedReturns.entrySet())
                if(e.getKey()==null || !e.getKey().matches("[AD][0-6]|D7") ||
                        e.getValue()==null)
                    throw new IllegalArgumentException("Unsafe leaf register");
            this.address=original.address;this.kind=original.kind;
            this.register=original.register;this.sourceRegister=original.sourceRegister;
            this.indexRegister=original.indexRegister;
            this.indexBits=original.indexBits;this.indexScale=original.indexScale;
            this.operand=original.operand;this.displacement=original.displacement;
            this.literalWord=original.literalWord;this.writeBits=original.writeBits;
            this.successors=original.successors;this.mnemonic=original.mnemonic;
            this.sideEffectRegisters=original.sideEffectRegisters;
            this.verifiedCallReturns=Map.copyOf(provedReturns);
        }
        public Step withSideEffects(Collection<String> updatedRegisters) {
            if(updatedRegisters==null || updatedRegisters.isEmpty())return this;
            return new Step(this,updatedRegisters);
        }
        public Step withVerifiedCallReturns(Map<String,Long> provedReturns){
            if(provedReturns==null || provedReturns.isEmpty())return this;
            return new Step(this,provedReturns);
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
        // Typed, bounded decoder only. There is no Java object deserialization.
        static Snapshot restore(long instruction,Kind kind,Long address,
                Integer writtenWord,int bits,String pointer,Long vbr,
                Map<Long,Integer> peripheral,boolean indirect,
                int min,int max,boolean unknownCall,boolean unknownStore) {
            if(instruction<0 || kind==null || !(
                    kind==Kind.STORE_DIRECT || kind==Kind.STORE_INDIRECT ||
                    kind==Kind.VBR_FROM_REGISTER || kind==Kind.VBR_CONSTANT) ||
                    min<0 || max<min || max>2 || peripheral==null ||
                    peripheral.size()>4096 ||
                    (pointer!=null && !pointer.matches("[AD][0-7]")) ||
                    (bits!=0 && bits!=8 && bits!=16 && bits!=32))
                throw new IllegalArgumentException("Invalid decoded CFG snapshot");
            return new Snapshot(instruction,kind,address,writtenWord,bits,
                pointer,vbr,peripheral,indirect,min,max,unknownCall,unknownStore);
        }
        private Snapshot(long instruction,Kind kind,Long effectiveAddress,
                Integer writtenWord,int bits,String pointer,Long vbr,
                Map<Long,Integer> peripheral,boolean indirect,int min,int max,
                boolean unknownCall,boolean unknownStore) {
            this.instruction=instruction;this.kind=kind;
            this.effectiveAddress=effectiveAddress;this.writtenWord=writtenWord;
            this.writeBits=bits;this.pointerRegister=pointer;this.vbr=vbr;
            this.knownPeripheralWords=Map.copyOf(peripheral);
            this.indirect=indirect;this.priorMmCandidateMin=min;
            this.priorMmCandidateMax=max;this.priorUnknownCall=unknownCall;
            this.priorUnknownStore=unknownStore;
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
        static Result restore(List<Snapshot> snapshots,int reachedNodes,int iterations,
                Map<Long,Map<String,Long>> pointers) {
            if(snapshots==null || pointers==null || reachedNodes<0 ||
                    reachedNodes>3000 ||
                    iterations<0 || iterations>30000 ||
                    snapshots.size()>512 ||
                    pointers.size()>3000)
                throw new IllegalArgumentException("Invalid fixed point bounds");
            Map<Long,Map<String,Long>> deep=new LinkedHashMap<>();
            long registers=0;
            for(var entry:pointers.entrySet()){
                if(entry.getKey()==null || entry.getKey()<0 ||
                        entry.getValue()==null)
                    throw new IllegalArgumentException("Null pointer state");
                registers+=entry.getValue().size();
                if(registers>4096)
                    throw new IllegalArgumentException("Too many register cells");
                for(String reg:entry.getValue().keySet())
                    if(reg==null || !reg.matches("[AD][0-7]") ||
                            entry.getValue().get(reg)==null)
                        throw new IllegalArgumentException("Invalid register snapshot");
                deep.put(entry.getKey(),Map.copyOf(entry.getValue()));
            }
            return new Result(snapshots,reachedNodes,iterations,false,
                Collections.unmodifiableMap(deep));
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
    /** Checkpointed state at a CFG instruction entry, never a finished result. */
    public record EntryState(Map<String,Long> pointers,
            Map<Long,Integer> peripherals,Long vbr,int mmMin,int mmMax,
            boolean unknownCall,boolean unknownStore) {
        public EntryState {
            if(pointers==null || peripherals==null || mmMin<0 ||
                    mmMax<mmMin || mmMax>2 || pointers.size()>16 ||
                    peripherals.size()>256 || (vbr!=null &&
                    (vbr<0 || vbr>MASK24)))
                throw new IllegalArgumentException("Invalid CFG work state");
            for(var p:pointers.entrySet())
                if(p.getKey()==null || !p.getKey().matches("[AD][0-7]") ||
                        p.getValue()==null || p.getValue()<0 ||
                        p.getValue()>MASK24)
                    throw new IllegalArgumentException("Bad register state");
            for(var p:peripherals.entrySet())
                if(p.getKey()==null || p.getKey()<0 ||
                        p.getKey()>MASK24 || p.getValue()==null ||
                        p.getValue()<0 || p.getValue()>65535)
                    throw new IllegalArgumentException("Bad MMIO state");
            pointers=Map.copyOf(pointers);
            peripherals=Map.copyOf(peripherals);
        }
    }
    public static final int MAX_PROGRESS_NODES=256;
    public static final int MAX_PROGRESS_CELLS=4096;
    /** An in-progress, unpublishable fixed-point worklist snapshot. */
    public record Progress(long entry,int maxIterations,int iterations,
            Map<Long,EntryState> atEntry,List<Long> pending) {
        public Progress {
            if(entry<0 || maxIterations<1 || maxIterations>30000 ||
                    iterations<0 || iterations>=maxIterations ||
                    atEntry==null || pending==null || atEntry.isEmpty() ||
                    atEntry.size()>MAX_PROGRESS_NODES ||
                    pending.isEmpty() || pending.size()>MAX_PROGRESS_NODES)
                throw new IllegalArgumentException("Invalid CFG progress bounds");
            int cells=0;
            for(var e:atEntry.entrySet()) {
                if(e.getKey()==null || e.getKey()<0 || e.getValue()==null)
                    throw new IllegalArgumentException("Invalid progress node");
                cells+=e.getValue().pointers().size()+
                    e.getValue().peripherals().size();
                if(cells>MAX_PROGRESS_CELLS)
                    throw new IllegalArgumentException("Oversized progress cells");
            }
            if(!atEntry.containsKey(entry) ||
                    pending.stream().distinct().count()!=pending.size() ||
                    !atEntry.keySet().containsAll(pending))
                throw new IllegalArgumentException("Invalid pending queue");
            atEntry=Map.copyOf(atEntry);
            pending=List.copyOf(pending);
        }
    }
    /** Exactly one of complete/progress is populated, or both null if too large. */
    public record Slice(Result complete,Progress progress) {
        public Slice {
            if(complete!=null && progress!=null)
                throw new IllegalArgumentException("Completed and pending");
        }
    }
    private static EntryState capture(State s) {
        return new EntryState(s.pointers,s.peripherals,s.vbr,
            s.mmCandidateMin,s.mmCandidateMax,s.crossedUnknownCall,
            s.crossedUnknownStore);
    }
    private static State restore(EntryState e) {
        State s=new State();
        s.pointers.putAll(e.pointers());s.peripherals.putAll(e.peripherals());
        s.vbr=e.vbr();s.mmCandidateMin=e.mmMin();s.mmCandidateMax=e.mmMax();
        s.crossedUnknownCall=e.unknownCall();s.crossedUnknownStore=e.unknownStore();
        return s;
    }

    public static Long pcodeInputValue(boolean constant,long literal,Long propagated){
        if(constant)return Long.valueOf(literal);
        return propagated;
    }

    /**
     * 68000 ADDQ/SUBQ to An adjusts the full address register regardless of
     * the instruction .W spelling. To Dn, .B/.W update only the low byte/word
     * and must NOT carry into untouched high bits. Zero means unknown size;
     * callers must clobber Dn rather than invent a full-register result.
     */
    static int registerAdjustWidth(String destination,String mnemonic) {
        if(destination==null || mnemonic==null ||
                !destination.matches("[AD][0-7]"))
            return 0;
        if(destination.startsWith("A"))return 32;
        String spelling=mnemonic.toUpperCase(java.util.Locale.ROOT);
        if(spelling.endsWith(".B"))return 8;
        if(spelling.endsWith(".W"))return 16;
        if(spelling.endsWith(".L"))return 32;
        return 0;
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
    private static int storeBytes(int bits) {
        return switch(bits) {
            case 8 -> 1;
            case 16 -> 2;
            case 32 -> 4;
            default -> 0;
        };
    }

    // CPU32 source-level external addresses are modeled modulo 24 bits.
    // A long write at 0xFFFFFE can also touch a tracked word at 0x000000.
    private static boolean overlapsBytes(long start,int size,
                                         long target,int targetSize) {
        for(int i=0;i<size;i++)
            for(int j=0;j<targetSize;j++)
                if(((start+i)&MASK24)==((target+j)&MASK24))
                    return true;
        return false;
    }

    /**
     * Candidate touch of the MC68332 MM bit's LOW BYTE under either MM
     * mapping. A partial/spanning STORE is UNKNOWN first-site evidence, not
     * a known 16-bit SIMCR value or proof of hardware latch execution.
     */
    static boolean mayTouchSimcrMmLowByte(Long address,int bits) {
        int bytes=storeBytes(bits);
        return address!=null && bytes>0 &&
            (overlapsBytes(address,bytes,0x7ffa01L,1) ||
             overlapsBytes(address,bytes,0xfffa01L,1));
    }

    private static boolean candidateSimcrStore(Step step, Long address) {
        return mayTouchSimcrMmLowByte(address,step.writeBits);
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
                    // Dn size is required. A partial Dn arithmetic update
                    // must NOT carry into the preserved high byte/word.
                    if(v==null || step.register.startsWith("D") &&
                            step.writeBits!=8 && step.writeBits!=16 &&
                            step.writeBits!=32) {
                        s.pointers.remove(step.register);
                    }else {
                        long mask=step.register.startsWith("D") &&
                            step.writeBits==8?0xffL:
                            step.register.startsWith("D") &&
                            step.writeBits==16?0xffffL:MASK24;
                        long changed=(v & ~mask) |
                            ((v+step.operand)&mask);
                        s.pointers.put(step.register,changed&MASK24);
                    }
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
                    int bytes = storeBytes(step.writeBits);
                    if(bytes==0) {
                        s.peripherals.clear();
                        s.crossedUnknownStore=true;
                    } else {
                        // Source/word windows can cross 0xFFFFFF:
                        // invalidate high and wrapped low bytes alike.
                        s.peripherals.keySet().removeIf(reg ->
                            overlapsBytes(address,bytes,reg,2));
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
                // Register evidence is reintroduced only after the generic
                // CALL barrier, and only from a strictly verified leaf.
                for(var proved:step.verifiedCallReturns.entrySet())
                    s.pointers.put(proved.getKey(),proved.getValue()&MASK24);
            }
            default -> {}
        }
        // Apply implicit auto-index changes AFTER interpreting the current
        // instruction's effective address (post-increment uses old A register).
        // The pre-decrement form is unresolved unless modeled separately, but
        // in either case a stale pointer must not survive to a later STORE.
        for(String reg:step.sideEffectRegisters)
            // ABI P-code clobbers are effects during the call. An
            // unconditional leaf proof establishes the result AFTER RTS,
            // and therefore takes precedence over that generic clobber.
            if(step.kind!=Kind.CALL_BARRIER ||
                    !step.verifiedCallReturns.containsKey(reg))
                s.pointers.remove(reg);
        return s;
    }
    /**
     * Find the least fixed point of reachable CFG edges starting at entry
     * with completely unknown registers. Conservative joins collapse
     * incompatible predecessor values to unknown.
     */
    public static Result analyze(long entry,Collection<Step> steps,
                                 Collection<Long> peripherals,int maxIterations){
        // The legacy non-checkpointed API retains its exact bounded behavior.
        Slice one=analyzeSlice(entry,steps,peripherals,maxIterations,null,
            maxIterations);
        if(one.complete()==null)
            throw new IllegalStateException("Unbounded CFG input unexpectedly");
        return one.complete();
    }

    /**
     * Execute at most sliceIterations fixed-point transfers, retaining the
     * original deterministic worklist ordering. Progress is NEVER analysis
     * evidence: only a completed Result can be published to a caller.
     *
     * A progress snapshot is eligible only when every live state fits strict
     * resource caps. For oversized functions return (null,null): the caller
     * must run ordinary analyze() without persistence.
     */
    /**
     * Contextual, read-only one-hop analysis for a particular source CALL
     * instruction. Entry A/D values are caller-predecessor-agreed constants,
     * NOT a function-wide, input-independent guarantee. This does not alter
     * the legacy cold solve or any GA-12 cache/durable checkpoint key.
     *
     * NEVER publish this call-site result as a full-program Review/Apply
     * proof: a different caller or unobserved runtime path may disagree.
     */
    public static Result analyzeWithEntryRegisters(long entry,
            Collection<Step> steps,Collection<Long> peripherals,
            int maxIterations,Map<String,Long> entryRegisters){
        if(entryRegisters==null || entryRegisters.size()>16)
            throw new IllegalArgumentException("Invalid caller register count");
        for(var e:entryRegisters.entrySet())
            if(e.getKey()==null || !e.getKey().matches("[AD][0-7]") ||
                    e.getValue()==null || e.getValue()<0 ||
                    e.getValue()>MASK24)
                throw new IllegalArgumentException("Invalid caller register value");
        Slice one=analyzeSlice(entry,steps,peripherals,maxIterations,
            null,maxIterations,entryRegisters);
        if(one.complete()==null)
            throw new IllegalStateException("Incomplete contextual CFG solve");
        return one.complete();
    }
    public static Slice analyzeSlice(long entry,Collection<Step> steps,
            Collection<Long> peripherals,int maxIterations,Progress previous,
            int sliceIterations){
        // Existing callers (including GA-12 persisted progress) always start
        // without injected registers, preserving their exact hash/semantics.
        return analyzeSlice(entry,steps,peripherals,maxIterations,previous,
            sliceIterations,Map.of());
    }
    private static Slice analyzeSlice(long entry,Collection<Step> steps,
            Collection<Long> peripherals,int maxIterations,Progress previous,
            int sliceIterations,Map<String,Long> initialRegisters){
        if(maxIterations<1 || sliceIterations<1 ||
                steps==null || peripherals==null ||
                initialRegisters==null || (previous!=null &&
                    !initialRegisters.isEmpty()))
            throw new IllegalArgumentException("Invalid CFG work budget");
        Map<Long,Step> graph=new LinkedHashMap<>();
        long edgeCount=0;
        for(Step s:steps) {
            if(s==null || graph.putIfAbsent(s.address,s)!=null)
                throw new IllegalArgumentException("Null or duplicate CFG PC");
            // An iteration cap bounds solver updates, not the number of
            // successor references examined on each update. Refuse an
            // oversized source inventory before cold OR resumed traversal,
            // rather than publishing a misleading partial MMIO snapshot.
            edgeCount+=s.successors.size();
            if(edgeCount>MAX_SOURCE_EDGES)
                throw new IllegalArgumentException("Unbounded source CFG edges");
        }
        Set<Long> targets=new LinkedHashSet<>(peripherals);
        Map<Long,State> input=new HashMap<>();
        ArrayDeque<Long> queue=new ArrayDeque<>();
        Set<Long> queued=new LinkedHashSet<>();
        int iterations=0;
        if(previous==null) {
            if(graph.containsKey(entry)){
                State initial=new State();
                initial.pointers.putAll(initialRegisters);
                input.put(entry,initial);queue.add(entry);queued.add(entry);
            }
        } else {
            if(previous.entry()!=entry ||
                    previous.maxIterations()!=maxIterations ||
                    !graph.keySet().containsAll(previous.atEntry().keySet()))
                throw new IllegalArgumentException("Stale CFG progress");
            for(var e:previous.atEntry().entrySet())
                input.put(e.getKey(),restore(e.getValue()));
            for(Long pc:previous.pending()) {
                if(!graph.containsKey(pc) || !queued.add(pc))
                    throw new IllegalArgumentException("Invalid worklist PC");
                queue.addLast(pc);
            }
            iterations=previous.iterations();
        }
        int inSlice=0;
        while(!queue.isEmpty() && iterations<maxIterations &&
                inSlice<sliceIterations){
            long pc=queue.removeFirst();queued.remove(pc);
            Step step=graph.get(pc);
            if(step==null)continue;
            State out=transfer(step,input.get(pc),targets);
            iterations++;inSlice++;
            for(Long successor:step.successors){
                if(!graph.containsKey(successor))continue;
                State prior=input.get(successor);
                boolean changed=false;
                if(prior==null){input.put(successor,out.copy());changed=true;}
                else changed=prior.join(out);
                if(changed && queued.add(successor))queue.addLast(successor);
            }
        }
        if(!queue.isEmpty()){
            if(iterations>=maxIterations)
                return new Slice(new Result(List.of(),input.size(),
                    iterations,true,Map.of()),null);
            if(maxIterations>30000 || input.size()>MAX_PROGRESS_NODES ||
                    queue.size()>MAX_PROGRESS_NODES)
                return new Slice(null,null);
            Map<Long,EntryState> states=new HashMap<>();
            try{
                for(var e:input.entrySet())states.put(e.getKey(),capture(e.getValue()));
                return new Slice(null,new Progress(entry,maxIterations,
                    iterations,states,List.copyOf(queue)));
            }catch(IllegalArgumentException tooLarge){
                return new Slice(null,null);
            }
        }
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
        return new Slice(new Result(found,input.size(),iterations,false,pointers),null);
    }
}
