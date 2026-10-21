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
        OTHER, SET_POINTER, ADJUST_POINTER, CLOBBER_POINTER,
        STORE_DIRECT, STORE_INDIRECT, VBR_FROM_REGISTER, VBR_CONSTANT, CALL_BARRIER
    }
    public static final class Step {
        public final long address;
        public final Kind kind;
        public final String register;
        public final long operand;
        public final long displacement;
        public final Integer literalWord;
        public final int writeBits;
        public final List<Long> successors;
        public final String mnemonic;
        public Step(long address,Kind kind,String register,long operand,long displacement,
                    Integer literalWord,int writeBits,Collection<Long> successors,String mnemonic){
            this.address=address;this.kind=Objects.requireNonNull(kind);
            this.register=register;this.operand=operand;this.displacement=displacement;
            this.literalWord=literalWord;this.writeBits=writeBits;
            this.successors=List.copyOf(successors);this.mnemonic=mnemonic==null?"":mnemonic;
        }
    }
    public static final class Snapshot {
        public final long instruction;
        public final Kind kind;
        public final Long effectiveAddress;
        public final Integer writtenWord;
        public final String pointerRegister;
        public final Long vbr;
        public final Map<Long,Integer> knownPeripheralWords;
        public final boolean indirect;
        private Snapshot(Step step,Long address,State after) {
            instruction=step.address;kind=step.kind;effectiveAddress=address;
            writtenWord=step.literalWord;pointerRegister=step.register;
            vbr=after.vbr;
            knownPeripheralWords=Map.copyOf(after.peripherals);
            indirect=step.kind==Kind.STORE_INDIRECT;
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
        private State copy(){
            State s=new State();s.pointers.putAll(pointers);
            s.peripherals.putAll(peripherals);s.vbr=vbr;return s;
        }
        private static <K,V> void intersect(Map<K,V> before,Map<K,V> incoming){
            before.entrySet().removeIf(e->!Objects.equals(incoming.get(e.getKey()),e.getValue()));
        }
        private boolean join(State rhs) {
            State b=copy();
            intersect(pointers,rhs.pointers);
            intersect(peripherals,rhs.peripherals);
            if(!Objects.equals(vbr,rhs.vbr))vbr=null;
            return !pointers.equals(b.pointers)||!peripherals.equals(b.peripherals)||
                    !Objects.equals(vbr,b.vbr);
        }
    }
    private static Long resolve(Step step,State s) {
        if(step.kind==Kind.STORE_DIRECT) return step.operand&MASK24;
        if(step.kind==Kind.STORE_INDIRECT){
            Long base=s.pointers.get(step.register);
            return base==null?null:(base+step.displacement)&MASK24;
        }
        return null;
    }
    private static State transfer(Step step,State in,Set<Long> targets){
        State s=in.copy();
        switch(step.kind) {
            case SET_POINTER -> {
                if(step.register!=null)s.pointers.put(step.register,step.operand&MASK24);
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
                if(address!=null && targets.contains(address)){
                    // Only full 16-bit immediate overwrites are firm register
                    // constants; BCLR, BSET, MOVE.B and MOVE.L remain unknown.
                    if(step.writeBits==16 && step.literalWord!=null)
                        s.peripherals.put(address,step.literalWord&0xffff);
                    else s.peripherals.remove(address);
                }
            }
            case VBR_CONSTANT -> s.vbr=step.operand&MASK24;
            case VBR_FROM_REGISTER -> s.vbr=s.pointers.get(step.register);
            case CALL_BARRIER -> {
                // A call may change any peripheral or register; no summary
                // means constants cannot cross this boundary.
                s.pointers.clear();s.peripherals.clear();s.vbr=null;
            }
            default -> {}
        }
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
                found.add(new Snapshot(step,effective,after));
            }
        }
        return new Result(found,input.size(),iterations,truncated,pointers);
    }
}
