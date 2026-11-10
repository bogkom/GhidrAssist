package ghidrassist.hardware;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;
import java.util.ArrayDeque;
import java.util.Objects;
import java.util.Optional;

/**
 * Opt-in, per-function restart cache: one bounded completed fixed point per
 * deterministic (project, function entry) disk slot. This deliberately uses
 * the exact Ghidra full-input/JAR key from GA-12, PLUS a full Step hash.
 */
public final class HardwareDurableFunctionStages {
    private HardwareDurableFunctionStages(){}
    /** Only the first N eligible functions are stored on disk per pass. */
    public static final int MAX_DURABLE_FUNCTIONS=64;

    /**
     * Independently audit a decoded durable payload against the ACTUAL
     * translated, input-hashed CFG, not merely the outer SHA envelope.
     * Only a bounded graph with an exact entry and source-reachable nodes
     * may supply prior work or a completed post-CALL/MMIO/VBR fixed point.
     * Missing/out-of-body successors are ignored as in HardwareDataflow;
     * their dynamic execution is UNKNOWN, not invented by this gate.
     */
    private static Map<Long,HardwareDataflow.Step> reachableSource(
            long entry,Collection<HardwareDataflow.Step> steps) {
        if(entry<0 || steps==null || steps.isEmpty() ||
                steps.size()>HardwareFunctionStageCache.MAX_STEPS_PER_FUNCTION)
            return null;
        Map<Long,HardwareDataflow.Step> graph=new HashMap<>();
        long edges=0;
        for(var step:steps) {
            if(step==null || step.address<0 ||
                    graph.putIfAbsent(step.address,step)!=null)
                return null;
            edges+=step.successors.size();
            if(edges>HardwareDataflow.MAX_SOURCE_EDGES)return null;
        }
        if(!graph.containsKey(entry))return null;
        Map<Long,HardwareDataflow.Step> visited=new HashMap<>();
        ArrayDeque<Long> queue=new ArrayDeque<>();
        Set<Long> scheduled=new HashSet<>();
        queue.add(entry);scheduled.add(entry);
        while(!queue.isEmpty()) {
            long pc=queue.removeFirst();
            var step=graph.get(pc);
            if(step==null)continue;
            visited.put(pc,step);
            for(Long next:step.successors)
                if(next!=null && graph.containsKey(next) &&
                        scheduled.add(next))
                    queue.addLast(next);
        }
        return visited;
    }

    private static boolean sourceBoundProgress(long entry,
            Collection<HardwareDataflow.Step> steps,
            HardwareDataflow.Progress progress) {
        if(progress==null || progress.entry()!=entry)return false;
        var reachable=reachableSource(entry,steps);
        return reachable!=null &&
            reachable.keySet().containsAll(progress.atEntry().keySet()) &&
            reachable.keySet().containsAll(progress.pending());
    }

    /**
     * A valid digest is not independent proof of the semantic content of a
     * decoded per-function snapshot. Check reachable source PC, exact Step
     * kind/width/register, complete effect-site coverage and 24-bit model
     * value bounds before restoring or replacing a completed checkpoint.
     * Does not reconstruct execution order, caller context or active MM.
     */
    /**
     * GA-02/03 + GA-12: check a decoded STORE/VBR value witness against
     * the SAME exact translated Step and pre-instruction register map
     * already carried by the completed fixed point. This intentionally
     * avoids re-running the expensive whole-function fixed point.
     * It cannot independently prove that an upstream register value
     * was derived correctly; that requires the original CFG solve.
     */
    private static Long sourceAddress(HardwareDataflow.Step step,
            Map<String,Long> pointers) {
        if(step.kind==HardwareDataflow.Kind.STORE_DIRECT)
            return step.operand&HardwareDataflow.MASK24;
        if(step.kind!=HardwareDataflow.Kind.STORE_INDIRECT)
            return null;
        Long base=step.register==null?null:pointers.get(step.register);
        if(base==null)return null;
        long offset=0;
        if(step.indexRegister!=null){
            Long index=pointers.get(step.indexRegister);
            if(index==null)return null;
            long signed=step.indexBits==16?
                (short)(index&0xffffL):index;
            offset=signed*step.indexScale;
        }
        return (base+step.displacement+offset)&HardwareDataflow.MASK24;
    }

    private static Integer sourceWord(HardwareDataflow.Step step,
            Map<String,Long> pointers) {
        if(step.writeBits!=16)return null;
        // Do NOT use a Long/long conditional here: Java would
        // silently unbox the absent register value and throw NPE.
        // An unknown D/A source is legitimate source uncertainty.
        Long known;
        if(step.literalWord!=null)
            known=step.literalWord.longValue();
        else if(step.sourceRegister!=null)
            known=pointers.get(step.sourceRegister);
        else
            known=null;
        return known==null?null:(int)(known&0xffff);
    }

    private static boolean overlaps(long address,int bytes,long register) {
        for(int a=0;a<bytes;a++)
            for(int r=0;r<2;r++)
                if(((address+a)&HardwareDataflow.MASK24)==
                        ((register+r)&HardwareDataflow.MASK24))
                    return true;
        return false;
    }

    private static boolean sourceValueWitness(
            HardwareDataflow.Step step,HardwareDataflow.Snapshot snapshot,
            Map<String,Long> pointers,Set<Long> tracked) {
        Long expectedAddress=sourceAddress(step,pointers);
        if(!Objects.equals(expectedAddress,snapshot.effectiveAddress) ||
                !Objects.equals(sourceWord(step,pointers),snapshot.writtenWord))
            return false;
        if(step.kind==HardwareDataflow.Kind.VBR_CONSTANT &&
                !Objects.equals(snapshot.vbr,
                    step.operand&HardwareDataflow.MASK24))
            return false;
        if(step.kind==HardwareDataflow.Kind.VBR_FROM_REGISTER &&
                !Objects.equals(snapshot.vbr,step.register==null?
                    null:pointers.get(step.register)))
            return false;
        if(!tracked.containsAll(snapshot.knownPeripheralWords.keySet()))
            return false;

        if(step.kind!=HardwareDataflow.Kind.STORE_DIRECT &&
                step.kind!=HardwareDataflow.Kind.STORE_INDIRECT)
            return true;
        // The source-level peripheral lattice stores ONLY whole 16-bit
        // register values. Unknown address/width clears the whole table;
        // partial/overlapping stores invalidate old values, and ONLY an
        // aligned complete known 16-bit write can reintroduce a constant.
        int bytes=switch(step.writeBits){
            case 8 -> 1;
            case 16 -> 2;
            case 32 -> 4;
            default -> 0;
        };
        if(expectedAddress==null || bytes==0)
            return snapshot.knownPeripheralWords.isEmpty();
        boolean canWrite=step.writeBits==16 &&
            (expectedAddress&1L)==0 && tracked.contains(expectedAddress) &&
            snapshot.writtenWord!=null;
        if(canWrite &&
                !Objects.equals(snapshot.knownPeripheralWords.get(
                    expectedAddress),snapshot.writtenWord))
            return false;
        for(Long register:snapshot.knownPeripheralWords.keySet()){
            if(overlaps(expectedAddress,bytes,register) &&
                    (!canWrite || !register.equals(expectedAddress)))
                return false;
        }
        return true;
    }

    /**
     * GA-02/03/12: independently recompute ONLY the A/D constant lattice
     * from the translated source CFG (not the stored predecessor states).
     * Every predecessor contributes to a join by intersection: unequal,
     * absent or clobbered constants become UNKNOWN. Loops use a bounded
     * iterative worklist. This deliberately does not execute instructions,
     * re-run the peripheral/MM/VBR solver or grant Review/Apply authority.
     *
     * At a cold function entry every A/D register is UNKNOWN. Contextual
     * one-hop CALL arguments are deliberately not eligible for GA-12 disk
     * restoration: no caller context is bound to its per-function key.
     */
    private static boolean sourceBoundRegisterJoins(long entry,
            Map<Long,HardwareDataflow.Step> graph,
            HardwareDataflow.Result result) {
        if(graph==null || !graph.containsKey(entry) ||
                result==null || result.iterations<1 ||
                result.iterations>30000)
            return false;
        Map<Long,Map<String,Long>> at=new HashMap<>();
        ArrayDeque<Long> queue=new ArrayDeque<>();
        Set<Long> scheduled=new HashSet<>();
        at.put(entry,Map.of());
        queue.add(entry);scheduled.add(entry);
        int iterations=0;
        while(!queue.isEmpty()) {
            // Full fixed-point completion cannot require fewer transfers
            // than its independent register-only projection. A forged tiny
            // iteration receipt must never be accepted as convergence.
            if(++iterations>result.iterations)return false;
            Long pc=queue.removeFirst();scheduled.remove(pc);
            var step=graph.get(pc);
            if(step==null)return false;
            var out=new HashMap<>(at.get(pc));
            switch(step.kind) {
                case SET_POINTER -> {
                    if(step.register!=null)
                        out.put(step.register,
                            step.operand&HardwareDataflow.MASK24);
                }
                case COPY_POINTER -> {
                    if(step.register!=null) {
                        Long value=out.get(step.sourceRegister);
                        if(value==null)out.remove(step.register);
                        else out.put(step.register,value);
                    }
                }
                case ADJUST_POINTER -> {
                    if(step.register!=null) {
                        Long value=out.get(step.register);
                        boolean data=step.register.startsWith("D");
                        if(value==null || data &&
                                step.writeBits!=8 && step.writeBits!=16 &&
                                step.writeBits!=32) {
                            out.remove(step.register);
                        }else {
                            long mask=data && step.writeBits==8?0xffL:
                                data && step.writeBits==16?0xffffL:
                                HardwareDataflow.MASK24;
                            long adjusted=(value&~mask) |
                                ((value+step.operand)&mask);
                            out.put(step.register,
                                adjusted&HardwareDataflow.MASK24);
                        }
                    }
                }
                case CLOBBER_POINTER -> {
                    if(step.register!=null)out.remove(step.register);
                }
                case CALL_BARRIER -> {
                    out.clear();
                    for(var constant:step.verifiedCallReturns.entrySet())
                        out.put(constant.getKey(),constant.getValue()&
                            HardwareDataflow.MASK24);
                }
                default -> {
                    // STORE/VBR/OTHER do not assign A/D source registers.
                    // Their implicit P-code clobbers are handled below.
                }
            }
            for(String clobber:step.sideEffectRegisters)
                if(step.kind!=HardwareDataflow.Kind.CALL_BARRIER ||
                        !step.verifiedCallReturns.containsKey(clobber))
                    out.remove(clobber);
            for(Long next:step.successors) {
                if(!graph.containsKey(next))continue;
                Map<String,Long> before=at.get(next);
                if(before==null) {
                    at.put(next,new HashMap<>(out));
                    if(scheduled.add(next))queue.addLast(next);
                }else {
                    // An incoming unknown/mismatched predecessor MUST
                    // erase a spurious constant at a CFG branch merge.
                    var joined=new HashMap<>(before);
                    joined.entrySet().removeIf(e ->
                        !Objects.equals(out.get(e.getKey()),e.getValue()));
                    if(!joined.equals(before)) {
                        at.put(next,joined);
                        if(scheduled.add(next))queue.addLast(next);
                    }
                }
            }
        }
        if(at.size()!=result.reachedNodes)return false;
        Map<Long,Map<String,Long>> proven=new HashMap<>();
        for(var e:at.entrySet())
            if(!e.getValue().isEmpty())
                proven.put(e.getKey(),e.getValue());
        // Compare EVERY nonempty pre-instruction register state, not just
        // the STORE sites. Empty (UNKNOWN) states cannot be invented away.
        return proven.equals(result.knownPointersAtEntry);
    }

    /**
     * Independent read-only projection of the peripheral/VBR/uncertainty
     * lattice. Register predecessors were already independently audited by
     * sourceBoundRegisterJoins; only those exact, source-proven A/D maps
     * may be used to resolve an MMIO address or a MOVEC register source.
     * Nothing here depends on the claimed peripheral/VBR disk payload.
     */
    private static final class HardwareJoinState {
        final Map<Long,Integer> peripheral=new HashMap<>();
        Long vbr;
        int mmMin, mmMax;
        boolean unknownCall, unknownStore;
        HardwareJoinState copy(){
            var out=new HardwareJoinState();
            out.peripheral.putAll(peripheral);
            out.vbr=vbr;out.mmMin=mmMin;out.mmMax=mmMax;
            out.unknownCall=unknownCall;out.unknownStore=unknownStore;
            return out;
        }
        boolean join(HardwareJoinState incoming){
            var previous=copy();
            peripheral.entrySet().removeIf(e ->
                !Objects.equals(incoming.peripheral.get(e.getKey()),
                    e.getValue()));
            if(!Objects.equals(vbr,incoming.vbr))vbr=null;
            mmMin=Math.min(mmMin,incoming.mmMin);
            mmMax=Math.max(mmMax,incoming.mmMax);
            unknownCall|=incoming.unknownCall;
            unknownStore|=incoming.unknownStore;
            return !peripheral.equals(previous.peripheral) ||
                !Objects.equals(vbr,previous.vbr) ||
                mmMin!=previous.mmMin || mmMax!=previous.mmMax ||
                unknownCall!=previous.unknownCall ||
                unknownStore!=previous.unknownStore;
        }
    }

    private static HardwareJoinState independentHardwareTransfer(
            HardwareDataflow.Step step,HardwareJoinState before,
            Map<String,Long> registers,Set<Long> tracked){
        var after=before.copy();
        switch(step.kind){
            case STORE_DIRECT, STORE_INDIRECT -> {
                Long address=sourceAddress(step,registers);
                if(HardwareDataflow.mayTouchSimcrMmLowByte(
                        address,step.writeBits)){
                    after.mmMin=Math.min(2,before.mmMin+1);
                    after.mmMax=Math.min(2,before.mmMax+1);
                }
                int bytes=switch(step.writeBits){
                    case 8 -> 1;
                    case 16 -> 2;
                    case 32 -> 4;
                    default -> 0;
                };
                if(address==null || bytes==0){
                    after.peripheral.clear();
                    after.unknownStore=true;
                }else{
                    after.peripheral.keySet().removeIf(target ->
                        overlaps(address,bytes,target));
                    if(step.writeBits==16 && (address&1L)==0 &&
                            tracked.contains(address)){
                        Integer known=sourceWord(step,registers);
                        if(known!=null)
                            after.peripheral.put(address,known);
                    }
                }
            }
            case VBR_CONSTANT ->
                after.vbr=step.operand&HardwareDataflow.MASK24;
            case VBR_FROM_REGISTER ->
                after.vbr=step.register==null?
                    null:registers.get(step.register);
            case CALL_BARRIER -> {
                // Even a verified leaf return does not prove preserved
                // peripheral registers or VBR across an external CALL.
                after.peripheral.clear();
                after.vbr=null;
                after.unknownCall=true;
            }
            default -> {
                // A/D SET/COPY/ADJUST/CLOBBER and OTHER do not change
                // MMIO or VBR. Register side effects are accounted for
                // by the independent register-only CFG audit.
            }
        }
        return after;
    }

    /**
     * GA-02/03/12: independently re-derive the bounded 16-bit MMIO words,
     * VBR candidate, saturated SIMCR source-site counters and UNKNOWN
     * CALL/STORE barriers at every STORE/MOVEC source observation.
     * Branch and cyclic joins drop any conflicting peripheral/VBR value;
     * they never promote an instruction to proof of execution or MM latch.
     *
     * This projects only hardware state, taking A/D register maps solely
     * from the separately verified source-register pass. No stored
     * peripheral/VBR snapshot is fed into the replay. Memory is capped
     * across all reachable CFG states; oversized cases are a cache miss.
     */
    private static boolean sourceBoundHardwareJoins(long entry,
            Map<Long,HardwareDataflow.Step> graph,
            Set<Long> tracked,HardwareDataflow.Result result){
        if(graph==null || !graph.containsKey(entry) || tracked==null ||
                result==null || result.iterations<1 ||
                result.iterations>30000)
            return false;
        Map<Long,HardwareJoinState> at=new HashMap<>();
        ArrayDeque<Long> queue=new ArrayDeque<>();
        Set<Long> scheduled=new HashSet<>();
        at.put(entry,new HardwareJoinState());
        queue.add(entry);scheduled.add(entry);
        long totalCells=0;
        int iterations=0;
        while(!queue.isEmpty()){
            // The complete original solver cannot have converged
            // with fewer transfers than its independent source-only
            // hardware projection. Respect the original finite budget.
            if(++iterations>result.iterations)return false;
            Long pc=queue.removeFirst();scheduled.remove(pc);
            var step=graph.get(pc);
            var before=at.get(pc);
            if(step==null || before==null)return false;
            var registers=result.knownPointersAtEntry.getOrDefault(
                pc,Map.of());
            var after=independentHardwareTransfer(step,before,
                registers,tracked);
            for(Long next:step.successors){
                if(!graph.containsKey(next))continue;
                var prior=at.get(next);
                if(prior==null){
                    at.put(next,after.copy());
                    totalCells+=after.peripheral.size();
                    if(totalCells>262144L)return false;
                    if(scheduled.add(next))queue.addLast(next);
                }else{
                    int oldCells=prior.peripheral.size();
                    if(prior.join(after)){
                        totalCells+=prior.peripheral.size()-oldCells;
                        if(scheduled.add(next))queue.addLast(next);
                    }
                }
            }
        }
        if(at.size()!=result.reachedNodes)return false;
        for(var snapshot:result.snapshots){
            var step=graph.get(snapshot.instruction);
            var before=at.get(snapshot.instruction);
            if(step==null || before==null)return false;
            var after=independentHardwareTransfer(step,before,
                result.knownPointersAtEntry.getOrDefault(
                    snapshot.instruction,Map.of()),tracked);
            if(!Objects.equals(snapshot.vbr,after.vbr) ||
                    !snapshot.knownPeripheralWords.equals(
                        after.peripheral) ||
                    snapshot.priorMmCandidateMin!=before.mmMin ||
                    snapshot.priorMmCandidateMax!=before.mmMax ||
                    snapshot.priorUnknownCall!=before.unknownCall ||
                    snapshot.priorUnknownStore!=before.unknownStore)
                return false;
        }
        return true;
    }

    private static boolean sourceBoundComplete(long entry,
            Collection<HardwareDataflow.Step> steps,
            Collection<Long> targets,HardwareDataflow.Result result) {
        if(result==null || result.truncated || targets==null)return false;
        Set<Long> tracked=new HashSet<>(targets);
        var reachable=reachableSource(entry,steps);
        if(reachable==null || result.reachedNodes!=reachable.size() ||
                result.iterations<result.reachedNodes ||
                !reachable.keySet().containsAll(
                    result.knownPointersAtEntry.keySet()) ||
                !sourceBoundRegisterJoins(entry,reachable,result))
            return false;
        int expectedEffects=0;
        for(var step:reachable.values())
            if(step.kind==HardwareDataflow.Kind.STORE_DIRECT ||
                    step.kind==HardwareDataflow.Kind.STORE_INDIRECT ||
                    step.kind==HardwareDataflow.Kind.VBR_FROM_REGISTER ||
                    step.kind==HardwareDataflow.Kind.VBR_CONSTANT)
                expectedEffects++;
        if(result.snapshots.size()!=expectedEffects)return false;
        Set<Long> seenEffects=new HashSet<>();
        for(var snapshot:result.snapshots) {
            if(snapshot==null || !seenEffects.add(snapshot.instruction))
                return false;
            var step=reachable.get(snapshot.instruction);
            if(step==null || snapshot.kind!=step.kind ||
                    snapshot.writeBits!=step.writeBits ||
                    !Objects.equals(snapshot.pointerRegister,step.register) ||
                    snapshot.indirect!=
                        (step.kind==HardwareDataflow.Kind.STORE_INDIRECT) ||
                    !address24(snapshot.effectiveAddress) ||
                    !address24(snapshot.vbr) ||
                    snapshot.writtenWord!=null &&
                        (snapshot.writtenWord<0 || snapshot.writtenWord>0xffff) ||
                    !sourceValueWitness(step,snapshot,
                        result.knownPointersAtEntry.getOrDefault(
                            snapshot.instruction,Map.of()),tracked))
                return false;
            for(var peripheral:snapshot.knownPeripheralWords.entrySet())
                if(peripheral.getKey()==null ||
                        !address24(peripheral.getKey()) ||
                        peripheral.getValue()==null ||
                        peripheral.getValue()<0 ||
                        peripheral.getValue()>0xffff)
                    return false;
        }
        for(var states:result.knownPointersAtEntry.values()) {
            if(states==null)return false;
            for(var register:states.entrySet())
                if(register.getKey()==null ||
                        !register.getKey().matches("[AD][0-7]") ||
                        register.getValue()==null ||
                        !address24(register.getValue()))
                    return false;
        }
        return sourceBoundHardwareJoins(entry,reachable,tracked,result);
    }

    private static boolean address24(Long value) {
        return value==null || value>=0 &&
            value<=HardwareDataflow.MASK24;
    }

    private static HardwareDurableStageStore.Key key(
            HardwareDurableStageStore.Key full,long functionEntry,int budget,
            Collection<HardwareDataflow.Step> steps,Collection<Long> targets){
        if(full==null || functionEntry<0 || budget<1)
            return null;
        String stepHash=HardwareFunctionStageCache.signature(steps,targets);
        if(stepHash==null)return null;
        // Stable disk pathname per project+entry prevents unchecked file
        // growth across edits; changing input or Step semantics changes the
        // embedded validated key and forces a cache miss/replacement.
        String slot=HardwareDurableStageStore.hash(
            "GA12F-SLOT-1|" + full.programIdSha256() + "|" +
            Long.toUnsignedString(functionEntry));
        String derivedEngine=HardwareDurableStageStore.hash(
            "GA12F-FIXPOINT-1|" + full.analyzerSha256() + "|" +
            Long.toUnsignedString(functionEntry) + "|" + budget + "|" + stepHash);
        return new HardwareDurableStageStore.Key(slot,full.importedSha256(),
            full.inputSha256(),derivedEngine,full.language(),full.mc68332());
    }
    public static Optional<HardwareDataflow.Result> load(Path directory,
            HardwareDurableStageStore.Key full,long entry,int budget,
            Collection<HardwareDataflow.Step> steps,Collection<Long> targets){
        HardwareDurableStageStore.Key k=key(full,entry,budget,steps,targets);
        if(directory==null || k==null)return Optional.empty();
        return HardwareDurableStageStore.load(directory,k)
            .flatMap(HardwareFunctionResultCodec::decode)
            .filter(result -> sourceBoundComplete(entry,steps,targets,result));
    }

    /** The same stable function slot holds either incomplete work or a completed result. */
    public static Optional<HardwareDataflow.Progress> loadProgress(Path directory,
            HardwareDurableStageStore.Key full,long entry,int budget,
            Collection<HardwareDataflow.Step> steps,Collection<Long> targets){
        HardwareDurableStageStore.Key k=key(full,entry,budget,steps,targets);
        if(directory==null || k==null)return Optional.empty();
        // A worklist can be structurally valid but refer to an address that
        // no longer exists in the exact translated CFG. Such data must not
        // reach the fixed-point solver as an uncaught stale-state exception.
        Set<Long> addresses=new HashSet<>();
        for(HardwareDataflow.Step step:steps)addresses.add(step.address);
        // The durable envelope binds the requested graph/budget, but the
        // untrusted typed payload must independently agree. A correctly
        // rehashed, mismatched worklist is a cache miss, not an exception
        // thrown later by analyzeSlice() into the caller's analysis.
        return HardwareDurableStageStore.load(directory,k)
            .flatMap(HardwareFunctionProgressCodec::decode)
            .filter(progress -> progress.entry()==entry &&
                progress.maxIterations()==budget &&
                addresses.containsAll(progress.atEntry().keySet()) &&
                sourceBoundProgress(entry,steps,progress));
    }
    /** Never store progress unless its typed worklist can be fully encoded. */
    public static boolean saveProgress(Path directory,
            HardwareDurableStageStore.Key full,long entry,int budget,
            Collection<HardwareDataflow.Step> steps,Collection<Long> targets,
            HardwareDataflow.Progress progress){
        HardwareDurableStageStore.Key k=key(full,entry,budget,steps,targets);
        if(directory==null || k==null || progress==null ||
                progress.entry()!=entry || progress.maxIterations()!=budget ||
                !sourceBoundProgress(entry,steps,progress))
            return false;
        try{
            HardwareDurableStageStore.save(directory,k,
                HardwareFunctionProgressCodec.encode(progress));
            return true;
        }catch(IOException|IllegalArgumentException invalid){
            return false;
        }
    }

    public static boolean save(Path directory,
            HardwareDurableStageStore.Key full,long entry,int budget,
            Collection<HardwareDataflow.Step> steps,Collection<Long> targets,
            HardwareDataflow.Result complete){
        HardwareDurableStageStore.Key k=key(full,entry,budget,steps,targets);
        if(directory==null || k==null ||
                !sourceBoundComplete(entry,steps,targets,complete))
            return false;
        try{
            HardwareDurableStageStore.save(directory,k,
                HardwareFunctionResultCodec.encode(complete));
            return true;
        }catch(IOException|IllegalArgumentException invalid){
            // File permissions, space limits and bad schemas are a miss.
            return false;
        }
    }
}
