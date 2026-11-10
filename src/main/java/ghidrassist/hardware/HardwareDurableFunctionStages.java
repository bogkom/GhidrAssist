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
    private static boolean sourceBoundComplete(long entry,
            Collection<HardwareDataflow.Step> steps,
            HardwareDataflow.Result result) {
        if(result==null || result.truncated)return false;
        var reachable=reachableSource(entry,steps);
        if(reachable==null || result.reachedNodes!=reachable.size() ||
                result.iterations<result.reachedNodes ||
                !reachable.keySet().containsAll(
                    result.knownPointersAtEntry.keySet()))
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
                        (snapshot.writtenWord<0 || snapshot.writtenWord>0xffff))
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
        return true;
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
            .filter(result -> sourceBoundComplete(entry,steps,result));
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
                !sourceBoundComplete(entry,steps,complete))
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
