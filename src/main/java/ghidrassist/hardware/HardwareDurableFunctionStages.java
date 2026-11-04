package ghidrassist.hardware;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.List;
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
            .flatMap(HardwareFunctionResultCodec::decode);
    }
    public static boolean save(Path directory,
            HardwareDurableStageStore.Key full,long entry,int budget,
            Collection<HardwareDataflow.Step> steps,Collection<Long> targets,
            HardwareDataflow.Result complete){
        HardwareDurableStageStore.Key k=key(full,entry,budget,steps,targets);
        if(directory==null || k==null || complete==null || complete.truncated)
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
