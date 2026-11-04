package ghidrassist.hardware;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.WeakHashMap;

/**
 * GA-12: read-only, process-local checkpoints of *completed function CFG
 * fixed points*. If a later function is cancelled, already completed
 * functions can be reused on the same Program and exact revision.
 *
 * The input signature covers every translated Step, successor, implicit
 * register side effect, modeled target register and iteration budget.
 * This does not persist functions to disk or resume inside a function.
 */
public final class HardwareFunctionStageCache<K> {
    public static final int MAX_FUNCTIONS=192;
    public static final int MAX_STEPS_PER_FUNCTION=3000;
    public static final int MAX_SNAPSHOTS_PER_FUNCTION=512;

    public record Scope(long modification,String language,String sourceSha,
                        boolean mc68332) {
        public Scope {
            if(modification<0 || language==null || language.isBlank())
                throw new IllegalArgumentException("Invalid analysis scope");
        }
    }
    private record Key(long entry,String stepsSha256,int iterationsBudget){}
    private static final class OwnerStages {
        final Scope scope;
        final LinkedHashMap<Key,HardwareDataflow.Result> stages =
            new LinkedHashMap<>();
        OwnerStages(Scope scope){this.scope=scope;}
    }
    private final Map<K,OwnerStages> completed=new WeakHashMap<>();
    private final HardwareStageEpochs<K> epochs=new HardwareStageEpochs<>();

    public synchronized long begin(K owner) {
        if(owner==null)throw new IllegalArgumentException("Missing Program");
        return epochs.begin(owner);
    }
    public synchronized int completed(K owner) {
        OwnerStages stages=completed.get(owner);
        return stages==null?0:stages.stages.size();
    }
    public synchronized void invalidate(K owner) {
        if(owner==null)return;
        epochs.invalidate(owner);
        completed.remove(owner);
    }

    private static void intValue(MessageDigest digest,int value) {
        digest.update((byte)(value>>>24));
        digest.update((byte)(value>>>16));
        digest.update((byte)(value>>>8));
        digest.update((byte)value);
    }
    private static void longValue(MessageDigest digest,long value) {
        intValue(digest,(int)(value>>>32));
        intValue(digest,(int)value);
    }
    private static void text(MessageDigest digest,String value) {
        if(value==null){intValue(digest,-1);return;}
        byte[] bytes=value.getBytes(StandardCharsets.UTF_8);
        intValue(digest,bytes.length);
        digest.update(bytes);
    }
    private static String signature(Collection<HardwareDataflow.Step> steps,
            Collection<Long> targets) {
        if(steps==null || targets==null ||
                steps.size()>MAX_STEPS_PER_FUNCTION)return null;
        try {
            MessageDigest digest=MessageDigest.getInstance("SHA-256");
            text(digest,"GA12-FUNCTION-CFG-FIXPOINT-1");
            intValue(digest,steps.size());
            for(HardwareDataflow.Step step:steps) {
                if(step==null)return null;
                longValue(digest,step.address);
                text(digest,step.kind.name());
                text(digest,step.register);
                text(digest,step.sourceRegister);
                text(digest,step.indexRegister);
                intValue(digest,step.indexBits);
                intValue(digest,step.indexScale);
                longValue(digest,step.operand);
                longValue(digest,step.displacement);
                intValue(digest,step.literalWord==null?-1:step.literalWord);
                intValue(digest,step.writeBits);
                text(digest,step.mnemonic);
                intValue(digest,step.successors.size());
                for(Long pc:step.successors){
                    if(pc==null)return null;
                    longValue(digest,pc);
                }
                List<String> altered=new ArrayList<>(step.sideEffectRegisters);
                Collections.sort(altered);
                intValue(digest,altered.size());
                for(String reg:altered)text(digest,reg);
            }
            // Existing CFG uses target addresses as a SET, not a sequence.
            TreeSet<Long> ordered=new TreeSet<>(targets);
            intValue(digest,ordered.size());
            for(Long address:ordered){
                if(address==null)return null;
                longValue(digest,address);
            }
            return java.util.HexFormat.of().formatHex(digest.digest());
        }catch(NoSuchAlgorithmException unavailable){
            throw new AssertionError(unavailable);
        }
    }
    private static Key key(long entry,int budget,
            Collection<HardwareDataflow.Step> steps,Collection<Long> targets){
        if(entry<0 || budget<1)return null;
        String signature=signature(steps,targets);
        return signature==null?null:new Key(entry,signature,budget);
    }

    public synchronized HardwareDataflow.Result get(K owner,long generation,
            Scope scope,long entry,int iterationsBudget,
            Collection<HardwareDataflow.Step> steps,Collection<Long> targets){
        if(owner==null || scope==null || !epochs.current(owner,generation))
            return null;
        OwnerStages existing=completed.get(owner);
        if(existing==null)return null;
        if(!existing.scope.equals(scope)){
            completed.remove(owner);
            return null;
        }
        Key key=key(entry,iterationsBudget,steps,targets);
        return key==null?null:existing.stages.get(key);
    }

    /** Refuse incomplete, oversized or stale fixed points. */
    public synchronized boolean put(K owner,long generation,Scope scope,
            long entry,int iterationsBudget,
            Collection<HardwareDataflow.Step> steps,Collection<Long> targets,
            HardwareDataflow.Result result){
        if(owner==null || scope==null || result==null || result.truncated ||
                !epochs.current(owner,generation) ||
                result.snapshots.size()>MAX_SNAPSHOTS_PER_FUNCTION ||
                result.knownPointersAtEntry.size()>MAX_STEPS_PER_FUNCTION)
            return false;
        Key key=key(entry,iterationsBudget,steps,targets);
        if(key==null)return false;
        OwnerStages group=completed.get(owner);
        if(group==null || !group.scope.equals(scope)){
            group=new OwnerStages(scope);
            completed.put(owner,group);
        }
        group.stages.put(key,result);
        while(group.stages.size()>MAX_FUNCTIONS)
            group.stages.remove(group.stages.keySet().iterator().next());
        return true;
    }
}
