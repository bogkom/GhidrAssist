package ghidrassist.hardware;

import java.util.Map;
import java.util.WeakHashMap;

/**
 * Process-local cancellation/invalidation generations, independent of Ghidra.
 *
 * A completed analysis from generation N must never publish a cache entry
 * after the owner has explicitly invalidated that program (generation N+1),
 * even when its modification number and imported-executable SHA did not
 * change. Weak keys avoid pinning closed programs in memory.
 *
 * All methods are synchronized. Caller must also validate the immutable
 * Ghidra analysis revision: this epoch does NOT replace revision checks.
 */
public final class HardwareStageEpochs<K> {
    private final Map<K,Long> epoch=new WeakHashMap<>();

    public synchronized long begin(K owner) {
        if(owner==null)throw new IllegalArgumentException("Null stage owner");
        return epoch.computeIfAbsent(owner,k->0L);
    }

    public synchronized void invalidate(K owner) {
        if(owner==null)return;
        long before=epoch.getOrDefault(owner,0L);
        // Fail closed on a theoretical generation overflow; never wrap to an
        // epoch that could match an old analysis.
        epoch.put(owner,Math.addExact(before,1L));
    }

    public synchronized boolean current(K owner,long generation) {
        return owner!=null && generation>=0 &&
            epoch.containsKey(owner) && epoch.get(owner)==generation;
    }
}
