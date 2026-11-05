package ghidrassist.hardware;

import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;

/**
 * Process-local cancellation/invalidation generations, independent of Ghidra.
 *
 * A completed analysis from generation N must never publish after its exact
 * Program owner was invalidated (generation N+1), even when the imported
 * executable SHA and Ghidra modification number did not change.
 *
 * Weak keys do not pin closed Programs. Crucially, two distinct owners that
 * compare equal via equals() must not share generation counters or clear each
 * other's pending analysis. All methods are synchronized; the caller must
 * independently check its immutable Ghidra analysis revision.
 */
public final class HardwareStageEpochs<K> {
    private static final class WeakIdentityKey<T> extends WeakReference<T> {
        private final int hash;
        WeakIdentityKey(T value, ReferenceQueue<T> queue) {
            super(value,queue);
            hash=System.identityHashCode(value);
        }
        @Override public int hashCode() { return hash; }
        @Override public boolean equals(Object other) {
            if(this==other)return true; // lets ReferenceQueue remove dead keys
            if(!(other instanceof WeakIdentityKey<?> candidate))return false;
            Object value=get();
            return value!=null && value==candidate.get();
        }
    }
    private final ReferenceQueue<K> collected=new ReferenceQueue<>();
    private final Map<WeakIdentityKey<K>,Long> epoch=new HashMap<>();

    private void discardCollectedOwners() {
        Reference<? extends K> key;
        while((key=collected.poll())!=null)
            epoch.remove(key);
    }
    private WeakIdentityKey<K> lookup(K owner) {
        return new WeakIdentityKey<>(owner,null);
    }
    public synchronized long begin(K owner) {
        if(owner==null)throw new IllegalArgumentException("Null stage owner");
        discardCollectedOwners();
        Long current=epoch.get(lookup(owner));
        if(current!=null)return current;
        epoch.put(new WeakIdentityKey<>(owner,collected),0L);
        return 0L;
    }

    public synchronized void invalidate(K owner) {
        if(owner==null)return;
        discardCollectedOwners();
        WeakIdentityKey<K> key=lookup(owner);
        Long before=epoch.get(key);
        // Fail closed on a theoretical generation overflow.
        long next=Math.addExact(before==null?0L:before,1L);
        if(before==null)epoch.put(new WeakIdentityKey<>(owner,collected),next);
        else epoch.put(key,next);
    }

    public synchronized boolean current(K owner,long generation) {
        if(owner==null || generation<0)return false;
        discardCollectedOwners();
        Long stored=epoch.get(lookup(owner));
        return stored!=null && stored==generation;
    }
}
