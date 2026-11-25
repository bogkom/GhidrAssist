package ghidrassist.hardware;

import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;

/**
 * GA-12: weak, exact-object-identity keys for process-local Program state.
 *
 * Ordinary WeakHashMap uses equals(), which can conflate two different
 * Program wrappers with identical revision metadata. Checkpoint reuse and
 * explicit-clear disk tombstones must instead belong to one exact owner.
 * Keys never retain a strong owner reference; values must not retain one.
 */
public final class HardwareWeakIdentityMap<K,V> {
    private static final class Key<T> extends WeakReference<T> {
        private final int identityHash;
        Key(T owner,ReferenceQueue<T> queue) {
            super(owner,queue);
            identityHash=System.identityHashCode(owner);
        }
        @Override public int hashCode(){return identityHash;}
        @Override public boolean equals(Object other){
            if(this==other)return true; // collected key removal by queue
            if(!(other instanceof Key<?> candidate))return false;
            Object owner=get();
            return owner!=null && owner==candidate.get();
        }
    }

    private final ReferenceQueue<K> collected=new ReferenceQueue<>();
    private final Map<Key<K>,V> contents=new HashMap<>();

    private void discardCollected(){
        Reference<? extends K> dead;
        while((dead=collected.poll())!=null)
            contents.remove(dead);
    }
    public synchronized V get(K owner){
        if(owner==null)return null;
        discardCollected();
        return contents.get(new Key<>(owner,null));
    }
    public synchronized V put(K owner,V value){
        if(owner==null || value==null)
            throw new IllegalArgumentException("Missing identity-map key/value");
        discardCollected();
        return contents.put(new Key<>(owner,collected),value);
    }
    public synchronized V remove(K owner){
        if(owner==null)return null;
        discardCollected();
        return contents.remove(new Key<>(owner,null));
    }
}
