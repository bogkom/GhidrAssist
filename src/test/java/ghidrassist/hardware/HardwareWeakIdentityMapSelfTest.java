package ghidrassist.hardware;

/** Pure Java 21 regression for identity-scoped, weak GA-12 cache state. */
public final class HardwareWeakIdentityMapSelfTest {
    private static int assertions;
    private static void check(boolean passed,String explanation){
        assertions++;
        if(!passed)throw new AssertionError(explanation);
    }
    private static void rejects(Runnable action,String explanation){
        boolean refused=false;
        try{action.run();}
        catch(IllegalArgumentException expected){refused=true;}
        check(refused,explanation);
    }
    private static final class EqualOwner {
        final int id;
        EqualOwner(int id){this.id=id;}
        @Override public boolean equals(Object other){
            return other instanceof EqualOwner;
        }
        @Override public int hashCode(){return 7;}
    }
    private static void publicationFence() throws Exception {
        var epochs=new HardwareStageEpochs<EqualOwner>();
        var owner=new EqualOwner(10);
        var other=new EqualOwner(11);
        long generation=epochs.begin(owner);
        long otherGeneration=epochs.begin(other);
        var entered=new java.util.concurrent.CountDownLatch(1);
        var release=new java.util.concurrent.CountDownLatch(1);
        var clearing=new java.util.concurrent.CountDownLatch(1);
        var order=new java.util.concurrent.atomic.AtomicInteger();
        try(var executor=java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()){
            var writer=executor.submit(()->epochs.publishIfCurrent(owner,generation,()->{
                entered.countDown();
                if(!release.await(5,java.util.concurrent.TimeUnit.SECONDS))
                    throw new AssertionError("publication release timeout");
                if(!order.compareAndSet(0,1))throw new AssertionError("clear overtook publication");
            }));
            try {
                check(entered.await(5,java.util.concurrent.TimeUnit.SECONDS),"writer entered fence");
                var clear=executor.submit(()->{
                    clearing.countDown();
                    epochs.invalidate(owner);
                    if(!order.compareAndSet(1,2))throw new AssertionError("clear overtook writer");
                });
                check(clearing.await(5,java.util.concurrent.TimeUnit.SECONDS),"clear requested");
                release.countDown();
                check(writer.get(5,java.util.concurrent.TimeUnit.SECONDS),"current publication accepted");
                clear.get(5,java.util.concurrent.TimeUnit.SECONDS);
            } finally {release.countDown();}
        }
        check(order.get()==2,"clear follows accepted publication");
        check(!epochs.publishIfCurrent(owner,generation,()->{
            throw new AssertionError("stale publication executed");
        }),"clear rejects old generation without side effects");
        check(epochs.publishIfCurrent(other,otherGeneration,()->{}),"equal owner remains independent");
        check(epochs.publishIfCurrent(owner,epochs.begin(owner),()->{}),"fresh generation accepted");
        try {
            epochs.publishIfCurrent(owner,epochs.begin(owner),()->{throw new java.io.IOException("synthetic");});
            throw new AssertionError("publication exception swallowed");
        } catch(java.io.IOException expected){check("synthetic".equals(expected.getMessage()),"IO failure propagated");}
    }
    public static void main(String[] args) throws Exception {
        publicationFence();
        var first=new EqualOwner(1);
        var second=new EqualOwner(2);
        var unseen=new EqualOwner(3);
        check(first!=second && first.equals(second) &&
                first.hashCode()==second.hashCode(),
            "fixtures collide by value but not Program identity");

        var completed=new HardwareWeakIdentityMap<EqualOwner,String>();
        check(completed.put(first,"cfg-a")==null &&
                completed.put(second,"cfg-b")==null,
            "different equal-valued Programs must create independent slots");
        check("cfg-a".equals(completed.get(first)) &&
                "cfg-b".equals(completed.get(second)) &&
                completed.get(unseen)==null,
            "an equal but unseen Program cannot inherit a completed CFG");
        check("cfg-a".equals(completed.put(first,"cfg-a-new")) &&
                "cfg-a-new".equals(completed.get(first)) &&
                "cfg-b".equals(completed.get(second)),
            "same exact owner refreshes only its own completed checkpoint");
        check("cfg-a-new".equals(completed.remove(first)) &&
                completed.get(first)==null &&
                "cfg-b".equals(completed.get(second)),
            "clear of one owner cannot erase another equal-valued owner");

        var skipDisk=new HardwareWeakIdentityMap<EqualOwner,Boolean>();
        skipDisk.put(first,true);
        check(Boolean.TRUE.equals(skipDisk.get(first)) &&
                skipDisk.get(second)==null && skipDisk.get(unseen)==null,
            "explicit-clear disk tombstone is Program identity scoped");
        skipDisk.put(second,false);
        check(Boolean.FALSE.equals(skipDisk.get(second)) &&
                Boolean.TRUE.equals(skipDisk.get(first)),
            "tombstone value and absence remain distinct for two owners");
        check(Boolean.TRUE.equals(skipDisk.remove(first)) &&
                skipDisk.get(first)==null &&
                Boolean.FALSE.equals(skipDisk.get(second)),
            "clearing first disk tombstone cannot change the second");
        check(completed.get(null)==null &&
                completed.remove(null)==null &&
                skipDisk.get(null)==null,
            "null lookups never alias a real Program");
        rejects(()->completed.put(null,"cfg"),
            "null owner cannot publish checkpoint evidence");
        rejects(()->completed.put(first,null),
            "null evidence cannot be stored as a completed stage");
        check(completed.put(first,"cfg-a-final")==null &&
                "cfg-a-final".equals(completed.get(first)) &&
                "cfg-b".equals(completed.get(second)),
            "new stage after clear cannot inherit another Program context");
        System.out.println("HardwareWeakIdentityMapSelfTest PASS: assertions="+assertions);
    }
}
