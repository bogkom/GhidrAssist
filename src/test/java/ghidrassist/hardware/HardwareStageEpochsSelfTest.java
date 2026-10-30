package ghidrassist.hardware;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

/** Deterministic offline concurrency tests; no Ghidra or Codex runtime. */
public final class HardwareStageEpochsSelfTest {
    private HardwareStageEpochsSelfTest(){}
    private static void check(boolean ok,String why){
        if(!ok)throw new AssertionError(why);
    }

    public static void main(String[] args)throws Exception{
        var epochs=new HardwareStageEpochs<Object>();
        Object projectA=new Object(),projectB=new Object();
        long firstA=epochs.begin(projectA);
        long firstB=epochs.begin(projectB);
        check(firstA==0 && firstB==0,"initial independent generations");
        check(epochs.current(projectA,firstA),"unchanged project current");
        epochs.invalidate(projectA);
        check(!epochs.current(projectA,firstA) &&
            epochs.current(projectA,epochs.begin(projectA)) &&
            epochs.current(projectB,firstB),
            "explicit invalidation blocks A but not B");
        check(!epochs.current(null,0) && !epochs.current(projectA,-1),
            "invalid keys/generations fail closed");
        boolean rejected=false;
        try{epochs.begin(null);}
        catch(IllegalArgumentException expected){rejected=true;}
        check(rejected,"cannot claim an ownerless checkpoint");

        // Simulate a scan that begins before UI invalidates current Program.
        // Its *program revision* can remain the same, but generation cannot.
        CountDownLatch scanStarted=new CountDownLatch(1);
        CountDownLatch continueScan=new CountDownLatch(1);
        AtomicBoolean published=new AtomicBoolean(false);
        AtomicReference<Throwable> error=new AtomicReference<>();
        Thread worker=new Thread(()->{
            try {
                long running=epochs.begin(projectA);
                scanStarted.countDown();
                if(!continueScan.await(5,TimeUnit.SECONDS))
                    throw new AssertionError("test barrier timeout");
                if(epochs.current(projectA,running))
                    published.set(true);
            }catch(Throwable t){error.set(t);}
        },"ga12-test-discarded-cfg-scan");
        worker.start();
        check(scanStarted.await(5,TimeUnit.SECONDS),"worker entered scan");
        epochs.invalidate(projectA);
        continueScan.countDown();
        worker.join(5000);
        check(!worker.isAlive() && error.get()==null &&
            !published.get(),"stale scan cannot publish after explicit clear");
        long newest=epochs.begin(projectA);
        check(epochs.current(projectA,newest) && newest>firstA,
            "new scan can reuse new epoch only");

        // Invalidation when there was no completed checkpoint must still
        // change the epoch, protecting an in-flight *first* scan.
        Object initial=new Object();
        long initialToken=epochs.begin(initial);
        epochs.invalidate(initial);
        check(!epochs.current(initial,initialToken),
            "clear before first completed stage also blocks late publish");
        System.out.println("HardwareStageEpochsSelfTest OK");
    }
}
