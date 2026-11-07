package ghidrassist.agent.react;

import java.util.List;

/** Pure Java21 evidence bridge tests; no LLM, Ghidra or external files. */
public final class AgenticEvidenceRegistrySelfTest {
    private AgenticEvidenceRegistrySelfTest() {}
    private static int assertions;
    private static void yes(boolean value,String reason) {
        assertions++;
        if(!value)throw new AssertionError(reason);
    }
    private static void denies(Runnable operation,String detail) {
        boolean denied=false;
        try {operation.run();}
        catch(IllegalArgumentException|IllegalStateException expected) {
            denied=true;
        }
        yes(denied,detail);
    }
    public static void main(String[] args) {
        var registry=new AgenticEvidenceRegistry<Object>();
        String programA=new String("synthetic-program");
        String equalButDifferent=new String("synthetic-program");
        var findings=new FindingsCache(2);
        findings.addFinding("source first","byte-range 0x100","listing",9);
        findings.addFinding("source second","byte-range 0x200","listing",6);
        String run=registry.begin(programA,17L,"a".repeat(64),findings);
        var first=registry.page(programA,17L,"a".repeat(64),0,1,null,null);
        yes(first.state().equals("RUNNING") && !first.complete() &&
            first.findings().hasMore() &&
            first.run().equals(run) &&
            first.findings().rows().get(0).fact().equals("source first"),
            "running analysis must not be called complete");
        var next=registry.page(programA,17L,"a".repeat(64),1,1,
            first.run(),first.findings().revision());
        yes(!next.findings().hasMore() &&
            next.findings().rows().get(0).fact().equals("source second"),
            "exact run and evidence version permit deterministic stitching");
        denies(()->registry.page(programA,17L,"a".repeat(64),1,1,null,null),
            "nonzero page requires explicit run and revision");
        denies(()->registry.page(programA,18L,"a".repeat(64),0,1,null,null),
            "changed Program revision refuses old evidence");
        denies(()->registry.page(programA,17L,"b".repeat(64),0,1,null,null),
            "changed imported firmware SHA refuses old evidence");
        denies(()->registry.page(equalButDifferent,17L,"a".repeat(64),
            0,1,null,null),"equal-but-distinct Program is not same owner");
        denies(()->registry.begin(equalButDifferent,17L,"a".repeat(64),
            findings),"equal-but-distinct owner cannot overwrite real Program slot");
        registry.finish(programA,findings,"SUCCESS");
        var success=registry.page(programA,17L,"a".repeat(64),0,2,null,null);
        yes(success.complete() && success.state().equals("SUCCESS") &&
            !success.findings().hasMore(),"completed unpruned run may report all retained facts");
        // Old score setter remains supported and must invalidate version.
        findings.getAllFindings().get(0).setRelevance(1);
        denies(()->registry.page(programA,17L,"a".repeat(64),1,1,
            run,success.findings().revision()),"score changes reject stale page");
        findings.addFinding("third source","byte-range 0x300","listing",10);
        var pruned=registry.page(programA,17L,"a".repeat(64),0,2,null,null);
        yes(!pruned.complete() && pruned.findings().evictedCount()==1,
            "a finished investigation with pruned evidence is never complete");
        var newer=new FindingsCache();
        newer.addFinding("new run",null,"listing",3);
        String second=registry.begin(programA,17L,"a".repeat(64),newer);
        yes(!second.equals(run),"every analysis has a distinct opaque run token");
        registry.finish(programA,findings,"SUCCESS");
        var fresh=registry.page(programA,17L,"a".repeat(64),0,1,null,null);
        yes(fresh.run().equals(second) && fresh.state().equals("RUNNING"),
            "late completion callback cannot mutate the next run");
        denies(()->registry.page(programA,17L,"a".repeat(64),1,1,
            run,fresh.findings().revision()),"stale run cannot stitch into newer analysis");
        registry.finish(programA,newer,"CANCELLED");
        var cancelled=registry.page(programA,17L,"a".repeat(64),0,10,null,null);
        yes(cancelled.state().equals("CANCELLED") && !cancelled.complete(),
            "cancelled work is not completed evidence");
        // A missing SHA or no actual findings must not make a durable
        // checkpoint claim complete merely because the task ended.
        var noSource=new FindingsCache();
        noSource.addFinding("observed",null,"listing",6);
        registry.begin(programA,17L,"UNKNOWN",noSource);
        registry.finish(programA,noSource,"SUCCESS");
        yes(!registry.page(programA,17L,"UNKNOWN",0,3,null,null).complete(),
            "unverified import identity cannot certify evidence checkpoint");
        var noFindings=new FindingsCache();
        registry.begin(programA,17L,"a".repeat(64),noFindings);
        registry.finish(programA,noFindings,"SUCCESS");
        yes(!registry.page(programA,17L,"a".repeat(64),0,3,null,null).complete(),
            "zero retained findings are not a completed evidence checkpoint");
        registry.invalidate(programA);
        denies(()->registry.page(programA,17L,"a".repeat(64),0,1,null,null),
            "explicit Program invalidation removes prior evidence");
        denies(()->registry.begin(null,0,"a",newer),
            "null Program must not register evidence");
        registry.begin(programA,17L,"a".repeat(64),newer);
        denies(()->registry.page(programA,17L,"a".repeat(64),
            0,FindingsCache.MAX_PAGE_SIZE+1,null,null),
            "oversized bounded pages must be rejected");
        // GA-15/18: invalidate a live source and cancel exactly its run,
        // with the registry entry removed before a future callback re-enters.
        var active=new FindingsCache();
        var cancelCount=new java.util.concurrent.atomic.AtomicInteger();
        String live=registry.begin(programA,17L,"a".repeat(64),active,()->{
            cancelCount.incrementAndGet();
            denies(()->registry.page(programA,17L,"a".repeat(64),
                0,1,null,null),"source must be absent before cancel callback");
            registry.finish(programA,active,"CANCELLED");
        });
        registry.invalidate(equalButDifferent);
        yes(cancelCount.get()==0 &&
            registry.page(programA,17L,"a".repeat(64),0,1,null,null).run().equals(live),
            "equal-but-distinct Program cannot cancel another source");
        registry.invalidate(programA);
        registry.invalidate(programA);
        yes(cancelCount.get()==1,
            "Program switch cancels exactly one live registered investigation");
        denies(()->registry.page(programA,17L,"a".repeat(64),0,1,null,null),
            "cancelled source is unavailable after switch even with same revision");
        var finished=new FindingsCache();
        var completedCalls=new java.util.concurrent.atomic.AtomicInteger();
        registry.begin(programA,17L,"a".repeat(64),finished,
            completedCalls::incrementAndGet);
        registry.finish(programA,finished,"SUCCESS");
        registry.invalidate(programA);
        yes(completedCalls.get()==0,"completed investigation is not cancelled by unload");

        // Replacing a still-running analysis must stop the old model run.
        // A synchronous completion callback may re-enter this registry, but
        // may not touch the replacement's pages or terminal state.
        var oldCache=new FindingsCache();
        var newCache=new FindingsCache();
        oldCache.addFinding("old evidence",null,"listing",5);
        newCache.addFinding("new evidence",null,"listing",6);
        var replacedCalls=new java.util.concurrent.atomic.AtomicInteger();
        String oldRun=registry.begin(programA,17L,"a".repeat(64),oldCache,
            () -> {
                replacedCalls.incrementAndGet();
                registry.finish(programA,oldCache,"CANCELLED");
                var page=registry.page(programA,17L,"a".repeat(64),
                    0,1,null,null);
                yes(page.findings().rows().get(0).fact().equals("new evidence") &&
                    page.state().equals("RUNNING"),
                    "synchronous old-run cancellation cannot overwrite replacement");
            });
        String newRun=registry.begin(programA,17L,"a".repeat(64),newCache);
        yes(!oldRun.equals(newRun) && replacedCalls.get()==1,
            "replacing a running analysis cancels the old run exactly once");
        denies(()->registry.page(programA,17L,"a".repeat(64),1,1,
            oldRun,0L),"replaced run token must never access new evidence");
        registry.finish(programA,newCache,"SUCCESS");
        var finalReplacement=registry.page(programA,17L,"a".repeat(64),
            0,1,null,null);
        yes(finalReplacement.state().equals("SUCCESS") &&
            finalReplacement.run().equals(newRun),
            "new run remains independently completable");
        var finishedReplacementCalls=new java.util.concurrent.atomic.AtomicInteger();
        var completedCache=new FindingsCache();
        registry.begin(programA,17L,"a".repeat(64),completedCache,
            finishedReplacementCalls::incrementAndGet);
        registry.finish(programA,completedCache,"SUCCESS");
        registry.begin(programA,17L,"a".repeat(64),new FindingsCache());
        yes(finishedReplacementCalls.get()==0,
            "replacing an already completed run must not cancel the provider");

        // A late provider callback must never resurrect or reclassify a
        // terminal checkpoint. The FIRST terminal outcome wins.
        var terminalCache=new FindingsCache();
        terminalCache.addFinding("terminal evidence",null,"listing",6);
        registry.begin(programA,17L,"a".repeat(64),terminalCache);
        registry.finish(programA,terminalCache,"CANCELLED");
        registry.finish(programA,terminalCache,"SUCCESS");
        registry.finish(programA,terminalCache,"ERROR");
        yes(registry.page(programA,17L,"a".repeat(64),0,1,null,null)
            .state().equals("CANCELLED"),
            "late success/error must not resurrect cancelled run");
        var successfulCache=new FindingsCache();
        successfulCache.addFinding("success evidence",null,"listing",6);
        registry.begin(programA,17L,"a".repeat(64),successfulCache);
        registry.finish(programA,successfulCache,"SUCCESS");
        registry.finish(programA,successfulCache,"ERROR");
        yes(registry.page(programA,17L,"a".repeat(64),0,1,null,null)
            .state().equals("SUCCESS"),
            "late provider error must not rewrite a completed run");

        // The three-argument overload must not hold the monitor while its
        // four-argument delegate invokes cancellation synchronously.
        var monitorCache=new FindingsCache();
        var monitorCancelCalls=new java.util.concurrent.atomic.AtomicInteger();
        registry.begin(programA,17L,"a".repeat(64),monitorCache,()->{
            monitorCancelCalls.incrementAndGet();
            yes(!Thread.holdsLock(registry),
                "replacement cancellation must run without registry monitor");
            registry.finish(programA,monitorCache,"CANCELLED");
        });
        var nextMonitorCache=new FindingsCache();
        String monitorRun=registry.begin(programA,17L,
            "a".repeat(64),nextMonitorCache);
        yes(monitorCancelCalls.get()==1 &&
            registry.page(programA,17L,"a".repeat(64),0,1,null,null)
                .run().equals(monitorRun),
            "three-argument begin replaces and cancels previous active run");
        registry.finish(programA,nextMonitorCache,"MAX_TOOLS");
        registry.finish(programA,nextMonitorCache,"SUCCESS");
        yes(registry.page(programA,17L,"a".repeat(64),0,1,null,null)
            .state().equals("MAX_TOOLS"),
            "budget termination must not be promoted by late SUCCESS");

        System.out.println("AGENTIC REGISTRY PASS assertions="+assertions);
    }
}
