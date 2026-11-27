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
            0,1,null,null),"unregistered equal-but-distinct Program has no evidence");
        // Equals-equivalent Ghidra Programs must coexist with distinct runs,
        // independent source identities, pages, revisions and outcomes.
        var otherFindings=new FindingsCache();
        otherFindings.addFinding("second owner only","address 0x500","listing",8);
        String otherRun=registry.begin(equalButDifferent,29L,
            "b".repeat(64),otherFindings);
        var otherPage=registry.page(equalButDifferent,29L,
            "b".repeat(64),0,10,null,null);
        yes(!otherRun.equals(run) &&
            otherPage.run().equals(otherRun) &&
            otherPage.findings().rows().get(0).fact().equals("second owner only") &&
            registry.page(programA,17L,"a".repeat(64),0,1,null,null)
                .run().equals(run),
            "equal Program wrappers must maintain independent runs and evidence");
        denies(()->registry.page(equalButDifferent,17L,"a".repeat(64),
            0,1,null,null),"equal owners cannot borrow another owner's revision/SHA");
        registry.finish(equalButDifferent,otherFindings,"SUCCESS");
        yes(registry.page(equalButDifferent,29L,
            "b".repeat(64),0,10,null,null).complete() &&
            registry.page(programA,17L,
            "a".repeat(64),0,1,null,null).state().equals("RUNNING"),
            "finishing one equal owner cannot finish another");
        registry.invalidate(equalButDifferent);
        denies(()->registry.page(equalButDifferent,29L,"b".repeat(64),
            0,1,null,null),"invalidating equal owner removes only its own pages");
        yes(registry.page(programA,17L,"a".repeat(64),
            0,1,null,null).run().equals(run),
            "invalidating equal Program wrapper does not erase peer evidence");
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
        // Loss from a single overlong finding is structural and cannot
        // be hidden by a terminal SUCCESS state or a one-page snapshot.
        var cropped=new FindingsCache();
        cropped.addFinding("F".repeat(FindingsCache.MAX_FACT_CHARS+5),
            "bounded","listing",6);
        registry.begin(programA,17L,"a".repeat(64),cropped);
        registry.finish(programA,cropped,"SUCCESS");
        var croppedPage=registry.page(programA,17L,"a".repeat(64),
            0,10,null,null);
        yes(croppedPage.state().equals("SUCCESS") &&
            croppedPage.findings().sourceIncomplete() &&
            !croppedPage.complete(),
            "SUCCESS cannot certify a truncated Agentic source");

        // Omitted long tool-source lines cannot be certified by SUCCESS,
        // even when the retained evidence occupies only one page.
        var missingLongLine=new FindingsCache();
        missingLongLine.extractFromToolOutput("listing",
            "ordinary valid evidence line\n"+"X".repeat(301));
        registry.begin(programA,17L,"a".repeat(64),missingLongLine);
        registry.finish(programA,missingLongLine,"SUCCESS");
        var omittedLinePage=registry.page(programA,17L,"a".repeat(64),
            0,100,null,null);
        yes(omittedLinePage.findings().sourceIncomplete() &&
            !omittedLinePage.complete(),
            "omitted long tool lines invalidate complete Agentic checkpoint");

        // GA-15: a successful model exit does not make fact-only or
        // tool-less findings independently sourced. A later high-relevance
        // finding, even after pruning, cannot repair a missing observation.
        var uncited=new FindingsCache(2);
        uncited.addFinding("uncited hypothesis",null,"listing",5);
        uncited.addFinding("well-sourced observation","page=220 sha=known","rag",9);
        registry.begin(programA,17L,"a".repeat(64),uncited);
        registry.finish(programA,uncited,"SUCCESS");
        var uncitedPage=registry.page(programA,17L,"a".repeat(64),
            0,10,null,null);
        yes(uncitedPage.state().equals("SUCCESS") &&
            uncitedPage.findings().retainedCount()==2 &&
            !uncitedPage.findings().sourceIncomplete() &&
            !uncitedPage.complete() && !uncitedPage.findings().complete(),
            "fact without evidence cannot become a complete Agentic checkpoint");
        var noTool=new FindingsCache();
        noTool.addFinding("excerpt without tool","PDF page 220",null,8);
        registry.begin(programA,17L,"a".repeat(64),noTool);
        registry.finish(programA,noTool,"SUCCESS");
        yes(!registry.page(programA,17L,"a".repeat(64),
            0,10,null,null).complete(),
            "missing tool origin is not independent source attribution");
        var restored=new FindingsCache();
        restored.addFinding("first uncited",null,"rag",1);
        restored.clear();
        restored.addFinding("new documented excerpt",
            "MC68332 PDF page 220 INDEX_TIME_ONLY","rag",8);
        registry.begin(programA,17L,"a".repeat(64),restored);
        registry.finish(programA,restored,"SUCCESS");
        yes(registry.page(programA,17L,"a".repeat(64),
            0,10,null,null).complete(),
            "cleared cache generation may regain completeness with sourced findings");
        var evictedSource=new FindingsCache(1);
        evictedSource.addFinding("uncited low rank",null,"rag",1);
        evictedSource.addFinding("cited high rank",
            "PDF page 219 index hash is claim only","rag",10);
        registry.begin(programA,17L,"a".repeat(64),evictedSource);
        registry.finish(programA,evictedSource,"SUCCESS");
        var afterEviction=registry.page(programA,17L,"a".repeat(64),
            0,10,null,null);
        yes(afterEviction.findings().evictedCount()==1 &&
            !afterEviction.complete(),
            "pruning cannot erase a historical uncited source gap");
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
        var otherActive=new FindingsCache();
        otherActive.addFinding("owner B running","address 0x600","listing",7);
        var otherCancelCount=new java.util.concurrent.atomic.AtomicInteger();
        String otherLive=registry.begin(equalButDifferent,17L,
            "a".repeat(64),otherActive,()->{
                otherCancelCount.incrementAndGet();
                registry.finish(equalButDifferent,otherActive,"CANCELLED");
            });
        registry.invalidate(equalButDifferent);
        yes(cancelCount.get()==0 && otherCancelCount.get()==1 &&
            registry.page(programA,17L,"a".repeat(64),0,1,null,null).run().equals(live),
            "cancelling equal-but-distinct owner B cannot cancel owner A");
        denies(()->registry.page(equalButDifferent,17L,"a".repeat(64),
            0,1,otherLive,null),"B pages must disappear after B invalidation");
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

        // An equals() collision and a constant hashCode collision are
        // not grounds to share evidence, even with matching source SHAs.
        record CollidingOwner(int number) {
            @Override public int hashCode() {return 1;}
        }
        var ownerOne=new CollidingOwner(1);
        var ownerOneEqual=new CollidingOwner(1);
        var ownerTwo=new CollidingOwner(2);
        var cacheOne=new FindingsCache();
        var cacheOneEqual=new FindingsCache();
        var cacheTwo=new FindingsCache();
        cacheOne.addFinding("A","source A","listing",8);
        cacheOneEqual.addFinding("B","source B","listing",8);
        cacheTwo.addFinding("C","source C","listing",8);
        var independent=new AgenticEvidenceRegistry<CollidingOwner>();
        String runA=independent.begin(ownerOne,5L,"c".repeat(64),cacheOne);
        String runB=independent.begin(ownerOneEqual,5L,"c".repeat(64),cacheOneEqual);
        String runC=independent.begin(ownerTwo,5L,"c".repeat(64),cacheTwo);
        independent.finish(ownerOne,cacheOne,"SUCCESS");
        independent.finish(ownerOneEqual,cacheOneEqual,"SUCCESS");
        independent.finish(ownerTwo,cacheTwo,"SUCCESS");
        yes(!runA.equals(runB) && !runB.equals(runC) &&
            independent.page(ownerOne,5L,"c".repeat(64),0,1,null,null)
                .findings().rows().get(0).fact().equals("A") &&
            independent.page(ownerOneEqual,5L,"c".repeat(64),0,1,null,null)
                .findings().rows().get(0).fact().equals("B") &&
            independent.page(ownerTwo,5L,"c".repeat(64),0,1,null,null)
                .findings().rows().get(0).fact().equals("C"),
            "identity keys isolate equals-equivalent and hash-colliding Programs");
        independent.invalidate(ownerOneEqual);
        yes(independent.page(ownerOne,5L,"c".repeat(64),0,1,null,null)
                .complete() &&
            independent.page(ownerTwo,5L,"c".repeat(64),0,1,null,null)
                .complete(),
            "invalidating one collided key does not erase other evidence");
        denies(()->independent.page(ownerOneEqual,5L,
            "c".repeat(64),0,1,null,null),
            "invalidation removes exact colliding key only");

        // Deterministically emulate an enqueued, cleared weak owner key:
        // never depend on System.gc() timing for identity-map cleanup tests.
        var cleanup=new AgenticEvidenceRegistry<Object>();
        var disposableOwner=new Object();
        var disposableFindings=new FindingsCache();
        disposableFindings.addFinding("temporary","disposable source","listing",5);
        cleanup.begin(disposableOwner,1L,"d".repeat(64),disposableFindings);
        try {
            var field=AgenticEvidenceRegistry.class.getDeclaredField("programs");
            field.setAccessible(true);
            var entries=(java.util.Map<?,?>)field.get(cleanup);
            yes(entries.size()==1,"weak identity map stores one live owner");
            var weak=(java.lang.ref.Reference<?>)entries.keySet().iterator().next();
            weak.clear();
            yes(weak.enqueue(),"synthetic weak owner can be queued exactly once");
            var survivor=new Object();
            var survivorFindings=new FindingsCache();
            survivorFindings.addFinding("survivor","source","listing",6);
            cleanup.begin(survivor,1L,"d".repeat(64),survivorFindings);
            yes(entries.size()==1 && cleanup.page(survivor,1L,
                "d".repeat(64),0,1,null,null)
                    .findings().rows().get(0).fact().equals("survivor"),
                "queued weak identity is discarded without deleting live owner");
            denies(()->cleanup.page(disposableOwner,1L,
                "d".repeat(64),0,1,null,null),
                "cleared weak owner cannot be retrieved as current evidence");
        } catch(ReflectiveOperationException e) {
            throw new AssertionError("Identity-map queue regression setup failed",e);
        }

        System.out.println("AGENTIC REGISTRY PASS assertions="+assertions);
    }
}
