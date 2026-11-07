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
        System.out.println("AGENTIC REGISTRY PASS assertions="+assertions);
    }
}
