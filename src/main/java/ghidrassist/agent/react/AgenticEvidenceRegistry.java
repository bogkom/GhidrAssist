package ghidrassist.agent.react;

import java.lang.ref.WeakReference;
import java.util.Map;
import java.util.UUID;
import java.util.WeakHashMap;

/**
 * GA-12/15: read-only bridge between a real ReAct findings cache and the
 * authenticated, process-local Automation API. Never runs a model, accepts
 * a remote finding, resumes an LLM conversation or authorizes Apply.
 *
 * Weak owner keys and an independent owner-identity check avoid returning
 * stale evidence from a different (but equals()-equivalent) Program.
 */
public final class AgenticEvidenceRegistry<K> {
    private static final AgenticEvidenceRegistry<Object> SHARED =
        new AgenticEvidenceRegistry<>();

    public static AgenticEvidenceRegistry<Object> shared() {
        return SHARED;
    }

    private static final class Bound<K> {
        final WeakReference<K> owner;
        final long revision;
        final String importSha;
        final String run;
        final FindingsCache findings;
        final Runnable onInvalidated;
        String state="RUNNING";
        Bound(K owner,long revision,String importSha,FindingsCache findings,
                Runnable onInvalidated) {
            this.owner=new WeakReference<>(owner);
            this.revision=revision;
            this.importSha=importSha;
            this.findings=findings;
            this.onInvalidated=onInvalidated;
            this.run=UUID.randomUUID().toString();
        }
    }

    /** A truthful *page of retained findings*, not proof of full analysis. */
    public record EvidencePage(String run,long programRevision,String importSha256,
            String state,boolean complete,FindingsCache.FindingsPage findings) {}

    private final Map<K,Bound<K>> programs=new WeakHashMap<>();

    public synchronized String begin(K owner,long revision,String importSha,
                                      FindingsCache findings) {
        return begin(owner,revision,importSha,findings,null);
    }

    /**
     * Optional cancellation belongs to this exact run. Production ReAct
     * registers its own cancel callback; synthetic/static users can omit it.
     * Invalidation removes the source before invoking any callback.
     */
    public String begin(K owner,long revision,String importSha,
                        FindingsCache findings,Runnable onInvalidated) {
        if(owner==null || revision<0 || findings==null)
            throw new IllegalArgumentException("Missing evidence Program or revision");
        Runnable previousCancellation=null;
        String run;
        synchronized(this) {
            Bound<K> existing=programs.get(owner);
            if(existing!=null && existing.owner.get()!=owner)
                throw new IllegalStateException(
                    "Equal-but-distinct Program cannot share Agentic evidence");
            // Publishing the new generation first prevents re-entrant completion
            // of the replaced run from overwriting its state or findings.
            Bound<K> bound=new Bound<>(owner,revision,
                importSha==null?"UNKNOWN":importSha,findings,onInvalidated);
            programs.put(owner,bound);
            run=bound.run;
            if(existing!=null && "RUNNING".equals(existing.state))
                previousCancellation=existing.onInvalidated;
        }
        // Never invoke provider cancellation while holding the registry lock:
        // providers may synchronously call finish() on the old run.
        if(previousCancellation!=null)previousCancellation.run();
        return run;
    }

    /** Finish only the exact previously registered cache, never a later run. */
    public synchronized void finish(K owner,FindingsCache findings,String outcome) {
        if(owner==null || findings==null)return;
        Bound<K> bound=programs.get(owner);
        if(bound!=null && bound.owner.get()==owner && bound.findings==findings)
            bound.state=switch(outcome==null?"":outcome) {
                case "SUCCESS" -> "SUCCESS";
                case "CANCELLED" -> "CANCELLED";
                case "MAX_ITERATIONS" -> "MAX_ITERATIONS";
                case "MAX_TOOLS" -> "MAX_TOOLS";
                default -> "ERROR";
            };
    }

    public synchronized EvidencePage page(K owner,long revision,String importSha,
            int offset,int limit,String expectedRun,Long expectedFindingsRevision) {
        if(owner==null || revision<0)
            throw new IllegalArgumentException("No active Program to inspect");
        Bound<K> bound=programs.get(owner);
        if(bound==null || bound.owner.get()!=owner)
            throw new IllegalStateException("No Agentic findings for current Program");
        String sha=importSha==null?"UNKNOWN":importSha;
        if(bound.revision!=revision || !bound.importSha.equals(sha))
            throw new IllegalStateException("Agentic findings Program revision changed");
        if(offset>0 && (expectedRun==null || expectedFindingsRevision==null))
            throw new IllegalArgumentException(
                "Nonzero offset requires expected_run and expected_findings_revision");
        if(expectedRun!=null && !bound.run.equals(expectedRun))
            throw new IllegalStateException("Agentic run changed during pagination");
        FindingsCache.FindingsPage page=expectedFindingsRevision==null ?
            bound.findings.page(offset,limit) :
            bound.findings.page(offset,limit,expectedFindingsRevision);
        return new EvidencePage(bound.run,bound.revision,bound.importSha,
            bound.state,"SUCCESS".equals(bound.state) && page.complete() &&
                page.retainedCount()>0 && bound.importSha.matches(
                    "(?i)[a-f0-9]{64}"),page);
    }

    public void invalidate(K owner) {
        Runnable callback=null;
        synchronized(this) {
            if(owner!=null) {
                Bound<K> bound=programs.get(owner);
                // Do not delete or cancel an equals()-equivalent but
                // different Program. This guard also protects key identity.
                if(bound!=null && bound.owner.get()==owner) {
                    programs.remove(owner);
                    if("RUNNING".equals(bound.state))
                        callback=bound.onInvalidated;
                }
            }
        }
        // No registry lock is held: cancelling a ReAct future synchronously
        // may trigger a completion handler that re-enters finish().
        if(callback!=null)callback.run();
    }
}
