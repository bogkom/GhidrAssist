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
        String state="RUNNING";
        Bound(K owner,long revision,String importSha,FindingsCache findings) {
            this.owner=new WeakReference<>(owner);
            this.revision=revision;
            this.importSha=importSha;
            this.findings=findings;
            this.run=UUID.randomUUID().toString();
        }
    }

    /** A truthful *page of retained findings*, not proof of full analysis. */
    public record EvidencePage(String run,long programRevision,String importSha256,
            String state,boolean complete,FindingsCache.FindingsPage findings) {}

    private final Map<K,Bound<K>> programs=new WeakHashMap<>();

    public synchronized String begin(K owner,long revision,String importSha,
                                      FindingsCache findings) {
        if(owner==null || revision<0 || findings==null)
            throw new IllegalArgumentException("Missing evidence Program or revision");
        Bound<K> existing=programs.get(owner);
        if(existing!=null && existing.owner.get()!=owner)
            throw new IllegalStateException(
                "Equal-but-distinct Program cannot share Agentic evidence");
        Bound<K> bound=new Bound<>(owner,revision,
            importSha==null?"UNKNOWN":importSha,findings);
        programs.put(owner,bound);
        return bound.run;
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
            bound.state,"SUCCESS".equals(bound.state) && page.complete(),page);
    }

    public synchronized void invalidate(K owner) {
        if(owner!=null)programs.remove(owner);
    }
}
