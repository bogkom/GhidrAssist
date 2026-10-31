package ghidrassist.tools.registry;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import ghidrassist.tools.context.ToolResultContext;
import java.time.Instant;
import java.util.*;

/** Controller-owned facts. A proposal/request is never proof of execution. */
public final class ToolExecutionJournal {
    public enum State { REQUESTED, STARTED, SUCCEEDED, REJECTED, FAILED }
    public record Entry(String callId, String toolName, String arguments, State state,
                        Instant requestedAt, Instant startedAt, Instant completedAt, String detail) {
        public boolean executed() { return startedAt != null; }
    }
    private final Map<String, Entry> entries = new LinkedHashMap<>();
    private static final Gson JSON = new GsonBuilder().disableHtmlEscaping().create();
    private static String quote(String value) {
        // Keep facts such as FACT=42 readable while escaping HTML and line breaks.
        return JSON.toJson(value).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026");
    }

    synchronized void requested(String id, String name, String arguments) {
        if (entries.containsKey(id)) throw new IllegalStateException("Duplicate execution identity");
        entries.put(id, new Entry(id, name, arguments, State.REQUESTED, Instant.now(), null, null, null));
    }
    synchronized void started(String id) {
        Entry old = Objects.requireNonNull(entries.get(id));
        if (old.state() != State.REQUESTED) throw new IllegalStateException("Call is not pending");
        entries.put(id, new Entry(id, old.toolName(), old.arguments(), State.STARTED,
            old.requestedAt(), Instant.now(), null, null));
    }
    synchronized void finished(String id, State state, String detail) {
        Entry old = Objects.requireNonNull(entries.get(id));
        if (state != State.SUCCEEDED && state != State.REJECTED && state != State.FAILED)
            throw new IllegalArgumentException("Not a terminal execution state");
        if (old.completedAt() != null) throw new IllegalStateException("Execution is already terminal");
        if ((state == State.SUCCEEDED && !old.executed()) || (state == State.REJECTED && old.executed()))
            throw new IllegalStateException("State contradicts observed execution");
        entries.put(id, new Entry(id, old.toolName(), old.arguments(), state, old.requestedAt(), old.startedAt(),
            Instant.now(), ToolResultContext.truncate(detail, 1200)));
    }
    public synchronized List<Entry> snapshot() { return List.copyOf(entries.values()); }

    /**
     * Free-form claims cannot be proven after a rejected/failed/pending attempt.
     * In that case publish only dispatcher facts, never the unverified model text.
     * Successful-only analysis remains unchanged; this is not an NLP truth detector.
     */
    public String verifiedAnswer(String proposedAnswer) {
        List<Entry> observed = snapshot();
        if (observed.stream().allMatch(entry -> entry.state() == State.SUCCEEDED))
            return proposedAnswer;
        StringBuilder safe = new StringBuilder("Verified tool execution report (unverified model synthesis withheld).\n");
        safe.append("execution_count=").append(observed.stream().filter(Entry::executed).count()).append('\n');
        for (Entry entry : observed) {
            safe.append("- tool=").append(quote(entry.toolName())).append(" call_id=").append(entry.callId())
                .append(" state=").append(entry.state())
                .append(" executed=").append(entry.executed())
                .append(" success=").append(entry.state() == State.SUCCEEDED);
            if (entry.detail() != null) safe.append(" returned_data=").append(quote(entry.detail()));
            safe.append('\n');
        }
        return safe.toString();
    }
}
