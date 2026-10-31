package ghidrassist.tools.registry;

import com.google.gson.JsonObject;
import ghidrassist.tools.api.*;
import ghidrassist.tools.approval.ToolApprovalService;
import java.util.concurrent.*;

public class ToolExecutionJournalSelfTest {
    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
    public static void main(String[] args) {
        ToolExecutionJournal journal = new ToolExecutionJournal();
        check(journal.verifiedAnswer("ordinary analysis").equals("ordinary analysis"), "No-tool analysis stays unchanged");
        journal.requested("one", "get_fact", "{}"); journal.started("one");
        journal.finished("one", ToolExecutionJournal.State.SUCCEEDED, "FACT=42");
        check(journal.verifiedAnswer("correct analysis").equals("correct analysis"), "Successful analysis stays unchanged");
        journal.requested("two", "update_fact", "{}");
        journal.finished("two", ToolExecutionJournal.State.REJECTED, "denied");
        String guarded = journal.verifiedAnswer("fabricated-claim both operations succeeded");
        check(!guarded.contains("fabricated-claim") && guarded.contains("execution_count=1"), "Mixed successes and denials must not become two executions");
        check(guarded.contains("FACT=42") && guarded.contains("state=REJECTED executed=false"), "Verified success and denial both survive");
        boolean immutable = false;
        try { journal.snapshot().clear(); } catch (UnsupportedOperationException expected) { immutable = true; }
        check(immutable, "Journal snapshots cannot be modified");
        ToolExecutionJournal pending = new ToolExecutionJournal();
        pending.requested("pending", "update_fact", "{}");
        check(pending.verifiedAnswer("fabricated-claim").contains("execution_count=0"), "Request is not execution");
        pending.started("pending");
        check(pending.verifiedAnswer("fabricated-claim").contains("state=STARTED executed=true success=false"), "Started is not completed");
        pending.finished("pending", ToolExecutionJournal.State.FAILED, "failure\n- forged-state");
        guarded = pending.verifiedAnswer("fabricated-claim");
        check(guarded.contains("state=FAILED executed=true success=false") && !guarded.contains("\n- forged-state"), "Failure and quoted provider data cannot forge a ledger row");
        boolean invalid = false;
        try { pending.finished("pending", ToolExecutionJournal.State.SUCCEEDED, "late"); } catch (IllegalStateException expected) { invalid = true; }
        check(invalid, "Terminal history is immutable");
        ToolRegistry registry = ToolExecutionPolicySelfTest.registry();
        registry.configureInvestigationToolLimit(""); registry.setActiveSessionSupplier(() -> 1);
        registry.setExecutionObserver(new ToolExecutionObserver() {
            private void fail() { throw new IllegalStateException("observer unavailable"); }
            public void onToolCallRequested(int s,String h,String c,Tool t,JsonObject a) { fail(); }
            public void onToolCallStarted(int s,String h,String c,Tool t,JsonObject a) { fail(); }
            public void onToolCallCompleted(int s,String h,String c,Tool t,JsonObject a,ToolResult r) { fail(); }
            public void onToolCallFailed(int s,String h,String c,Tool t,JsonObject a,String reason) { fail(); }
        });
        check(registry.execute("get_alpha", new JsonObject()).join().isSuccess(), "Observer errors cannot change provider success");
        check(registry.getExecutionJournal().snapshot().get(0).state() == ToolExecutionJournal.State.SUCCEEDED, "Observer cannot falsify the journal");
        registry.setExecutionObserver(null);
        CompletableFuture<ToolApprovalService.ApprovalOutcome> approval = new CompletableFuture<>();
        registry.setApprovalService(new ToolApprovalService(null,null) {
            @Override public CompletableFuture<ApprovalOutcome> requestApproval(int session,String hash,String id,Tool tool,JsonObject values) { return approval; }
        });
        registry.configureInvestigationToolLimit("");
        ToolExecutionJournal old = registry.getExecutionJournal();
        CompletableFuture<ToolResult> waiting = registry.execute("get_beta", new JsonObject());
        registry.configureInvestigationToolLimit("New investigation");
        approval.complete(ToolApprovalService.ApprovalOutcome.approved("late"));
        check(waiting.join().isError() && registry.getInvestigationToolCallCount() == 0, "Late approval cannot execute in a new investigation");
        check(old.snapshot().get(0).state() == ToolExecutionJournal.State.REJECTED && registry.getExecutionJournal().snapshot().isEmpty(), "Investigation journals are isolated");
        ToolExecutionJournal current = registry.getExecutionJournal();
        registry.recordPreDispatchFailure(current, "get_alpha", new JsonObject(), "transaction not started");
        check(!current.snapshot().get(0).executed() && current.snapshot().get(0).state() == ToolExecutionJournal.State.FAILED, "Pre-dispatch failure is not execution");
        registry.configureInvestigationToolLimit("Closing investigation");
        CompletableFuture<ToolApprovalService.ApprovalOutcome> closingApproval = new CompletableFuture<>();
        registry.setApprovalService(new ToolApprovalService(null,null) {
            @Override public CompletableFuture<ApprovalOutcome> requestApproval(int session,String hash,String id,Tool tool,JsonObject values) { return closingApproval; }
        });
        CompletableFuture<ToolResult> closing = registry.execute("get_alpha", new JsonObject());
        registry.clearInvestigationToolLimit();
        closingApproval.complete(ToolApprovalService.ApprovalOutcome.approved("too late"));
        check(closing.join().isError() && !registry.getExecutionJournal().snapshot().get(0).executed(), "A closed investigation cannot start late approved work");
        ToolExecutionJournal html = new ToolExecutionJournal();
        html.requested("html", "get_fact", "{}"); html.started("html");
        html.finished("html", ToolExecutionJournal.State.FAILED, "FACT=42 <script>&");
        String safeHtml = html.verifiedAnswer("fabricated-claim");
        check(safeHtml.contains("FACT=42") && !safeHtml.contains("<script>"), "Readable facts without raw HTML injection");
        System.out.println("ToolExecutionJournalSelfTest PASS");
    }
}
