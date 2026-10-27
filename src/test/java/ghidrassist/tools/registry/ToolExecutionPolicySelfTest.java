package ghidrassist.tools.registry;

import com.google.gson.JsonObject;
import ghidra.program.model.listing.Program;
import ghidrassist.tools.api.*;
import ghidrassist.tools.approval.ToolApprovalService;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/** Standalone contract tests; no GUI, model, project or user profile is required. */
public class ToolExecutionPolicySelfTest {
    private static final AtomicInteger executions = new AtomicInteger();
    private static final List<String> NAMES = List.of("get_alpha", "get_beta", "get_task_status", "server.get_task_status");
    private static ToolRegistry registry() {
        ToolRegistry registry = new ToolRegistry();
        registry.registerProvider(new ToolProvider() {
            public String getProviderName() { return "policy-fixture"; }
            public List<Tool> getTools() {
                return NAMES.stream().map(name -> (Tool) new Tool() {
                    public String getName() { return name; }
                    public String getDescription() { return "Fixture"; }
                    public JsonObject getInputSchema() { return new JsonObject(); }
                    public String getSource() { return "fixture"; }
                }).toList();
            }
            public boolean handlesTool(String name) { return NAMES.contains(name); }
            public void setContext(Program program) { }
            public CompletableFuture<ToolResult> executeTool(String name, JsonObject args) {
                executions.incrementAndGet();
                return CompletableFuture.completedFuture(ToolResult.success("value"));
            }
        });
        return registry;
    }
    private static ToolResult call(ToolRegistry registry, String tool, int key) {
        JsonObject args = new JsonObject(); args.addProperty("key", key);
        return registry.execute(tool, args).join();
    }
    private static void check(boolean value, String message) { if (!value) throw new AssertionError(message); }
    public static void main(String[] args) {
        Map<String,Integer> budgets = new HashMap<>(Map.of("get_alpha", 1));
        Set<String> allowed = new HashSet<>(Set.of("get_alpha", "get_beta"));
        ToolExecutionPolicy policy = new ToolExecutionPolicy(allowed, budgets);
        budgets.put("get_alpha", 99); allowed.add("other");
        check(policy.limit("get_alpha") == 1 && !policy.allows("other"), "Policy must be immutable");
        ToolRegistry registry = registry();
        registry.configureInvestigationToolLimit("Read tools", policy);
        check(call(registry, "get_alpha", 1).isSuccess(), "First budgeted read");
        check(call(registry, "get_alpha", 2).isError(), "Different args must not bypass per-tool budget");
        check(call(registry, "get_beta", 1).isSuccess(), "One tool's limit must not be global");
        check(registry.getInvestigationToolCallCount() == 2, "Actual executions only");
        check(call(registry, "get_task_status", 1).isError(), "Unlisted tool must be blocked");
        registry.configureInvestigationToolLimit("", new ToolExecutionPolicy(Set.of(), Map.of()));
        check(call(registry, "get_alpha", 1).isError(), "Empty allowlist denies all");
        registry.configureInvestigationToolLimit("", new ToolExecutionPolicy(Set.of("unknown"), Map.of()));
        check(call(registry, "get_alpha", 1).isError(), "Unknown policy names cannot authorize known tools");
        registry.configureInvestigationToolLimit("Read tools");
        check(call(registry, "get_beta", 1).isSuccess(), "Policy resets between investigations");
        check(call(registry, "get_beta", 1).isError(), "Static read deduplication remains enabled");
        check(call(registry, "get_task_status", 1).isSuccess() && call(registry, "get_task_status", 1).isSuccess(), "Changing status can be polled");
        check(call(registry, "server.get_task_status", 1).isSuccess() && call(registry, "server.get_task_status", 1).isSuccess(), "Prefixed status can be polled");
        registry.configureInvestigationToolLimit("Call exactly one tool");
        check(call(registry, "get_alpha", 1).isSuccess() && call(registry, "get_beta", 1).isError(), "Explicit global limit stays global");
        registry.configureInvestigationToolLimit("", new ToolExecutionPolicy(null, Map.of("get_alpha", 0)));
        check(call(registry, "get_alpha", 1).isError() && call(registry, "get_beta", 1).isSuccess(), "Zero per-tool budget");
        boolean invalid = false;
        try { new ToolExecutionPolicy(null, Map.of("get_alpha", -1)); } catch (IllegalArgumentException expected) { invalid = true; }
        check(invalid, "Reject negative budget");
        registry.configureInvestigationToolLimit("", new ToolExecutionPolicy(null, Map.of("get_alpha", 1)));
        List<CompletableFuture<ToolResult>> requests = new ArrayList<>();
        for (int i=0; i<20; i++) { JsonObject value = new JsonObject(); value.addProperty("key", i); requests.add(registry.execute("get_alpha", value)); }
        CompletableFuture.allOf(requests.toArray(CompletableFuture[]::new)).join();
        check(requests.stream().filter(r -> r.join().isSuccess()).count() == 1, "Concurrent budget reservation must be atomic");
        registry.configureInvestigationToolLimit("", new ToolExecutionPolicy(null, Map.of("get_alpha", 1)));
        registry.setActiveSessionSupplier(() -> 1);
        registry.setApprovalService(new ToolApprovalService(null, null) {
            int requests;
            @Override public CompletableFuture<ApprovalOutcome> requestApproval(int session, String hash, String id, Tool tool, JsonObject values) {
                return CompletableFuture.completedFuture(++requests == 1 ? ApprovalOutcome.denied("fixture") : ApprovalOutcome.approved("fixture"));
            }
        });
        check(call(registry, "get_alpha", 1).isError() && registry.getInvestigationToolCallCount() == 0, "Denial must not consume budget");
        check(call(registry, "get_alpha", 1).isSuccess(), "Denied arguments must not poison deduplication");
        System.out.println("ToolExecutionPolicySelfTest PASS");
    }
}
