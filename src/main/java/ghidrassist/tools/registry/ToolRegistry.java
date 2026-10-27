package ghidrassist.tools.registry;

import com.google.gson.JsonObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidrassist.tools.approval.ToolApprovalService;
import ghidrassist.tools.api.Tool;
import ghidrassist.tools.api.ToolExecutionObserver;
import ghidrassist.tools.api.ToolExecutor;
import ghidrassist.hardware.McpEvidenceGuard;
import ghidrassist.tools.api.ToolProvider;
import ghidrassist.tools.api.ToolResult;
import ghidrassist.tools.context.ToolResultContext;
import ghidrassist.tools.native_.NativeToolManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.IntSupplier;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Central registry that aggregates tools from all providers.
 * Provides unified access to tools regardless of their source.
 *
 * Usage:
 *   ToolRegistry registry = new ToolRegistry();
 *   registry.registerProvider(new NativeToolManager(db));
 *   registry.registerProvider(new MCPToolManager(mcpRegistry));
 *
 *   List<Tool> allTools = registry.getAllTools();
 *   ToolResult result = registry.execute("get_semantic_analysis", args).join();
 */
public class ToolRegistry implements ToolExecutor {

    private final List<ToolProvider> providers = new ArrayList<>();
    private Program currentProgram;
    private Address currentAddress;
    private volatile ToolExecutionObserver executionObserver;
    // Per-registry, bounded evidence retained across ReAct iterations. A normal
    // query registry and each ReAct orchestrator have separate instances.
    private final java.util.LinkedHashMap<String,String> toolObservations =
        new java.util.LinkedHashMap<>();
    private volatile ToolApprovalService approvalService;
    private volatile IntSupplier activeSessionSupplier = () -> -1;
    private volatile Supplier<String> programHashSupplier = () -> null;
    // Limits are enforced by the dispatcher, not merely suggested to the LLM.
    // A null limit means the user did not request a hard per-investigation cap.
    private Integer investigationToolLimit;
    private boolean investigationReadOnly;
    private int investigationToolCalls;
    private volatile ToolExecutionJournal executionJournal = new ToolExecutionJournal();
    private boolean investigationClosed;
    private volatile ToolExecutionPolicy executionPolicy = ToolExecutionPolicy.unrestricted();
    private final Map<String, Integer> perToolCalls = new HashMap<>();
    private final java.util.Set<String> investigationReadKeys = new java.util.HashSet<>();
    private synchronized boolean reserveUniqueRead(String toolName, JsonObject args) {
        // Task status is a changing observation, including server-prefixed MCP names.
        String localName = toolName == null ? "" : toolName.substring(toolName.lastIndexOf('.') + 1);
        if (localName.equals("get_task_status") || !isReadOnlyLookup(toolName)) return true;
        Tool tool = getTool(toolName);
        String key = (tool == null ? toolName : tool.getExecutionIdentity()) + ":" + (args == null ? "{}" : args.toString());
        return investigationReadKeys.add(key);
    }


    public synchronized void configureInvestigationToolLimit(String objective) {
        configureInvestigationToolLimit("", ToolExecutionPolicy.unrestricted());
        String normalized = objective == null ? "" : objective.toLowerCase(java.util.Locale.ROOT);
        investigationReadOnly = normalized.contains("nie modyfikuj projektu")
            || normalized.contains("nie zmieniaj projektu")
            || normalized.contains("do not modify the project")
            || normalized.contains("do not change the program");
        if (normalized.contains("nie wywołuj żadnych narzędzi")
                || normalized.contains("nie wykonuj żadnych wywołań")
                || normalized.contains("do not call any tools")
                || normalized.contains("do not invoke any tools")) {
            investigationToolLimit = 0;
        } else if (normalized.contains("wywołaj dokładnie jeden raz")
                || normalized.contains("nie wykonuj więcej niż jednego wywołania")
                || normalized.contains("maksymalnie jedno wywołanie")
                || normalized.contains("exactly one tool call")
                || normalized.contains("call exactly one tool")) {
            investigationToolLimit = 1;
        } else {
            investigationToolLimit = null;
        }
    }


    /** Explicit policy is authoritative; do not reinterpret its budgets from prose. */
    public synchronized void configureInvestigationToolLimit(String ignoredObjective, ToolExecutionPolicy policy) {
        executionPolicy = java.util.Objects.requireNonNull(policy);
        executionJournal = new ToolExecutionJournal();
        investigationClosed = false;
        perToolCalls.clear();
        investigationToolCalls = 0;
        investigationReadKeys.clear();
        investigationToolLimit = policy.totalLimit();
        investigationReadOnly = policy.readOnly();
    }

    public synchronized void clearInvestigationToolLimit() {
        investigationClosed = true;
        executionPolicy = ToolExecutionPolicy.unrestricted();
        perToolCalls.clear();
        investigationToolLimit = null;
        investigationReadOnly = false;
        investigationToolCalls = 0;
        investigationReadKeys.clear();
    }

    private synchronized String reserveInvestigationToolCall(String toolName, JsonObject args, ToolExecutionJournal journal) {
        if (journal != executionJournal || investigationClosed) return "Investigation is no longer active";
        if (!executionPolicy.allows(toolName)) return "Tool call blocked: tool is not allowed by the controller policy";
        Tool tool = getTool(toolName);
        String identity = tool.getExecutionIdentity();
        Integer toolLimit = executionPolicy.limit(toolName);
        // A budget on one registered alias also constrains the same backend operation.
        for (Tool candidate : getAllTools()) {
            Integer candidateLimit = executionPolicy.limit(candidate.getName());
            if (candidateLimit != null && identity.equals(candidate.getExecutionIdentity()))
                toolLimit = toolLimit == null ? candidateLimit : Math.min(toolLimit, candidateLimit);
        }
        if (toolLimit != null && perToolCalls.getOrDefault(identity, 0) >= toolLimit)
            return "Tool call blocked: per-tool limit reached for " + toolName;
        if (investigationToolLimit != null && investigationToolCalls >= investigationToolLimit)
            return "Tool call blocked: user-defined investigation tool limit reached";
        if (!reserveUniqueRead(toolName, args))
            return "Duplicate read-only request suppressed; reuse previous evidence";
        investigationToolCalls++;
        perToolCalls.merge(identity, 1, Integer::sum);
        return null;
    }

    public synchronized int getInvestigationToolCallCount() {
        return investigationToolCalls;
    }


    /**
     * Register a tool provider.
     * @param provider The provider to register
     */
    public void registerProvider(ToolProvider provider) {
        if (provider != null) {
            providers.add(provider);
            // Set current program context if we have one
            if (currentProgram != null) {
                provider.setContext(currentProgram);
            }
            Msg.info(this, "Registered tool provider: " + provider.getProviderName() +
                    " with " + provider.getTools().size() + " tools");
        }
    }

    /**
     * Unregister a tool provider.
     * @param provider The provider to unregister
     */
    public void unregisterProvider(ToolProvider provider) {
        providers.remove(provider);
    }

    /**
     * Check if a provider with the given name is already registered.
     * @param providerName Name of the provider
     * @return true if a provider with this name is registered
     */
    public boolean hasProvider(String providerName) {
        return providers.stream().anyMatch(p -> p.getProviderName().equals(providerName));
    }

    /**
     * Get all registered providers.
     * @return List of providers
     */
    public List<ToolProvider> getProviders() {
        return new ArrayList<>(providers);
    }

    @Override
    public List<Tool> getAllTools() {
        return providers.stream()
                .flatMap(p -> p.getTools().stream())
                .collect(Collectors.toList());
    }

    /**
     * Get tools from a specific provider.
     * @param providerName Name of the provider
     * @return List of tools from that provider
     */
    public List<Tool> getToolsByProvider(String providerName) {
        return providers.stream()
                .filter(p -> p.getProviderName().equals(providerName))
                .flatMap(p -> p.getTools().stream())
                .collect(Collectors.toList());
    }

    /**
     * Find a tool by name across all providers.
     * @param toolName Tool name
     * @return The tool, or null if not found
     */
    public Tool getTool(String toolName) {
        for (ToolProvider provider : providers) {
            for (Tool tool : provider.getTools()) {
                if (tool.getName().equals(toolName)) {
                    return tool;
                }
            }
        }
        return null;
    }

    /**
     * Check if any provider handles the given tool.
     * @param toolName Tool name
     * @return true if a provider can handle the tool
     */
    public boolean handlesTool(String toolName) {
        return providers.stream().anyMatch(p -> p.handlesTool(toolName));
    }

    public ToolExecutionJournal getExecutionJournal() { return executionJournal; }

    private void notifyObserver(java.util.function.Consumer<ToolExecutionObserver> callback) {
        ToolExecutionObserver observer = executionObserver;
        if (observer == null) return;
        try { callback.accept(observer); }
        catch (RuntimeException error) { Msg.warn(this, "Tool observer failed: " + error.getMessage()); }
    }

    private ToolResult reject(ToolExecutionJournal journal, String id, Tool tool, JsonObject args,
            int sessionId, String hash, String reason) {
        journal.finished(id, ToolExecutionJournal.State.REJECTED, reason);
        if (tool != null && sessionId > 0)
            notifyObserver(observer -> observer.onToolCallFailed(sessionId, hash, id, tool, args, reason));
        return ToolResult.error(reason);
    }

    /** A transaction failed before the dispatcher was entered; it did not execute a tool. */
    public void recordPreDispatchFailure(ToolExecutionJournal journal, String name, JsonObject args, String reason) {
        String id = java.util.UUID.randomUUID().toString();
        journal.requested(id, name, args == null ? "{}" : args.toString());
        journal.finished(id, ToolExecutionJournal.State.FAILED, reason);
    }

    @Override
    public CompletableFuture<ToolResult> execute(String toolName, JsonObject args) {
        final ToolExecutionJournal journal = executionJournal;
        final String id = java.util.UUID.randomUUID().toString();
        journal.requested(id, toolName, args == null ? "{}" : args.toString());
        final Tool tool = getTool(toolName);
        final int sessionId = activeSessionSupplier != null ? activeSessionSupplier.getAsInt() : -1;
        final String hash = programHashSupplier != null ? programHashSupplier.get() : null;
        if (tool != null && sessionId > 0)
            notifyObserver(observer -> observer.onToolCallRequested(sessionId, hash, id, tool, args));
        String earlyRejection = tool == null ? "Unknown tool: " + toolName
            : !executionPolicy.allows(toolName) ? "Tool call blocked: tool is not allowed by the controller policy"
            : investigationToolLimit != null && investigationToolLimit == 0 ? "Tool call blocked: the user prohibited tools for this investigation"
            : investigationReadOnly && !isReadOnlyLookup(toolName) ? "Tool call blocked: the user explicitly prohibited Ghidra project modification" : null;
        if (earlyRejection != null)
            return CompletableFuture.completedFuture(reject(journal, id, tool, args, sessionId, hash, earlyRejection));

        CompletableFuture<ToolApprovalService.ApprovalOutcome> approval;
        try {
            approval = approvalService == null
                ? CompletableFuture.completedFuture(ToolApprovalService.ApprovalOutcome.approved(ToolApprovalService.DECISION_ALLOW_ONCE))
                : java.util.Objects.requireNonNull(approvalService.requestApproval(sessionId, hash, id, tool, args));
        } catch (Exception error) {
            approval = CompletableFuture.failedFuture(error);
        }
        return approval.thenComposeAsync(outcome -> {
            if (outcome == null || !outcome.isApproved())
                return CompletableFuture.completedFuture(reject(journal, id, tool, args, sessionId, hash, "Tool execution denied by user"));
            for (ToolProvider provider : providers) {
                if (!provider.handlesTool(toolName)) continue;
                // An approval for an investigation that has already ended cannot start new work.
                if (journal != executionJournal)
                    return CompletableFuture.completedFuture(reject(journal, id, tool, args, sessionId, hash, "Investigation is no longer active"));
                String rejection = reserveInvestigationToolCall(toolName, args, journal);
                if (rejection != null)
                    return CompletableFuture.completedFuture(reject(journal, id, tool, args, sessionId, hash, rejection));
                journal.started(id);
                if (sessionId > 0)
                    notifyObserver(observer -> observer.onToolCallStarted(sessionId, hash, id, tool, args));
                Msg.info(this, "Executing tool '" + toolName + "' via provider " + provider.getProviderName());
                return provider.executeTool(toolName, args).handle((result, failure) -> {
                    ToolResult safe = failure != null ? ToolResult.error(failure.toString())
                        : result == null ? ToolResult.error("Tool returned no result") : result;
                    if (safe.isSuccess()) {
                        String original = safe.getContent();
                        String checked = McpEvidenceGuard.enrich(toolName, original);
                        if (checked != null && !checked.equals(original)) safe = ToolResult.success(checked);
                        if (journal == executionJournal) {
                            if (isReadOnlyLookup(toolName)) rememberSuccessfulRead(toolName, args, safe.getContent());
                            else clearRecentToolEvidence();
                        }
                    }
                    journal.finished(id, safe.isSuccess() ? ToolExecutionJournal.State.SUCCEEDED : ToolExecutionJournal.State.FAILED,
                        safe.getContentOrError());
                    final ToolResult delivered = safe;
                    if (sessionId > 0) notifyObserver(observer -> {
                        if (delivered.isError()) observer.onToolCallFailed(sessionId, hash, id, tool, args, delivered.getErrorMessage());
                        else observer.onToolCallCompleted(sessionId, hash, id, tool, args, delivered);
                    });
                    return safe;
                });
            }
            return CompletableFuture.completedFuture(reject(journal, id, tool, args, sessionId, hash, "No provider found for tool: " + toolName));
        }).exceptionally(error -> {
            String reason = "Tool execution failed: " + error;
            journal.finished(id, ToolExecutionJournal.State.FAILED, reason);
            if (sessionId > 0) notifyObserver(observer -> observer.onToolCallFailed(sessionId, hash, id, tool, args, reason));
            return ToolResult.error(reason);
        });
    }

    /** Existing dispatcher classification, also displayed by the task-policy editor. */
    public static boolean isReadOnlyLookup(String name) {
        if (name == null) return false;
        String local=name.toLowerCase(java.util.Locale.ROOT);
        return local.contains("get_") || local.contains("list_") ||
            local.contains("search_");
    }

    /** Reset evidence at the start of each ReAct investigation or after a write. */
    public synchronized void clearRecentToolEvidence() {
        toolObservations.clear();
        investigationReadKeys.clear();
    }

    /** Only successful read-only observations; bounded to eight distinct queries. */
    private synchronized void rememberSuccessfulRead(String name, JsonObject args, String content) {
        if (name == null || content == null) return;
        if (!isReadOnlyLookup(name)) return;
        String key=name+" "+(args==null?"{}":args.toString());
        // Put recent data last even when the same read was attempted again.
        toolObservations.remove(key);
        String concise = ToolResultContext.truncate(content, 2200);
        toolObservations.put(key,concise);
        while(toolObservations.size()>8)
            toolObservations.remove(toolObservations.keySet().iterator().next());
    }

    /** Raw tool-result evidence for ReAct planning and final synthesis. */
    public synchronized String getRecentToolEvidence() {
        if (toolObservations.isEmpty()) return "";
        StringBuilder text=new StringBuilder("Actual successful tool responses (NOT model guesses):\n");
        for (var entry: toolObservations.entrySet()) {
            text.append("TOOL ").append(entry.getKey()).append("\n")
                .append(entry.getValue()).append("\n");
        }
        return text.toString();
    }

    public void setExecutionObserver(ToolExecutionObserver executionObserver) {
        this.executionObserver = executionObserver;
    }

    public void setApprovalService(ToolApprovalService approvalService) {
        this.approvalService = approvalService;
    }

    public void setActiveSessionSupplier(IntSupplier activeSessionSupplier) {
        this.activeSessionSupplier = activeSessionSupplier != null ? activeSessionSupplier : () -> -1;
    }

    public void setProgramHashSupplier(Supplier<String> programHashSupplier) {
        this.programHashSupplier = programHashSupplier != null ? programHashSupplier : () -> null;
    }

    /**
     * Set the Ghidra program context for all providers.
     * @param program Current Ghidra program
     */
    public void setContext(Program program) {
        this.currentProgram = program;
        for (ToolProvider provider : providers) {
            provider.setContext(program);
            // Also set address if we have one
            if (currentAddress != null && provider instanceof NativeToolManager) {
                ((NativeToolManager) provider).setAddress(currentAddress);
            }
        }
        Msg.debug(this, "Updated program context for " + providers.size() + " providers");
    }

    /**
     * Set the current address context for tools that need it.
     * @param address Current cursor address in Ghidra
     */
    public void setAddress(Address address) {
        this.currentAddress = address;
        for (ToolProvider provider : providers) {
            if (provider instanceof NativeToolManager) {
                ((NativeToolManager) provider).setAddress(address);
            }
        }
        Msg.debug(this, "Updated address context: " + (address != null ? address.toString() : "null"));
    }

    /**
     * Set both program and address context.
     * @param program Current Ghidra program
     * @param address Current cursor address
     */
    public void setFullContext(Program program, Address address) {
        this.currentProgram = program;
        this.currentAddress = address;
        for (ToolProvider provider : providers) {
            provider.setContext(program);
            if (provider instanceof NativeToolManager) {
                ((NativeToolManager) provider).setFullContext(program, address);
            }
        }
        Msg.debug(this, "Updated full context for " + providers.size() + " providers");
    }

    /**
     * Get the current program context.
     * @return Current program or null
     */
    public Program getCurrentProgram() {
        return currentProgram;
    }

    /**
     * Get the current address context.
     * @return Current address or null
     */
    public Address getCurrentAddress() {
        return currentAddress;
    }

    /**
     * Get tool count summary.
     * @return Summary string
     */
    public String getSummary() {
        StringBuilder sb = new StringBuilder();
        sb.append("ToolRegistry: ").append(getAllTools().size()).append(" total tools\n");
        for (ToolProvider provider : providers) {
            sb.append("  - ").append(provider.getProviderName())
              .append(": ").append(provider.getTools().size()).append(" tools\n");
        }
        return sb.toString();
    }

    /**
     * Get all tools as function definitions for LLM function calling.
     * This converts Tool objects to the Map format expected by LLM providers.
     * Deduplicates tools by name (first registration wins).
     * @return List of function definitions
     */
    public List<Map<String, Object>> getToolsAsFunction() {
        // Deduplicate by tool name - first registration wins
        Map<String, Tool> uniqueTools = new java.util.LinkedHashMap<>();
        for (Tool tool : getAllTools()) {
            if (!uniqueTools.containsKey(tool.getName())) {
                uniqueTools.put(tool.getName(), tool);
            } else {
                Msg.debug(this, "Skipping duplicate tool: " + tool.getName() +
                        " (already registered from another provider)");
            }
        }

        return uniqueTools.values().stream()
                .map(this::toolToFunctionSchema)
                .collect(Collectors.toList());
    }

    /**
     * Convert a Tool to function calling schema format.
     */
    private Map<String, Object> toolToFunctionSchema(Tool tool) {
        Map<String, Object> function = new HashMap<>();
        function.put("type", "function");

        Map<String, Object> functionDef = new HashMap<>();
        functionDef.put("name", tool.getName());
        functionDef.put("description", tool.getDescription());

        // Convert JsonObject to Map for parameters
        JsonObject inputSchema = tool.getInputSchema();
        if (inputSchema != null) {
            functionDef.put("parameters", jsonObjectToMap(inputSchema));
        } else {
            // Default empty parameters
            Map<String, Object> emptyParams = new HashMap<>();
            emptyParams.put("type", "object");
            emptyParams.put("properties", new HashMap<>());
            functionDef.put("parameters", emptyParams);
        }

        function.put("function", functionDef);
        return function;
    }

    /**
     * Convert JsonObject to Map for function schema.
     */
    private Map<String, Object> jsonObjectToMap(JsonObject json) {
        Map<String, Object> map = new HashMap<>();
        for (String key : json.keySet()) {
            map.put(key, jsonElementToObject(json.get(key)));
        }
        return map;
    }

    /**
     * Convert JsonElement to appropriate Java object.
     */
    private Object jsonElementToObject(com.google.gson.JsonElement element) {
        if (element == null || element.isJsonNull()) {
            return null;
        } else if (element.isJsonPrimitive()) {
            com.google.gson.JsonPrimitive primitive = element.getAsJsonPrimitive();
            if (primitive.isBoolean()) {
                return primitive.getAsBoolean();
            } else if (primitive.isNumber()) {
                return primitive.getAsNumber();
            } else {
                return primitive.getAsString();
            }
        } else if (element.isJsonArray()) {
            List<Object> list = new ArrayList<>();
            for (com.google.gson.JsonElement e : element.getAsJsonArray()) {
                list.add(jsonElementToObject(e));
            }
            return list;
        } else if (element.isJsonObject()) {
            return jsonObjectToMap(element.getAsJsonObject());
        }
        return element.toString();
    }
}
