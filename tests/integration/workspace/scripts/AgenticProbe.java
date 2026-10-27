// Test-only headless adapter: real production ReActOrchestrator, LLM provider,
// ConversationalToolHandler and ToolRegistry. No direct MCP calls.
import com.google.gson.*;
import ghidra.app.script.GhidraScript;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.agent.react.*;
import ghidrassist.apiprovider.*;
import ghidrassist.tools.api.*;
import ghidrassist.tools.approval.ToolApprovalService;
import ghidrassist.tools.registry.ToolRegistry;
import ghidrassist.tools.registry.ToolExecutionPolicy;
import java.lang.reflect.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.io.IOException;
import okhttp3.Interceptor;
import okhttp3.Response;
import okhttp3.ResponseBody;
import okio.Buffer;
import okio.BufferedSource;
import okio.ForwardingSource;
import okio.Okio;
import okio.Source;

public class AgenticProbe extends GhidraScript {
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();
    private final JsonArray events = new JsonArray();
    private String caseId;
    private String runId;

    /** Passive OAuth response telemetry. It records timing/status/usage only, never headers or bodies. */
    private static final class OAuthTelemetry implements Interceptor {
        private final Gson gson = new Gson();
        private final JsonArray calls = new JsonArray();
        private long sequence;

        private JsonElement diagnosticCopy(JsonElement element) {
            if (element == null || element.isJsonNull()) return JsonNull.INSTANCE;
            if (element.isJsonObject()) {
                JsonObject clean = new JsonObject();
                JsonElement itemType = element.getAsJsonObject().get("type");
                if (itemType != null && itemType.isJsonPrimitive() && "reasoning".equals(itemType.getAsString())) {
                    clean.addProperty("type", "reasoning");
                    clean.addProperty("content_omitted", true);
                    return clean;
                }
                for (var entry : element.getAsJsonObject().entrySet()) {
                    String key = entry.getKey().toLowerCase(Locale.ROOT);
                    if (List.of("id", "session_id", "account_id", "call_id", "correlation_id", "request_id", "access_token", "refresh_token", "id_token", "encrypted_content").contains(key) || key.contains("authorization")) continue;
                    clean.add(entry.getKey(), diagnosticCopy(entry.getValue()));
                }
                return clean;
            }
            if (element.isJsonArray()) {
                JsonArray clean = new JsonArray();
                for (JsonElement item : element.getAsJsonArray()) clean.add(diagnosticCopy(item));
                return clean;
            }
            if (element.getAsJsonPrimitive().isString()) return new JsonPrimitive(element.getAsString()
                .replaceAll("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", "[REDACTED_ID]")
                .replaceAll("(?i)(session(?:[_ -]?id)?\\s*[:=]\\s*)[^\\s,;]+", "$1[REDACTED]"));
            return element.deepCopy();
        }

        private synchronized JsonObject begin() {
            JsonObject call = new JsonObject();
            call.addProperty("sequence", ++sequence);
            call.addProperty("started_at", Instant.now().toString());
            call.addProperty("started_nanos", System.nanoTime());
            calls.add(call);
            return call;
        }

        private synchronized void finish(JsonObject call, String error) {
            if (call.has("finished_at")) return;
            call.addProperty("finished_at", Instant.now().toString());
            call.addProperty("duration_seconds", (System.nanoTime() - call.get("started_nanos").getAsLong()) / 1_000_000_000.0);
            call.remove("started_nanos");
            if (error != null) call.addProperty("transport_error_class", error);
        }

        private void observeLine(JsonObject call, String line) {
            String data = line.startsWith("data: ") ? line.substring(6).trim() : line.trim();
            if (data.isEmpty() || data.equals("[DONE]")) return;
            try {
                JsonObject event = JsonParser.parseString(data).getAsJsonObject();
                JsonObject response = event.has("response") && event.get("response").isJsonObject()
                    ? event.getAsJsonObject("response") : event;
                if (response.has("output")) call.add("model_output", diagnosticCopy(response.get("output")));
                JsonObject error = response.has("error") && response.get("error").isJsonObject()
                    ? response.getAsJsonObject("error") : null;
                if (error != null) {
                    JsonObject safeError = new JsonObject();
                    for (String key : List.of("type", "code", "param", "message"))
                        if (error.has(key) && error.get(key).isJsonPrimitive()) safeError.add(key, error.get(key).deepCopy());
                    call.add("api_error", safeError);
                }
                if (response.has("detail") && response.get("detail").isJsonPrimitive())
                    call.add("api_error_detail", diagnosticCopy(response.get("detail")));
                if (response.has("message") && response.get("message").isJsonPrimitive())
                    call.add("api_error_message", diagnosticCopy(response.get("message")));
                if (response.has("code") && response.get("code").isJsonPrimitive())
                    call.add("api_error_code", diagnosticCopy(response.get("code")));
                if (!response.has("usage") || !response.get("usage").isJsonObject()) return;
                JsonObject usage = response.getAsJsonObject("usage");
                for (String key : List.of("input_tokens", "output_tokens", "total_tokens"))
                    if (usage.has(key) && usage.get(key).isJsonPrimitive()) call.add(key, usage.get(key).deepCopy());
                call.addProperty("usage_reported", true);
            } catch (RuntimeException ignored) { /* Ignore non-JSON SSE payloads without retaining them. */ }
        }

        @Override public Response intercept(Chain chain) throws IOException {
            JsonObject call = begin();
            try {
                JsonObject request = new JsonObject();
                request.addProperty("method", chain.request().method());
                request.addProperty("endpoint", chain.request().url().scheme() + "://" + chain.request().url().host() + chain.request().url().encodedPath());
                JsonObject headers = new JsonObject();
                for (String header : List.of("Content-Type", "accept", "originator", "OpenAI-Beta"))
                    if (chain.request().header(header) != null) headers.addProperty(header, chain.request().header(header));
                request.add("headers", headers);
                if (chain.request().body() != null) {
                    Buffer buffer = new Buffer(); chain.request().body().writeTo(buffer);
                    request.add("payload", diagnosticCopy(JsonParser.parseString(buffer.readUtf8())));
                }
                call.add("request", request);
                Response response = chain.proceed(chain.request());
                call.addProperty("http_status", response.code());
                call.addProperty("headers_duration_seconds", (System.nanoTime() - call.get("started_nanos").getAsLong()) / 1_000_000_000.0);
                call.addProperty("content_type", response.header("Content-Type"));
                ResponseBody body = response.body();
                if (body == null) { finish(call, null); return response; }
                BufferedSource wrapped = Okio.buffer(new ForwardingSource(body.source()) {
                    private final Buffer captured = new Buffer();
                    private boolean done;
                    private void complete(String error) { if (!done) { done = true; finish(call, error); } }
                    @Override public long read(Buffer sink, long byteCount) throws IOException {
                        try {
                            long read = super.read(sink, byteCount);
                            if (read > 0) {
                                Buffer copy = new Buffer();
                                sink.copyTo(copy, sink.size() - read, read);
                                captured.writeAll(copy);
                                long newline;
                                while ((newline = captured.indexOf((byte)'\n')) >= 0) {
                                    String line = captured.readUtf8(newline);
                                    captured.readByte();
                                    observeLine(call, line);
                                }
                            } else if (read == -1) {
                                if (captured.size() > 0) observeLine(call, captured.readUtf8());
                                complete(null);
                            }
                            return read;
                        } catch (IOException error) { complete(error.getClass().getSimpleName()); throw error; }
                    }
                    @Override public void close() throws IOException {
                        try { super.close(); } finally { complete(null); }
                    }
                });
                ResponseBody observed = new ResponseBody() {
                    @Override public okhttp3.MediaType contentType() { return body.contentType(); }
                    @Override public long contentLength() { return body.contentLength(); }
                    @Override public BufferedSource source() { return wrapped; }
                };
                return response.newBuilder().body(observed).build();
            } catch (IOException error) {
                finish(call, error.getClass().getSimpleName());
                throw error;
            }
        }

        synchronized JsonArray snapshot() { return calls.deepCopy(); }
        void awaitCompletion() throws InterruptedException {
            for (int attempt = 0; attempt < 100; attempt++) {
                boolean complete = true;
                for (JsonElement call : snapshot()) if (!call.getAsJsonObject().has("finished_at")) complete = false;
                if (complete) return;
                Thread.sleep(20);
            }
        }
    }

    private synchronized void event(String kind, String correlation, Tool tool, JsonObject args,
            String content, Boolean success) {
        JsonObject value = new JsonObject();
        value.addProperty("time", Instant.now().toString());
        value.addProperty("run_id", runId);
        value.addProperty("case_id", caseId);
        value.addProperty("kind", kind);
        value.addProperty("sequence", events.size() + 1);
        if (correlation != null) value.addProperty("correlation_id", correlation);
        if (tool != null) value.addProperty("tool", tool.getName());
        if (args != null) value.add("arguments", args.deepCopy());
        if (content != null) value.addProperty("content", content);
        if (success != null) value.addProperty("success", success);
        events.add(value);
    }

    private static GhidrAssistPlugin headlessPluginShell() throws Exception {
        // PluginTool construction requires a GUI. Only getCurrentProgram() is read
        // during the orchestrator's constructor; context is supplied afterwards via
        // its existing public updateProgramContext(). Never use this shell for UI.
        Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
        Field field = unsafeClass.getDeclaredField("theUnsafe");
        field.setAccessible(true);
        Object unsafe = field.get(null);
        return (GhidrAssistPlugin) unsafeClass.getMethod("allocateInstance", Class.class)
            .invoke(unsafe, GhidrAssistPlugin.class);
    }

    private void redactConfiguredSecrets(JsonElement value, APIProviderConfig config) {
        if (config == null || config.getKey() == null) return;
        try {
            JsonElement credentials = JsonParser.parseString(config.getKey());
            Set<String> secrets = new HashSet<>();
            collectCredentialValues(credentials, secrets);
            redactTree(value, secrets);
        } catch (RuntimeException ignored) { /* The provider key is never copied into output. */ }
    }

    private void collectCredentialValues(JsonElement value, Set<String> secrets) {
        if (value == null || value.isJsonNull()) return;
        if (value.isJsonObject()) {
            for (var entry : value.getAsJsonObject().entrySet()) {
                String key = entry.getKey().toLowerCase(Locale.ROOT);
                if (key.contains("token") || key.contains("secret") || key.contains("authorization")) {
                    if (entry.getValue().isJsonPrimitive()) secrets.add(entry.getValue().getAsString());
                } else collectCredentialValues(entry.getValue(), secrets);
            }
        } else if (value.isJsonArray()) {
            for (JsonElement item : value.getAsJsonArray()) collectCredentialValues(item, secrets);
        }
    }

    private JsonElement redactTree(JsonElement value, Set<String> secrets) {
        if (value == null || value.isJsonNull()) return value;
        if (value.isJsonObject()) {
            for (var entry : value.getAsJsonObject().entrySet())
                value.getAsJsonObject().add(entry.getKey(), redactTree(entry.getValue(), secrets));
        } else if (value.isJsonArray()) {
            JsonArray array = value.getAsJsonArray();
            for (int i = 0; i < array.size(); i++) array.set(i, redactTree(array.get(i), secrets));
        } else if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
            String text = value.getAsString();
            for (String secret : secrets) if (secret != null && secret.length() > 8) text = text.replace(secret, "[REDACTED]");
            text = text.replaceAll("(?i)(Bearer\\s+)[A-Za-z0-9._~+/-]+=*", "$1[REDACTED]");
            return new com.google.gson.JsonPrimitive(text);
        }
        return value;
    }

    private void closeLocalTransport(ReActOrchestrator orchestrator) throws Exception {
        Field llm = ReActOrchestrator.class.getDeclaredField("llmApi");
        llm.setAccessible(true);
        Object api = llm.get(orchestrator);
        Field apiClient = api.getClass().getDeclaredField("apiClient");
        apiClient.setAccessible(true);
        ghidrassist.core.LlmApiClient facade = (ghidrassist.core.LlmApiClient) apiClient.get(api);
        Field clientField = APIProvider.class.getDeclaredField("client");
        clientField.setAccessible(true);
        okhttp3.OkHttpClient client = (okhttp3.OkHttpClient) clientField.get(facade.getProvider());
        client.dispatcher().executorService().shutdown();
        client.connectionPool().evictAll();
    }

    // Observe *returned* production ToolResult errors too: the existing observer
    // does not emit a failure callback for suppressed duplicate reads. The only
    // overridden method delegates all decisions/execution unchanged to super.
    private class RecordingToolRegistry extends ToolRegistry {
        @Override public CompletableFuture<ToolResult> execute(String name, JsonObject args) {
            Tool tool = getTool(name);
            return super.execute(name, args).thenApply(result -> {
                event("dispatcher_result", null, tool, args, result.getContentOrError(), result.isSuccess());
                if (result.isError())
                    event("controller_rejection", null, tool, args, result.getContentOrError(), false);
                return result;
            });
        }
    }

    private class FixtureProvider implements ToolProvider {
        final Map<String, Integer> executed = new LinkedHashMap<>();
        final List<Tool> tools = new ArrayList<>();
        FixtureProvider(boolean wireSafe) {
            for (String name : List.of("get_regression_fact", "get_regression_other", "get_task_status", "fixture.get_task_status", "update_regression_record", "get_regression_error")) {
                if (wireSafe && !name.matches("[A-Za-z0-9_-]+")) continue;
                tools.add(new Tool() {
                    public String getName() { return name; }
                    public String getDescription() { return "Deterministic regression fixture: " + name; }
                    public String getSource() { return "regression-fixture"; }
                    public JsonObject getInputSchema() {
                        return JsonParser.parseString("{\"type\":\"object\",\"properties\":{\"key\":{\"type\":\"string\"},\"task_id\":{\"type\":\"string\"}}}").getAsJsonObject();
                    }
                });
            }
        }
        public String getProviderName() { return "regression-fixture"; }
        public List<Tool> getTools() { return tools; }
        public boolean handlesTool(String name) { return tools.stream().anyMatch(t -> t.getName().equals(name)); }
        public void setContext(Program program) { }
        public synchronized CompletableFuture<ToolResult> executeTool(String name, JsonObject args) {
            int count = executed.merge(name, 1, Integer::sum);
            if (name.equals("get_regression_error")) {
                String kind = args.get("key").getAsString();
                if (kind.equals("throw")) throw new IllegalStateException("fixture provider exploded");
                if (kind.equals("future")) return CompletableFuture.failedFuture(new IllegalStateException("fixture future failed"));
                return CompletableFuture.completedFuture(ToolResult.error("fixture provider rejected"));
            }
            Tool tool = tools.stream().filter(t -> t.getName().equals(name)).findFirst().get();
            String output = (name.equals("get_task_status") || name.endsWith(".get_task_status"))
                ? "task_id=task-1 status=" + (count == 1 ? "PENDING" : "COMPLETED")
                : name.equals("get_regression_fact") ? "REGRESSION_FACT=42 key=" + args
                : name.equals("get_regression_other") ? "REGRESSION_OTHER=17 key=" + args
                : "UPDATED_FIXTURE_ONLY=true";
            event("provider_execution", null, tool, args, output, true);
            return CompletableFuture.completedFuture(ToolResult.success(output));
        }
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        // endpoint, scenarios JSON, output JSON, index copy, catalog copy, run id
        String endpoint = args[0];
        APIProviderConfig realConfig = args.length > 6 ? new Gson().fromJson(Files.readString(Path.of(args[6])), APIProviderConfig.class) : null;
        if (realConfig != null) realConfig.normalizeLegacyDefaults();
        JsonArray scenarios = JsonParser.parseString(Files.readString(Path.of(args[1]))).getAsJsonArray();
        Path output = Path.of(args[2]);
        Preferences.setProperty("GhidrAssist.LuceneIndexPath", args[3]);
        Preferences.setProperty("GhidrAssist.RAGLibraries.v1", Files.readString(Path.of(args[4])));
        Preferences.store();
        runId = args[5];
        JsonObject results = new JsonObject();
        results.addProperty("run_id", runId);
        results.addProperty("orchestrator_class", ReActOrchestrator.class.getName());
        results.addProperty("registry_class", ToolRegistry.class.getName());
        results.addProperty("registry_adapter", "RecordingToolRegistry.execute delegates unchanged to super.execute and records returned ToolResult");
        results.addProperty("llm_provider", realConfig == null ? OpenAIPlatformApiProvider.class.getName() : realConfig.getType().toString());
        results.addProperty("mcp_enabled", false);
        results.addProperty("real_llm", realConfig != null);
        if (realConfig != null) { results.addProperty("real_provider_type",realConfig.getType().toString()); results.addProperty("real_model",realConfig.getModel()); }
        results.addProperty("project", currentProgram.getDomainFile().getProjectLocator().toString());
        results.addProperty("headless_plugin_adapter", "Unsafe shell; program supplied through updateProgramContext; no PluginTool/UI");
        JsonObject cases = new JsonObject();
        results.add("cases", cases);
        results.add("execution_events", events);
        for (JsonElement element : scenarios) {
            JsonObject scenario = element.getAsJsonObject();
            caseId = scenario.get("id").getAsString();
            JsonObject value = new JsonObject();
            value.addProperty("prompt", scenario.get("prompt").getAsString());
            value.addProperty("started_at", Instant.now().toString());
            cases.add(caseId, value);
            ReActOrchestrator orchestrator = null;
            String harnessStage = "provider_setup";
            try {
                APIProviderConfig cfg = new APIProviderConfig("RegressionLocal", APIProvider.ProviderType.OPENAI_PLATFORM_API,
                    caseId, 4096, endpoint, "local-regression-key", false, true, 15);
                if (realConfig != null) {
                    cfg = new Gson().fromJson(new Gson().toJson(realConfig), APIProviderConfig.class);
                    if (!"DIRECT".equalsIgnoreCase(endpoint)) cfg.setUrl(endpoint);
                }
                orchestrator = new ReActOrchestrator(cfg, headlessPluginShell(), realConfig == null ? 1 : 3, 50000, 4, false);
                OAuthTelemetry telemetry = new OAuthTelemetry();
                if (realConfig != null && realConfig.getType() == APIProvider.ProviderType.OPENAI_OAUTH) {
                    harnessStage = "oauth_telemetry_provider_lookup";
                    Field llmField = ReActOrchestrator.class.getDeclaredField("llmApi");
                    llmField.setAccessible(true);
                    Object llm = llmField.get(orchestrator);
                    Field facadeField = Class.forName("ghidrassist.LlmApi").getDeclaredField("apiClient");
                    facadeField.setAccessible(true);
                    Object facade = facadeField.get(llm);
                    APIProvider providerInstance = ((ghidrassist.core.LlmApiClient)facade).getProvider();
                    harnessStage = "oauth_telemetry_client_lookup";
                    Field clientField = APIProvider.class.getDeclaredField("client");
                    clientField.setAccessible(true);
                    okhttp3.OkHttpClient existing = (okhttp3.OkHttpClient)clientField.get(providerInstance);
                    harnessStage = "oauth_telemetry_interceptor_install";
                    // Application interceptor sees decompressed bodies; network interception sees gzip bytes.
                    clientField.set(providerInstance, existing.newBuilder().addInterceptor(telemetry).build());
                    if (scenario.has("reasoning")) providerInstance.setReasoningConfig(ReasoningConfig.fromString(scenario.get("reasoning").getAsString()));
                }
                orchestrator.updateProgramContext(currentProgram);
                orchestrator.setActiveSessionId(42);
                orchestrator.setProgramHashSupplier(() -> currentProgram.getExecutableSHA256());
                Field registryField = ReActOrchestrator.class.getDeclaredField("toolRegistry");
                registryField.setAccessible(true);
                ToolRegistry initialRegistry = (ToolRegistry) registryField.get(orchestrator);
                ToolRegistry registry = new RecordingToolRegistry();
                for (ToolProvider productionProvider : initialRegistry.getProviders())
                    registry.registerProvider(productionProvider);
                registryField.set(orchestrator, registry);
                orchestrator.updateProgramContext(currentProgram);
                orchestrator.setActiveSessionId(42);
                orchestrator.setProgramHashSupplier(() -> currentProgram.getExecutableSHA256());
                FixtureProvider provider = new FixtureProvider(realConfig != null && (!scenario.has("wire_safe_tools") || scenario.get("wire_safe_tools").getAsBoolean()));
                registry.registerProvider(provider);
                orchestrator.setToolExecutionObserver(new ToolExecutionObserver() {
                    public void onToolCallRequested(int s, String h, String c, Tool t, JsonObject a) { event("registry_requested", c, t, a, null, null); }
                    public void onToolCallStarted(int s, String h, String c, Tool t, JsonObject a) { event("execution_started", c, t, a, null, null); }
                    public void onToolCallCompleted(int s, String h, String c, Tool t, JsonObject a, ToolResult r) {
                        event("tool_response", c, t, a, r.getContentOrError(), r.isSuccess());
                    }
                    public void onToolCallFailed(int s, String h, String c, Tool t, JsonObject a, String error) {
                        event("registry_rejected_or_failed", c, t, a, error, false);
                    }
                });
                orchestrator.setToolApprovalService(new ToolApprovalService(null, null) {
                    @Override public CompletableFuture<ApprovalOutcome> requestApproval(int session, String hash,
                            String correlation, Tool tool, JsonObject arguments) {
                        if (tool.getName().equals("update_regression_record"))
                            return CompletableFuture.completedFuture(ApprovalOutcome.denied("regression deny"));
                        return CompletableFuture.completedFuture(ApprovalOutcome.approved("regression allow"));
                    }
                });
                CountDownLatch handlerFinished = new CountDownLatch(1);
                ReActProgressHandler handler = new ReActProgressHandler() {
                    public void onStart(String objective) { event("analysis_started", null, null, null, objective, null); }
                    public void onThought(String thought, int iteration) { }
                    public void onAction(String name, JsonObject arguments) {
                        if (realConfig != null) event("model_proposal", null, registry.getTool(name), arguments, null, null);
                    }
                    public void onObservation(String name, String response) { }
                    public void onFinding(String finding) { }
                    public void onTodosUpdated(String formatted, List<TodoListManager.Todo> todos, String compact) {
                        event("todo_state", null, null, null,
                            todos.stream().map(todo -> todo.getStatus().toString()).collect(java.util.stream.Collectors.joining(",")), null);
                    }
                    public void onSynthesisChunk(String content) { event("delivered_synthesis_chunk", null, null, null, content, null); }
                    public void onComplete(ReActResult result) { event("final_claim", null, null, null, result.getAnswer(), null); handlerFinished.countDown(); }
                    public void onError(Throwable error) {
                        if (realConfig != null) {
                            Throwable cause = error;
                            while (cause != null) {
                                if (cause instanceof ghidrassist.apiprovider.exceptions.APIProviderException apiError) {
                                    value.addProperty("error_http_status", apiError.getHttpStatusCode());
                                    value.addProperty("error_api_code", apiError.getApiErrorCode());
                                    value.addProperty("error_category", apiError.getCategory().name());
                                    value.addProperty("safe_provider_message", apiError.getMessage());
                                    break;
                                }
                                cause = cause.getCause();
                            }
                        }
                        event("analysis_error", null, null, null,
                            realConfig == null ? error.toString() : error.getClass().getSimpleName(), false);
                        handlerFinished.countDown();
                    }
                    public boolean shouldContinue() { return !monitor.isCancelled(); }
                };
                ToolExecutionPolicy policy = ToolExecutionPolicy.unrestricted();
                if (scenario.has("policy")) {
                    JsonObject specification = scenario.getAsJsonObject("policy");
                    Set<String> allowed = null;
                    if (specification.has("allowed_tools")) {
                        allowed = new LinkedHashSet<>();
                        for (JsonElement name : specification.getAsJsonArray("allowed_tools")) allowed.add(name.getAsString());
                    }
                    Map<String,Integer> limits = new LinkedHashMap<>();
                    if (specification.has("per_tool_limits"))
                        for (var limit : specification.getAsJsonObject("per_tool_limits").entrySet()) limits.put(limit.getKey(), limit.getValue().getAsInt());
                    Integer total = specification.has("total_calls") ? specification.get("total_calls").getAsInt() : null;
                    boolean readOnly = specification.has("read_only") && specification.get("read_only").getAsBoolean();
                    policy = new ToolExecutionPolicy(allowed, limits, total, readOnly);
                    value.add("policy", specification.deepCopy());
                }
                String prompt = scenario.get("prompt").getAsString();
                harnessStage = "react_orchestration";
                String context = "Deterministic integration fixture. Use only returned tool evidence.";
                String plan = "1. Execute the requested investigation using the specified tools.";
                CompletableFuture<ReActResult> investigation = scenario.has("policy")
                    ? orchestrator.analyze(prompt, context, "regression-" + caseId, handler, plan, policy)
                    : orchestrator.analyze(prompt, context, "regression-" + caseId, handler, plan);
                value.addProperty("policy_api", scenario.has("policy") ? "explicit" : "legacy-unrestricted");
                ReActResult result = investigation.get(realConfig == null ? 75 : 240, TimeUnit.SECONDS);
                harnessStage = "journal_collection";
                if (!handlerFinished.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("Final handler did not complete");
                value.addProperty("status", result.getStatus().toString());
                value.addProperty("answer", result.getAnswer());
                value.addProperty("error", result.getErrorMessage());
                value.addProperty("actual_dispatcher_count", result.getToolCallCount());
                value.addProperty("duration_seconds", result.getDuration().toMillis() / 1000.0);
                if (realConfig != null && realConfig.getType() == APIProvider.ProviderType.OPENAI_OAUTH) {
                    telemetry.awaitCompletion();
                    value.addProperty("provider_http_invocations", telemetry.snapshot().size());
                    value.add("provider_http_calls", telemetry.snapshot());
                    JsonObject aggregate = new JsonObject();
                    long inputTokens = 0, outputTokens = 0, totalTokens = 0; boolean reported = false;
                    for (JsonElement call : telemetry.snapshot()) {
                        JsonObject item = call.getAsJsonObject();
                        if (!item.has("usage_reported")) continue;
                        reported = true;
                        if (item.has("input_tokens")) inputTokens += item.get("input_tokens").getAsLong();
                        if (item.has("output_tokens")) outputTokens += item.get("output_tokens").getAsLong();
                        if (item.has("total_tokens")) totalTokens += item.get("total_tokens").getAsLong();
                    }
                    aggregate.addProperty("reported", reported);
                    if (reported) { aggregate.addProperty("input_tokens", inputTokens); aggregate.addProperty("output_tokens", outputTokens); aggregate.addProperty("total_tokens", totalTokens); }
                    value.add("token_usage", aggregate);
                }
                value.add("provider_counts", gson.toJsonTree(provider.executed));
                value.addProperty("retained_evidence", registry.getRecentToolEvidence());
                JsonArray journal = new JsonArray();
                for (var entry : registry.getExecutionJournal().snapshot()) {
                    JsonObject fact = new JsonObject();
                    fact.addProperty("call_id", entry.callId()); fact.addProperty("tool", entry.toolName());
                    fact.addProperty("state", entry.state().toString()); fact.addProperty("executed", entry.executed());
                    fact.addProperty("detail", entry.detail()); fact.addProperty("arguments",entry.arguments()); journal.add(fact);
                }
                value.add("execution_journal", journal);
            } catch (Exception error) {
                value.addProperty("harness_error", realConfig == null ? error.toString() : error.getClass().getSimpleName());
                if (realConfig != null) {
                    value.addProperty("harness_stage", harnessStage);
                    if (error instanceof ClassCastException && error.getMessage() != null)
                        value.addProperty("safe_harness_detail", error.getMessage());
                }
                if (orchestrator != null) orchestrator.cancel();
                printerr("AGENTIC_CASE_ERROR " + caseId + " " + (realConfig == null ? error.toString() : error.getClass().getSimpleName()));
                if (realConfig == null) error.printStackTrace();
            }
            if (orchestrator != null) closeLocalTransport(orchestrator);
            value.addProperty("finished_at", Instant.now().toString());
            redactConfiguredSecrets(results, realConfig);
            // Authentication/session/call identifiers are not needed for the evidence contract.
            JsonElement safeOutput = realConfig == null ? results : new OAuthTelemetry().diagnosticCopy(results);
            synchronized (this) { Files.writeString(output, gson.toJson(safeOutput) + "\n"); }
            println("AGENTIC_CASE_COMPLETED=" + caseId + " " + value.get("status"));
        }
    }
}
