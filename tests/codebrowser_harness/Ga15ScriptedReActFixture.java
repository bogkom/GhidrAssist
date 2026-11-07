// Java-only CI fixture. Not packaged into the GhidrAssist extension.
// This drives the ACTUAL ReActOrchestrator and the ACTUAL Ghidra native
// read-only tool dispatcher. No model, OAuth, network provider or Apply.
package ghidrassist.agent.react;

import com.google.gson.JsonObject;
import ghidrassist.GhidrAssistPlugin;
import ghidrassist.LlmApi;
import ghidrassist.apiprovider.APIProvider;
import ghidrassist.apiprovider.APIProviderConfig;
import ghidrassist.apiprovider.ToolChoiceMode;
import ghidrassist.tools.api.ToolResult;
import ghidrassist.tools.registry.ToolExecutionPolicy;
import ghidrassist.tools.registry.ToolRegistry;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Real ReAct state machine; deterministic scripted LLM adapter, CI ONLY. */
public final class Ga15ScriptedReActFixture {
    private Ga15ScriptedReActFixture() {}

    public static CompletableFuture<ReActResult> start(GhidrAssistPlugin plugin,
            Program program,Address site,Path evidence) throws Exception {
        return startScenario(plugin,program,site,evidence,"normal",null,null);
    }

    /**
     * Test-only handshakes for cancel and A→B→A; the extension never
     * packages this class or exposes it through AutomationServer.
     */
    public static CompletableFuture<ReActResult> startScenario(
            GhidrAssistPlugin plugin, Program program,Address site,
            Path evidence,String scenario,Runnable switchAway,
            Runnable switchBack) throws Exception {
        if(!java.util.Set.of("normal","cancel","switch").contains(scenario))
            throw new IllegalArgumentException("Unknown synthetic ReAct scenario");
        if("switch".equals(scenario) &&
                (switchAway==null || switchBack==null))
            throw new IllegalArgumentException("Missing CodeBrowser switch callbacks");
        if(plugin.getCurrentProgram()!=program || site==null ||
                !program.getMemory().contains(site))
            throw new IllegalStateException("Real CodeBrowser Program or Listing address absent");
        long originalRevision=program.getModificationNumber();
        APIProviderConfig cfg=new APIProviderConfig("GA15 CI scripted offline",
            APIProvider.ProviderType.OPENAI_PLATFORM_API,
            "no-network-model",128,"http://127.0.0.1:9",
            "not-a-secret-test-only",false);
        AtomicInteger lateThoughts=new AtomicInteger();
        AtomicReference<CompletableFuture<ReActResult>> currentRun=
            new AtomicReference<>();
        ScriptedLlm deterministic=new ScriptedLlm(cfg,plugin,evidence,
            site.toString(),lateThoughts);
        ReActOrchestrator react=new ReActOrchestrator(
            cfg,plugin,2,8000,1,false,deterministic);
        // No new product API just to set a CI cursor; use the actual
        // production ToolRegistry and Ghidra read-only provider.
        Field field=ReActOrchestrator.class.getDeclaredField("toolRegistry");
        field.setAccessible(true);
        ToolRegistry tools=(ToolRegistry)field.get(react);
        tools.setFullContext(program,site);
        if(tools.getTool("ga_get_current_address")==null)
            throw new IllegalStateException("Real Ghidra current-address tool missing");

        var handler=new ReActProgressHandler() {
            public void onStart(String objective) {}
            public void onThought(String text,int iteration) {
                CompletableFuture<ReActResult> active=currentRun.get();
                if(active!=null && active.isDone())
                    lateThoughts.incrementAndGet();
            }
            public void onAction(String toolName,JsonObject args) {}
            public void onObservation(String toolName,String result) {}
            public void onFinding(String fact) {}
            public void onComplete(ReActResult result) {}
            public void onError(Throwable error) {}
            public boolean shouldContinue() { return true; }
        };
        ToolExecutionPolicy policy=new ToolExecutionPolicy(
            Set.of("ga_get_current_address"),Map.of("ga_get_current_address",1),
            1,true);
        CompletableFuture<ReActResult> future=react.analyze(
            "Read only one static synthetic CodeBrowser Listing address",
            "Evidence is static; no runtime execution of MCU hardware",
            "ga15-ci-fixture",handler,
            "- [ ] Read the current CodeBrowser Listing address",policy);
        currentRun.set(future);
        future.whenComplete((result,failure)->{
            JsonObject receipt=new JsonObject();
            receipt.addProperty("schema",1);
            receipt.addProperty("synthetic_only",true);
            receipt.addProperty("real_react_orchestrator",true);
            receipt.addProperty("scripted_model_no_network",true);
            receipt.addProperty("real_ghidra_tool", "ga_get_current_address");
            receipt.addProperty("source_program",program.getName());
            receipt.addProperty("source_revision",originalRevision);
            receipt.addProperty("revision_unchanged",
                program.getModificationNumber()==originalRevision);
            receipt.addProperty("status",result==null ? "ERROR" :
                result.getStatus().name());
            receipt.addProperty("tool_calls",result==null ? 0 :
                result.getToolCallCount());
            receipt.addProperty("findings",result==null ? 0 :
                result.getFindings().size());
            receipt.addProperty("tool_succeeded",deterministic.toolSucceeded);
            receipt.addProperty("late_ui_updates_at_completion",lateThoughts.get());
            receipt.addProperty("scenario",scenario);
            if(failure!=null)receipt.addProperty("error",failure.toString());
            else if(result!=null && result.getErrorMessage()!=null)
                receipt.addProperty("error",result.getErrorMessage());
            try {
                Files.writeString(evidence.resolve("ga15-react-result.json"),
                    receipt.toString(),StandardCharsets.UTF_8);
            } catch(Exception writeFailure) {
                throw new IllegalStateException("Failed to write synthetic ReAct result",writeFailure);
            }
        });
        if(!"normal".equals(scenario)) {
            CompletableFuture.runAsync(()->{
                try {
                    waitFor(evidence.resolve("ga15-react-action"),60);
                    String command=Files.readString(
                        evidence.resolve("ga15-react-action")).trim();
                    if(!scenario.equals(command))
                        throw new IllegalStateException(
                            "Unexpected external ReAct action: "+command);
                    if("cancel".equals(scenario))react.cancel();
                    else switchAway.run();
                    Files.writeString(evidence.resolve("ga15-react-action-done"),
                        scenario,StandardCharsets.UTF_8);
                    if("switch".equals(scenario)) {
                        waitFor(evidence.resolve("ga15-react-return"),60);
                        switchBack.run();
                        Files.writeString(evidence.resolve("ga15-react-returned"),
                            "source-reopened",StandardCharsets.UTF_8);
                    }
                } catch(Exception failure) {
                    try {
                        Files.writeString(evidence.resolve("ga15-react-action-error"),
                            failure.toString(),StandardCharsets.UTF_8);
                    } catch(Exception ignored) {}
                }
            });
        }
        if("normal".equals(scenario)) {
            // A second, independent CI controller now prepares a local
            // review-only draft from the completed real ReAct evidence. Check
            // it inside the SAME genuine Ghidra Program/registry generation.
            CompletableFuture.runAsync(()->{
                JsonObject proof=new JsonObject();
                proof.addProperty("schema",1);
                proof.addProperty("synthetic_only",true);
                try {
                    waitFor(evidence.resolve("ga15-review-draft-ready"),80);
                    var draft=AgenticReviewDraft.load(
                        evidence.resolve("ga15-new-independent-review.json"),
                        program,AgenticEvidenceRegistry.shared());
                    String staged=draft.toReviewQuery();
                    if(!staged.startsWith("New independent static MMIO reference audit") ||
                            !staged.contains("Untrusted historical observations") ||
                            !staged.contains("Propose a NEW investigation plan"))
                        throw new IllegalStateException("Imported review did not stage safe new query");
                    proof.addProperty("live_program_draft_import_pass",true);
                    proof.addProperty("read_only_historical_data_only",true);
                    try {
                        AgenticReviewDraft.load(
                            evidence.resolve("ga15-forged-independent-review.json"),
                            program,AgenticEvidenceRegistry.shared());
                        throw new IllegalStateException("Rehashed injected review passed");
                    } catch(IllegalArgumentException expected) {
                        proof.addProperty("forged_draft_refused",true);
                    }
                } catch(Exception failure) {
                    proof.addProperty("error",failure.toString());
                }
                try {
                    Files.writeString(evidence.resolve("ga15-review-draft-validation.json"),
                        proof.toString(),StandardCharsets.UTF_8);
                } catch(Exception fail) {
                    throw new IllegalStateException("Failed to emit review validation",fail);
                }
            });
        }
        return future;
    }

    private static void waitFor(Path marker,int seconds)
            throws Exception {
        long end=System.nanoTime()+TimeUnit.SECONDS.toNanos(seconds);
        while(!Files.isRegularFile(marker)) {
            if(System.nanoTime()>=end)
                throw new IllegalStateException("Timed out: "+marker.getFileName());
            Thread.sleep(40);
        }
    }

    /** Scripted callbacks are constrained to an actual read-only tool result. */
    private static final class ScriptedLlm extends LlmApi {
        private final Path output;
        private final String expectedAddress;
        private volatile boolean toolSucceeded;
        private final AtomicInteger functionRounds=new AtomicInteger();
        private final AtomicInteger lateThoughts;
        private final AtomicInteger cancellationRequests=new AtomicInteger();
        private final AtomicInteger synchronousCancelErrors=new AtomicInteger();
        private volatile LlmResponseHandler activeCallback;

        ScriptedLlm(APIProviderConfig config,GhidrAssistPlugin plugin,
                Path output,String expectedAddress,AtomicInteger lateThoughts) {
            super(config,plugin);
            this.output=output;
            this.expectedAddress=expectedAddress.toLowerCase();
            this.lateThoughts=lateThoughts;
        }

        @Override
        public void sendConversationalToolRequest(String prompt,
                List<Map<String,Object>> functionSchemas,
                LlmResponseHandler handler,int maxToolRounds,
                ToolRegistry registry,ToolChoiceMode choice) {
            if(functionRounds.incrementAndGet()!=1 || maxToolRounds!=1 ||
                    !functionSchemas.stream().anyMatch(schema ->
                        schema.toString().contains("ga_get_current_address"))) {
                handler.onError(new AssertionError("Expected one real read-only Ghidra tool round"));
                return;
            }
            activeCallback=handler;
            handler.onStart();
            registry.execute("ga_get_current_address",new JsonObject())
                .whenComplete((result,error)->{
                    if(error!=null || result==null || !result.isSuccess() ||
                            result.getContent()==null ||
                            !result.getContent().toLowerCase().contains(expectedAddress)) {
                        handler.onError(new AssertionError(
                            "Actual Ghidra tool did not return selected Listing PC: "+
                            (error!=null ? error :
                                result==null ? "null" : result.getContentOrError())));
                        return;
                    }
                    toolSucceeded=true;
                    // Keep the REAL ReAct iteration RUNNING while an external
                    // process queries production loopback JSON-RPC/CLI. Only
                    // this test fixture's marker releases the scripted turn.
                    try {
                        Files.writeString(output.resolve("ga15-react-running"),
                            "real-tool-read-pending-scripted-model",StandardCharsets.UTF_8);
                    } catch(Exception failure) {
                        handler.onError(failure);
                        return;
                    }
                    CompletableFuture.runAsync(()->{
                        try {
                            long stop=System.nanoTime()+TimeUnit.SECONDS.toNanos(90);
                            while(!Files.isRegularFile(output.resolve("ga15-react-release"))) {
                                if(System.nanoTime()>stop)
                                    throw new IllegalStateException("Timed out waiting for external CLI probe");
                                Thread.sleep(50);
                            }
                            String answer="Static synthetic Ghidra Listing address observation: "+
                                result.getContent()+
                                "\nAn instruction at a PC is NOT proof it executed or an MCU IRQ was active.";
                            handler.onToolsExecuted(1);
                            handler.onUpdate(answer);
                            handler.onComplete(answer);
                        } catch(Exception failure) { handler.onError(failure); }
                        finally {
                            try {
                                JsonObject late=new JsonObject();
                                late.addProperty("late_ui_updates",lateThoughts.get());
                                late.addProperty("provider_cancel_calls",
                                    cancellationRequests.get());
                                late.addProperty("synchronous_cancel_error_callbacks",
                                    synchronousCancelErrors.get());
                                Files.writeString(output.resolve(
                                    "ga15-react-late-delivered"),
                                    late.toString(),StandardCharsets.UTF_8);
                            } catch(Exception markerError) {
                                // Controller will timeout if receipt is missing.
                            }
                        }
                    });
                });
        }

        @Override
        public void cancelCurrentRequest() {
            // An actual provider can call onError synchronously as soon as
            // it is cancelled. The ReAct result must already be terminal
            // CANCELLED before this error is delivered, never ERROR.
            cancellationRequests.incrementAndGet();
            LlmResponseHandler handler=activeCallback;
            if(handler!=null) {
                synchronousCancelErrors.incrementAndGet();
                handler.onError(new IllegalStateException(
                    "Expected synchronous cancellation error from scripted provider"));
            }
        }

        @Override
        public void sendRequestAsync(String prompt,LlmResponseHandler handler) {
            // Invoked only for final synthesis after the genuine ReAct
            // dispatcher has executed and journaled one read-only tool.
            handler.onStart();
            handler.onComplete("Synthetic static evidence: the native read-only "+
                "Ghidra Listing tool returned the PC; no execution or writes verified.");
        }
    }
}
