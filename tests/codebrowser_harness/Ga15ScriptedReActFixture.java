// Java-only CI fixture. Not packaged into the GhidrAssist extension.
// This drives the ACTUAL ReActOrchestrator and the ACTUAL Ghidra native
// read-only tool dispatcher. No model, OAuth, network provider or Apply.
package ghidrassist.agent.react;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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
                    StagedReview newReview=verifyActualGuiReviewStage(
                        plugin,program,draft,proof);
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
                    // First complete a separate report for the pre-approval
                    // state. The external CI controller must explicitly
                    // signal approval; before this marker NO fresh ReAct exists.
                    Files.writeString(evidence.resolve(
                        "ga15-review-draft-validation.json"),
                        proof.toString(),StandardCharsets.UTF_8);
                    runIndependentlyApprovedInvestigation(
                        plugin,program,site,evidence,newReview);
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

    /** Captured from actual, independent Query tab and freshly applied policy. */
    private record StagedReview(String query,int chatId,
            ToolExecutionPolicy policy,String previousRun) {}

    /** Test-only direct EDT staging in the real GhidrAssist Query tab. */
    private static StagedReview verifyActualGuiReviewStage(
            GhidrAssistPlugin plugin,Program program,AgenticReviewDraft draft,
            JsonObject proof) throws Exception {
        java.util.concurrent.atomic.AtomicReference<Throwable> failed=
            new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicReference<StagedReview> staged=
            new java.util.concurrent.atomic.AtomicReference<>();
        var previous=AgenticEvidenceRegistry.shared().page(
            program,program.getModificationNumber(),
            program.getExecutableSHA256(),0,1,null,null);
        if(!"SUCCESS".equals(previous.state()))
            throw new IllegalStateException("Cannot build follow-up from running evidence");
        javax.swing.SwingUtilities.invokeAndWait(()->{
            try {
                var field=GhidrAssistPlugin.class.getDeclaredField("provider");
                field.setAccessible(true);
                Object provider=field.get(plugin);
                if(provider==null)
                    throw new IllegalStateException("GhidrAssist GUI provider absent");
                Object ui=provider.getClass().getMethod("getUI").invoke(provider);
                var controllerField=ui.getClass().getDeclaredField("controller");
                controllerField.setAccessible(true);
                Object controller=controllerField.get(ui);
                var tabField=ui.getClass().getDeclaredField("queryTab");
                tabField.setAccessible(true);
                var tab=(ghidrassist.ui.tabs.QueryTab)tabField.get(ui);
                var serviceField=controller.getClass().getDeclaredField("queryService");
                serviceField.setAccessible(true);
                var queryService=(ghidrassist.services.QueryService)
                    serviceField.get(controller);
                int oldId=queryService.createNewChatSession();
                if(oldId<=0)
                    throw new IllegalStateException("Missing isolated GUI chat");
                // Simulate a previous conversation's permissive setting.
                // Staging must never reuse it or its session-scoped grants.
                queryService.setAcceptAllToolsEnabled(true);
                var stage=controller.getClass().getDeclaredMethod(
                    "stageImportedAgenticDraft",AgenticReviewDraft.class);
                stage.setAccessible(true);
                stage.invoke(controller,draft);
                int fresh=queryService.getCurrentSessionId();
                var policy=tab.getTaskToolPolicyPanel().snapshot();
                var queryField=tab.getClass().getDeclaredField("queryTextArea");
                queryField.setAccessible(true);
                var area=(javax.swing.JTextArea)queryField.get(tab);
                String query=area.getText();
                if(fresh==oldId || fresh<=0 ||
                        queryService.isAcceptAllToolsEnabled() ||
                        policy==null || !policy.readOnly() ||
                        !Integer.valueOf(8).equals(policy.totalLimit()) ||
                        !tab.isAgenticSelected() ||
                        !query.contains("Untrusted historical observations") ||
                        !query.startsWith("New independent static MMIO reference audit"))
                    throw new IllegalStateException(
                        "Real GUI did not isolate new chat, query, tool permissions");
                var pending=controller.getClass().getDeclaredField("isAgentPlanPending");
                pending.setAccessible(true);
                var running=controller.getClass().getDeclaredField("isQueryRunning");
                running.setAccessible(true);
                if(pending.getBoolean(controller) || running.getBoolean(controller))
                    throw new IllegalStateException(
                        "Import unexpectedly proposed or started a model run");
                proof.addProperty("real_gui_new_chat_id",true);
                proof.addProperty("real_gui_old_grants_not_inherited",true);
                proof.addProperty("real_gui_readonly_tool_limit_8",true);
                proof.addProperty("real_gui_staged_no_model_run",true);
                proof.addProperty("real_gui_source_program_unchanged",
                    plugin.getCurrentProgram()==program);
                staged.set(new StagedReview(query,fresh,policy,previous.run()));
            } catch(Throwable error) {
                failed.set(error);
            }
        });
        if(failed.get()!=null)
            throw new IllegalStateException(
                "Real CodeBrowser Query review staging failed",failed.get());
        if(staged.get()==null)
            throw new IllegalStateException("No independently staged GUI review");
        return staged.get();
    }

    /**
     * TEST-ONLY approved follow-up: a fresh real ReActOrchestrator (not a
     * resumed model) runs a real Ghidra read-only tool after an external
     * explicit approval marker. The marker is not a production approval API.
     */
    private static void runIndependentlyApprovedInvestigation(
            GhidrAssistPlugin plugin,Program program,Address site,
            Path evidence,StagedReview staged) throws Exception {
        var registry=AgenticEvidenceRegistry.shared();
        long originalRevision=program.getModificationNumber();
        var prior=registry.page(program,originalRevision,
            program.getExecutableSHA256(),0,1,null,null);
        if(!prior.run().equals(staged.previousRun()) ||
                !"SUCCESS".equals(prior.state()))
            throw new IllegalStateException("Prior reviewed evidence changed");
        Path approved=evidence.resolve("ga15-independent-review-approved.json");
        // No new ReAct run can exist until the independent CI controller
        // explicitly supplies a new approved PLAN. This does not impersonate
        // the real GUI Approve Plan button.
        waitFor(approved,80);
        JsonObject request=JsonParser.parseString(
            Files.readString(approved,StandardCharsets.UTF_8)).getAsJsonObject();
        String plan=request.get("approved_plan").getAsString();
        if(!request.get("explicit_test_approval").getAsBoolean() ||
                !staged.previousRun().equals(
                    request.get("expected_previous_run").getAsString()) ||
                !"- [ ] Independently verify the current Listing address"
                    .equals(plan))
            throw new IllegalStateException("Fresh plan authorization refused");
        var before=registry.page(program,originalRevision,
            program.getExecutableSHA256(),0,1,null,null);
        if(!before.run().equals(prior.run()))
            throw new IllegalStateException("A new ReAct run started before approval");
        var cfg=new APIProviderConfig("GA15 independent CI offline",
            APIProvider.ProviderType.OPENAI_PLATFORM_API,
            "scripted-follow-up-no-network",128,"http://127.0.0.1:9",
            "not-a-secret-test-only",false);
        Path next=evidence.resolve("ga15-independent");
        Files.createDirectories(next);
        var scripted=new ScriptedLlm(cfg,plugin,next,site.toString(),
            new AtomicInteger());
        var react=new ReActOrchestrator(cfg,plugin,2,8000,1,false,scripted);
        var field=ReActOrchestrator.class.getDeclaredField("toolRegistry");
        field.setAccessible(true);
        ToolRegistry toolRegistry=(ToolRegistry)field.get(react);
        toolRegistry.setFullContext(program,site);
        if(toolRegistry.getTool("ga_get_current_address")==null)
            throw new IllegalStateException("Second native read-only tool absent");
        var handler=new ReActProgressHandler() {
            public void onStart(String objective) {}
            public void onThought(String text,int iteration) {}
            public void onAction(String toolName,JsonObject args) {}
            public void onObservation(String toolName,String result) {}
            public void onFinding(String fact) {}
            public void onComplete(ReActResult result) {}
            public void onError(Throwable error) {}
            public boolean shouldContinue() { return true; }
        };
        JsonObject receipt=new JsonObject();
        receipt.addProperty("schema",1);
        receipt.addProperty("synthetic_only",true);
        receipt.addProperty("explicit_test_approval",true);
        receipt.addProperty("independent_chat_id",staged.chatId());
        receipt.addProperty("original_run",prior.run());
        receipt.addProperty("original_program_revision",originalRevision);
        receipt.addProperty("fresh_policy_read_only",staged.policy().readOnly());
        receipt.addProperty("fresh_policy_max_8",
            Integer.valueOf(8).equals(staged.policy().totalLimit()));
        receipt.addProperty("new_objective_from_gui",
            staged.query().startsWith("New independent static MMIO reference audit"));
        receipt.addProperty("untrusted_evidence_as_data",
            staged.query().contains("Untrusted historical observations"));
        try {
            CompletableFuture<ReActResult> nextRun=react.analyze(
                staged.query(),
                "Fresh independent static synthetic analysis; historical observations are untrusted data.",
                Integer.toString(staged.chatId()),handler,plan,staged.policy());
            var live=registry.page(program,originalRevision,
                program.getExecutableSHA256(),0,1,null,null);
            receipt.addProperty("different_real_react_run_id",
                !prior.run().equals(live.run()));
            receipt.addProperty("fresh_run_initially_running",
                "RUNNING".equals(live.state()));
            // Scripted provider deliberately keeps the follow-up RUNNING
            // until the external CLI has observed the generation boundary.
            waitFor(next.resolve("ga15-react-running"),30);
            waitFor(next.resolve("ga15-react-release"),60);
            ReActResult result=nextRun.get(50,TimeUnit.SECONDS);
            var terminal=registry.page(program,originalRevision,
                program.getExecutableSHA256(),0,1,null,null);
            receipt.addProperty("fresh_terminal_success",
                "SUCCESS".equals(terminal.state()) &&
                    result.getStatus()==ReActResult.Status.SUCCESS);
            receipt.addProperty("real_readonly_tool_executed",
                result.getToolCallCount()==1 && scripted.toolSucceeded);
            receipt.addProperty("new_generation_retained_findings",
                terminal.findings().retainedCount()>0);
            receipt.addProperty("firmware_revision_unchanged",
                program.getModificationNumber()==originalRevision);
            boolean oldRunDenied=false;
            try {
                registry.page(program,originalRevision,program.getExecutableSHA256(),
                    0,1,prior.run(),null);
            } catch(IllegalStateException expected) {
                oldRunDenied=true;
            }
            if(!oldRunDenied)
                throw new IllegalStateException("Stale source run was still accepted");
            receipt.addProperty("previous_run_denied",true);
            receipt.addProperty("new_run_id",terminal.run());
            receipt.addProperty("tool_calls",result.getToolCallCount());
        } catch(Exception error) {
            receipt.addProperty("error",error.toString());
        } finally {
            Files.writeString(evidence.resolve("ga15-independent-result.json"),
                receipt.toString(),StandardCharsets.UTF_8);
        }
        // Separate third run: exercise the REAL production Swing Approve
        // Plan button -> TabController -> ReAct execution, not merely a
        // test harness calling analyze() directly.
        if(receipt.has("fresh_terminal_success") &&
                receipt.get("fresh_terminal_success").getAsBoolean()) {
            verifyProductionApprovePlanButton(plugin,program,site,evidence,staged);
        }
    }

    private static void verifyProductionApprovePlanButton(
            GhidrAssistPlugin plugin,Program program,Address site,
            Path evidence,StagedReview staged) throws Exception {
        var registry=AgenticEvidenceRegistry.shared();
        long revision=program.getModificationNumber();
        var previous=registry.page(program,revision,
            program.getExecutableSHA256(),0,1,null,null);
        if(!"SUCCESS".equals(previous.state()))
            throw new IllegalStateException("Second ReAct not terminal");
        Path marker=evidence.resolve("ga15-gui-approve-plan.json");
        waitFor(marker,80);
        JsonObject command=JsonParser.parseString(
            Files.readString(marker,StandardCharsets.UTF_8)).getAsJsonObject();
        String plan=command.get("approved_plan").getAsString();
        if(!command.get("explicit_test_approval").getAsBoolean() ||
                !"- [ ] Independently verify the current Listing address".equals(plan) ||
                !previous.run().equals(command.get("expected_previous_run").getAsString()))
            throw new IllegalStateException("GUI approval test plan refused");

        JsonObject proof=new JsonObject();
        proof.addProperty("schema",1);
        proof.addProperty("synthetic_only",true);
        proof.addProperty("actual_swing_approve_button",false);
        proof.addProperty("no_model_or_oauth",true);
        Path next=evidence.resolve("ga15-gui-approval");
        Files.createDirectories(next);
        APIProviderConfig cfg=new APIProviderConfig("GA15 GUI CI offline",
            APIProvider.ProviderType.OPENAI_PLATFORM_API,
            "scripted-gui-approval-no-network",128,"http://127.0.0.1:9",
            "not-a-secret-test-only",false);
        var scripted=new ScriptedLlm(cfg,plugin,next,site.toString(),
            new AtomicInteger());
        var react=new ReActOrchestrator(cfg,plugin,2,8000,1,false,scripted);
        Field toolsField=ReActOrchestrator.class.getDeclaredField("toolRegistry");
        toolsField.setAccessible(true);
        ToolRegistry registryTools=(ToolRegistry)toolsField.get(react);
        registryTools.setFullContext(program,site);
        java.util.concurrent.atomic.AtomicReference<Throwable> uiFailure=
            new java.util.concurrent.atomic.AtomicReference<>();
        try {
            javax.swing.SwingUtilities.invokeAndWait(()->{
                try {
                    Field providerField=GhidrAssistPlugin.class.getDeclaredField("provider");
                    providerField.setAccessible(true);
                    Object provider=providerField.get(plugin);
                    Object ui=provider.getClass().getMethod("getUI").invoke(provider);
                    Field controllerField=ui.getClass().getDeclaredField("controller");
                    controllerField.setAccessible(true);
                    Object controller=controllerField.get(ui);
                    Field tabField=ui.getClass().getDeclaredField("queryTab");
                    tabField.setAccessible(true);
                    var tab=(ghidrassist.ui.tabs.QueryTab)tabField.get(ui);
                    Field serviceField=controller.getClass().getDeclaredField("queryService");
                    serviceField.setAccessible(true);
                    var service=(ghidrassist.services.QueryService)
                        serviceField.get(controller);
                    if(service.getCurrentSessionId()!=staged.chatId() ||
                            service.isAcceptAllToolsEnabled())
                        throw new IllegalStateException("GUI session reused previous grants");
                    // We deliberately seed only a fresh proposed test plan.
                    // No prior plan or authorization is imported from a draft.
                    String runId=java.util.UUID.randomUUID().toString();
                    service.beginReActRun(runId,staged.query());
                    setField(controller,"pendingAgentPlan",plan);
                    setField(controller,"pendingAgentQuery",staged.query());
                    setField(controller,"pendingAgentRunId",runId);
                    setField(controller,"pendingAgentInitialContext",
                        "Fresh static synthetic context, no inherited model instructions.");
                    setField(controller,"pendingAgentUseMCP",false);
                    setField(controller,"isAgentPlanPending",true);
                    setField(controller,"agenticTestOrchestratorFactory",
                        (java.util.function.Supplier<ReActOrchestrator>)(()->react));
                    tab.setPendingPlan(plan);
                    Field approve=tab.getClass().getDeclaredField("approvePlanButton");
                    approve.setAccessible(true);
                    javax.swing.JButton button=(javax.swing.JButton)approve.get(tab);
                    if(!button.isEnabled() || !button.isVisible())
                        throw new IllegalStateException("Approve Plan button not ready");
                    button.doClick();
                    if((Boolean)getField(controller,"isAgentPlanPending") ||
                            getField(controller,"pendingAgentPlan")!=null)
                        throw new IllegalStateException("Approval did not consume new plan");
                    proof.addProperty("actual_swing_approve_button",true);
                    proof.addProperty("fresh_chat_approved",true);
                    proof.addProperty("controller_factory_injected_ci_only",true);
                } catch(Throwable err) {
                    uiFailure.set(err);
                }
            });
            if(uiFailure.get()!=null)
                throw new IllegalStateException("Real Swing Approve Plan failed",uiFailure.get());
            waitFor(next.resolve("ga15-react-running"),35);
            var active=registry.page(program,revision,
                program.getExecutableSHA256(),0,1,null,null);
            proof.addProperty("new_run_on_button",!active.run().equals(previous.run()));
            proof.addProperty("running_after_button","RUNNING".equals(active.state()));
            waitFor(next.resolve("ga15-react-release"),70);
            long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(50);
            AgenticEvidenceRegistry.EvidencePage observed=null;
            while(System.nanoTime()<deadline) {
                observed=registry.page(program,revision,
                    program.getExecutableSHA256(),0,1,null,null);
                if(!"RUNNING".equals(observed.state()))break;
                Thread.sleep(50);
            }
            if(observed==null || !"SUCCESS".equals(observed.state()))
                throw new IllegalStateException("GUI-approved ReAct never reached SUCCESS");
            proof.addProperty("terminal_success",true);
            proof.addProperty("one_real_native_readonly_tool",scripted.toolSucceeded);
            proof.addProperty("new_registry_evidence",observed.findings().retainedCount()>0);
            proof.addProperty("program_revision_unchanged",
                program.getModificationNumber()==revision);
            proof.addProperty("different_run_than_second",!observed.run().equals(previous.run()));
        } catch(Exception err) {
            proof.addProperty("error",err.toString());
        } finally {
            Files.writeString(evidence.resolve("ga15-gui-approved-result.json"),
                proof.toString(),StandardCharsets.UTF_8);
        }
    }

    private static void setField(Object target,String name,Object value) throws Exception {
        Field f=target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        f.set(target,value);
    }

    private static Object getField(Object target,String name) throws Exception {
        Field f=target.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return f.get(target);
    }


    /** CI only: a genuinely NEW JVM opens historical offline evidence and
     * requires a fresh Query session, fresh plan and actual Approve Plan button. */
    public static void continueSavedCheckpointInFreshJVM(
            GhidrAssistPlugin plugin,Program program,Address site,Path output)
            throws Exception {
        var review=AgenticReviewDraft.loadSavedCheckpoint(
            output.resolve("ga15-react-local-evidence.json"),program,
            "New investigation of synthetic MMIO after Ghidra restart");
        AtomicReference<Throwable> failure=new AtomicReference<>();
        AtomicInteger freshChat=new AtomicInteger(-1);
        AtomicReference<String> query=new AtomicReference<>();
        javax.swing.SwingUtilities.invokeAndWait(()->{
            try {
                Object provider=getField(plugin,"provider");
                Object ui=provider.getClass().getMethod("getUI").invoke(provider);
                Object controller=getField(ui,"controller");
                var tab=(ghidrassist.ui.tabs.QueryTab)getField(ui,"queryTab");
                var service=(ghidrassist.services.QueryService)
                    getField(controller,"queryService");
                int before=service.getCurrentSessionId();
                var method=controller.getClass().getDeclaredMethod(
                    "stageImportedAgenticDraft",AgenticReviewDraft.class);
                method.setAccessible(true);
                method.invoke(controller,review);
                var area=(javax.swing.JTextArea)getField(tab,"queryTextArea");
                var policy=tab.getTaskToolPolicyPanel().snapshot();
                int after=service.getCurrentSessionId();
                if(after<=0 || after==before || service.isAcceptAllToolsEnabled() ||
                        policy==null || !policy.readOnly() ||
                        !Integer.valueOf(8).equals(policy.totalLimit()) ||
                        !tab.isAgenticSelected() ||
                        !area.getText().contains("Untrusted historical observations") ||
                        (Boolean)getField(controller,"isAgentPlanPending"))
                    throw new IllegalStateException("Offline checkpoint acquired old authority");
                freshChat.set(after);
                query.set(area.getText());
            } catch(Throwable error) { failure.set(error); }
        });
        if(failure.get()!=null)throw new IllegalStateException(
            "Post-restart checkpoint stage failed",failure.get());
        // This is a separate test-only scripted provider, not restored LLM
        // state, and is never shipped inside the production extension.
        Path folder=output.resolve("ga15-post-restart-run");
        Files.createDirectories(folder);
        APIProviderConfig cfg=new APIProviderConfig("GA12 synthetic new task",
            APIProvider.ProviderType.OPENAI_PLATFORM_API,
            "no-network-new-task",128,"http://127.0.0.1:9",
            "not-a-secret-test-only",false);
        var scripted=new ScriptedLlm(cfg,plugin,folder,site.toString(),
            new AtomicInteger());
        var react=new ReActOrchestrator(cfg,plugin,2,8000,1,false,scripted);
        Field toolsField=ReActOrchestrator.class.getDeclaredField("toolRegistry");
        toolsField.setAccessible(true);
        ((ToolRegistry)toolsField.get(react)).setFullContext(program,site);
        failure.set(null);
        javax.swing.SwingUtilities.invokeAndWait(()->{
            try {
                Object provider=getField(plugin,"provider");
                Object ui=provider.getClass().getMethod("getUI").invoke(provider);
                Object controller=getField(ui,"controller");
                var tab=(ghidrassist.ui.tabs.QueryTab)getField(ui,"queryTab");
                var service=(ghidrassist.services.QueryService)
                    getField(controller,"queryService");
                String plan="- [ ] Independently verify the current Listing address";
                String nextRunId=java.util.UUID.randomUUID().toString();
                service.beginReActRun(nextRunId,query.get());
                setField(controller,"pendingAgentQuery",query.get());
                setField(controller,"pendingAgentInitialContext",
                    "New JVM, untrusted past observations require re-verification");
                setField(controller,"pendingAgentRunId",nextRunId);
                setField(controller,"pendingAgentPlan",plan);
                setField(controller,"pendingAgentUseMCP",false);
                setField(controller,"isAgentPlanPending",true);
                setField(controller,"agenticTestOrchestratorFactory",
                    (java.util.function.Supplier<ReActOrchestrator>)(()->react));
                tab.setPendingPlan(plan);
                var approve=(javax.swing.JButton)getField(tab,"approvePlanButton");
                if(!approve.isEnabled() || !approve.isVisible())
                    throw new IllegalStateException("New review approval unavailable");
                approve.doClick();
                if((Boolean)getField(controller,"isAgentPlanPending"))
                    throw new IllegalStateException("Approve Plan did not consume fresh plan");
            } catch(Throwable error) { failure.set(error); }
        });
        if(failure.get()!=null)throw new IllegalStateException(
            "Post-restart Approve Plan failed",failure.get());
        waitFor(folder.resolve("ga15-react-running"),45);
        var running=AgenticEvidenceRegistry.shared().page(program,
            program.getModificationNumber(),program.getExecutableSHA256(),
            0,1,null,null);
        if(!"RUNNING".equals(running.state()))
            throw new IllegalStateException("No new ReAct run after fresh approval");
        Files.writeString(folder.resolve("ga15-react-release"),
            "new independent post-restart task",StandardCharsets.UTF_8);
        AgenticEvidenceRegistry.EvidencePage terminal=running;
        long until=System.nanoTime()+TimeUnit.SECONDS.toNanos(60);
        while(System.nanoTime()<until) {
            terminal=AgenticEvidenceRegistry.shared().page(program,
                program.getModificationNumber(),program.getExecutableSHA256(),
                0,100,null,null);
            if(!"RUNNING".equals(terminal.state()))break;
            Thread.sleep(60);
        }
        if(!"SUCCESS".equals(terminal.state()) || !terminal.complete() ||
                !scripted.toolSucceeded)
            throw new IllegalStateException("Independent post-restart ReAct incomplete");
        var prior=com.google.gson.JsonParser.parseString(Files.readString(
            output.resolve("ga15-react-local-evidence.json"),
            StandardCharsets.UTF_8)).getAsJsonObject().getAsJsonObject("payload");
        if(terminal.run().equals(prior.get("run").getAsString()))
            throw new IllegalStateException("The old run ID was incorrectly resurrected");

        // New retained findings are a new, separately persisted checkpoint.
        JsonObject payload=new JsonObject();
        payload.addProperty("schema",1);
        payload.addProperty("kind","ghidrassist-agentic-retained-evidence");
        payload.addProperty("run",terminal.run());
        payload.addProperty("program_revision",terminal.programRevision());
        payload.addProperty("import_sha256",terminal.importSha256());
        payload.addProperty("state",terminal.state());
        payload.addProperty("findings_revision",terminal.findings().revision());
        payload.addProperty("retained_count",terminal.findings().retainedCount());
        payload.addProperty("accepted_count",terminal.findings().acceptedCount());
        payload.addProperty("evicted_count",terminal.findings().evictedCount());
        payload.addProperty("source_incomplete",terminal.findings().sourceIncomplete());
        payload.addProperty("complete",terminal.complete());
        com.google.gson.JsonArray rows=new com.google.gson.JsonArray();
        for(var row:terminal.findings().rows()) {
            JsonObject jsonRow=new JsonObject();
            jsonRow.addProperty("fact",row.fact());
            jsonRow.addProperty("evidence",row.evidence());
            jsonRow.addProperty("toolUsed",row.toolUsed());
            jsonRow.addProperty("relevance",row.relevance());
            jsonRow.addProperty("timestamp",row.timestamp());
            rows.add(jsonRow);
        }
        payload.add("rows",rows);
        // Provable linkage between two read-only checkpoint generations:
        // SHA-256 of the saved prior canonical payload and its exact opaque
        // run ID. Neither this lineage nor the new file is authorization.
        var parentEnvelope=com.google.gson.JsonParser.parseString(
            Files.readString(output.resolve("ga15-react-local-evidence.json"),
                StandardCharsets.UTF_8)).getAsJsonObject();
        payload.addProperty("parent_checkpoint_sha256",
            parentEnvelope.get("payload_sha256").getAsString());
        payload.addProperty("parent_run",prior.get("run").getAsString());
        payload.addProperty("continuation_kind",
            "new-independently-reviewed-run");
        payload.addProperty("notice","New reviewed findings, never restored AI state");
        var gson=new com.google.gson.GsonBuilder().disableHtmlEscaping().create();
        String canonical=gson.toJson(sortCheckpointJson(payload));
        String digest=java.util.HexFormat.of().formatHex(
            java.security.MessageDigest.getInstance("SHA-256").digest(
                canonical.getBytes(StandardCharsets.UTF_8)));
        JsonObject env=new JsonObject();
        env.add("payload",payload);
        env.addProperty("payload_sha256",digest);
        Files.writeString(output.resolve("ga15-post-restart-checkpoint.json"),
            gson.toJson(env),StandardCharsets.UTF_8,
            java.nio.file.StandardOpenOption.CREATE_NEW);
        JsonObject result=new JsonObject();
        result.addProperty("schema",1);
        result.addProperty("synthetic_only",true);
        result.addProperty("fresh_chat_id",freshChat.get());
        result.addProperty("new_review_from_saved_checkpoint",true);
        result.addProperty("actual_approve_plan_button",true);
        result.addProperty("native_readonly_tool_executed",true);
        result.addProperty("new_react_success",true);
        result.addProperty("distinct_new_run",true);
        result.addProperty("new_checkpoint_created",true);
        Files.writeString(output.resolve("ga15-post-restart-continuation.json"),
            gson.toJson(result),StandardCharsets.UTF_8);
    }

    private static com.google.gson.JsonElement sortCheckpointJson(
            com.google.gson.JsonElement value) {
        if(value.isJsonObject()) {
            JsonObject sorted=new JsonObject();
            value.getAsJsonObject().entrySet().stream()
                .sorted(java.util.Map.Entry.comparingByKey())
                .forEach(e->sorted.add(e.getKey(),sortCheckpointJson(e.getValue())));
            return sorted;
        }
        if(value.isJsonArray()) {
            com.google.gson.JsonArray array=new com.google.gson.JsonArray();
            for(var item:value.getAsJsonArray())array.add(sortCheckpointJson(item));
            return array;
        }
        return value.deepCopy();
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
