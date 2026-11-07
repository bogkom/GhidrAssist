# Explicit Agentic execution policy

Call `ReActOrchestrator.analyze(query, context, sessionId, handler, approvedPlan, policy)`
with a `ToolExecutionPolicy(allowedTools, perToolLimits)` supplied by trusted caller
configuration. The existing overload remains unrestricted unless the existing
narrow global/read-only objective rules apply. The explicit-policy overload does
not apply those textual rules: its typed input is authoritative, so prose such as
"exactly one tool call per tool" cannot overwrite independent per-tool budgets.
The four-argument policy constructor additionally accepts `totalLimit` and
`readOnly`; use these fields for explicit global and read-only constraints. No free-form natural-language
allowlist or per-tool budget parser is introduced.

`allowedTools == null` allows registered tools; an empty set denies all tools.
Names are exact registered names, including the MCP server prefix. Budgets are
nonnegative independent limits keyed by those names. Changing arguments does
not create a new budget. A denied approval consumes no execution budget. Both
budget and static-read deduplication reservations are atomic. A task status poll
may repeat, but it still consumes execution budgets. Each new investigation
resets its policy and counters; policies defensively copy caller collections.

This deliberately distinguishes an instruction to a model from a controller
policy. Callers that need enforced restrictions must supply the policy. The
existing GUI's unrestricted text entry does not infer a policy from arbitrary
prose. A UI or caller may expose structured options without parsing every
possible instruction. The regression scenarios GA-04 and GA-07 now supply the
explicit policy corresponding to their prompts; their behavioral assertions
remain unchanged. Companion cases retain the unrestricted and legacy global
limit behavior.

## Verified execution reports

ToolRegistry owns an immutable-snapshot journal of requested, started, succeeded,
rejected and failed calls. Each entry has an actual call identity and request,
start and completion timestamps. Failed-after-start differs from rejection before
execution. Observer failures cannot rewrite provider outcomes. Late approvals
cannot start work in a closed or different investigation.

If every recorded call succeeded, the original model analysis is retained.
After any rejected, failed or pending attempt, free-form synthesis is replaced
by a deterministic journal report that retains observed successful data and
separates actual attempts from successful completions. Synthesis is buffered
until this check, so a fabricated success cannot appear transiently in the UI.
This conservative fallback can withhold an otherwise honest narrative following
a rejected duplicate; it avoids relying on an unreliable natural-language claim
parser. It does not semantically verify general factual analysis when all calls
succeed. Progress callbacks also count dispatcher executions rather than proposals.

RAG/source/pagination metadata is retained outside the documentation excerpt
budget in both the evidence cache and conversation truncation. Mandatory metadata
may exceed a very small requested excerpt budget; callers needing less context
should request fewer results rather than silently lose provenance or pagination.

## Query GUI

The Query toolbar opens **Tools** in a separate resizable, modeless Swing window.
Configuration and the optional **Tool history** window occupy no transcript area.
The toolbar shows the applied mode, selected count and whether its lifetime is
`next` task or `chat`; its tooltip includes total and per-tool budget information.

Choose **All available tools**, **Read-only tools**, or **Selected tools**. The
inventory uses full registered names, provider groups and provider descriptions.
Search matches literal substrings of names/descriptions, ignoring case. Provider
filtering and selection operate together; **Select all shown** and **Deselect all
shown** affect only the filtered rows. The count includes hidden selected rows.
Tables scroll horizontally; selecting a row displays the full description.

**Max calls** is a per-tool budget and **Total calls** is a per-task global budget.
Blank means **Unlimited** and zero blocks executions. The read-only preview uses
exactly the existing ToolRegistry classification (`get_`, `list_`, `search_` in
the name); it is not a separate audit of provider implementations. Dispatcher
approvals, aliases, deduplication, journals and other protections are unchanged.
To allow one tool once, choose Selected tools, clear both filters, deselect all,
select its full name and set both budgets to one.

**Apply** validates all visible and hidden row limits and commits a snapshot in
memory. Cancel/window-close discards edits; Restore defaults requires Apply.
Next task settings reset after execution completes, fails or is cancelled.
Cancelling a proposed plan does not consume settings. Current conversation
settings survive tasks but reset when starting, clearing, deleting or switching
conversations. They are never written to preferences or restored from history.
Unchanged defaults preserve the legacy API overload. Approve Plan freezes the
applied policy and editing remains disabled during execution.

Help (?) explains these options in a resizable window. Tool history separately
shows the latest task's REQUESTED, RUNNING, SUCCEEDED, REJECTED and FAILED events
and full responses/reasons. These remain production observer events, independent
of the policy editor and the model's claims.

## GA-12/15: terminal Agentic evidence lifecycle (2026-11-07)

The read-only Agentic evidence registry treats `RUNNING` as its only mutable
lifecycle state. Once an exact run reaches SUCCESS, CANCELLED, ERROR,
MAX_ITERATIONS or MAX_TOOLS, later callbacks cannot rewrite its outcome or
upgrade incomplete evidence. A replacement run atomically becomes the active
evidence generation before the old run receives its cancellation signal.
Both `begin` overloads invoke replacement cancellation without holding the
registry monitor, including synchronous provider re-entry. Identity-bound
Program and revision/SHA/pagination checks are unchanged. This rule does not
rollback tool side effects, authorize Apply or resume a model checkpoint.

## GA-12/15: bounded evidence and consistent read views (2026-11-07)

All live findings summaries and prompt/iteration-history views are serialized
with cache writes and relevance edits. This prevents concurrent tool callbacks
from producing inconsistent textual snapshots while the Automation API pages
retain revision-based stitching. When a single fact, evidence string or tool
identifier exceeds its local retention cap, the cache marks the originating
source incomplete even if the retained prefix fits on one page. A terminal
SUCCESS cannot certify truncated input as a complete checkpoint. Explicit
`clear()` resets the incompleteness receipt for a newly initialized analysis;
this does not imply that discarded evidence has been recovered.

## GA-15: omitted oversized individual tool-output lines (2026-11-07)

The bounded findings extractor does not retain lines longer than 300
characters. Such deliberately omitted source lines now set the independent
`sourceIncomplete` receipt even when the original transcript fits in the
128 KiB scan window and no row-count limit was reached. The warning is
retained as structural metadata if relevance pruning evicts its text, and
`SUCCESS` does not certify complete source evidence in a checkpoint. Exact
300-character lines are still eligible for normal extraction. This is a
conservative retained-evidence rule, not proof of exhaustive tool semantics.

## GA-12/15: explicit resume preflight (2026-11-07)

`ghidrassist-agent agentic-resume-check --input FILE` verifies the SHA-256
integrity and bounded metadata of an offline evidence checkpoint, then queries
exactly one **read-only** live Agentic page using Bearer JSON-RPC. It requires
the active Program revision and executable SHA, identical run token, terminal
status and unchanged retained-evidence generation/counters. A RUNNING offline
checkpoint or a replaced run is refused. The response explicitly states
`resumable_ai_session=false`, `tool_execution_authorized=false` and
`apply_authorized=false`. A matching result requires **new Review** before any
new model session or tool execution; it is not an actual resume, rollback,
operator approval, or identity authentication of the file's creator. No remote
snapshot import, callback replay or privileged mutation is implemented.

## GA-12/15: real CodeBrowser preflight and content-stable Review (2026-11-07)

The read-only `agentic-resume-check` now compares **every retained finding row**
against a live, authenticated Agentic source in the current Ghidra Program, not
just matching run ids, revision and counters. Every bounded page carries the
same Program/import SHA, run token, terminal state and cache revision; a
concurrent mutation, shortened page or rehashed locally forged evidence is
rejected. CI exercises the real CLI over real CodeBrowser/JSON-RPC after an
actual ReAct native tool call in synthetic Ghidra 12.1.4 PUBLIC, including
forged-content, stale-run and unauthorized Bearer refusals. A preflight PASS
only opens an opportunity for **independent human Review**; it cannot resume
LLM execution, grant tools, reuse approvals or Apply modifications.

## GA-12/15: new independent investigation review draft (2026-11-07)

`ghidrassist-agent agentic-review-draft --input CHECKPOINT --output DRAFT --query "New objective"`
requires exact authenticated live evidence matching the offline checkpoint.
It creates a private, create-no-overwrite, bounded JSON review proposal containing
a fresh operator-supplied objective and at most 20 **untrusted data** excerpts.
The proposal has no executable plan, no copied ToolExecutionPolicy, no LLM
state, no permission to run tools or Apply, and `new_review_approved=false`.
Its terminal state is `AWAITING_NEW_REVIEW`. Actual approval and a new
independent ReAct run remain separate future steps: no CLI execution endpoint
accepts review drafts as authorization. The real synthetic CodeBrowser GUI
harness validates the exported artifact, refuse-overwrite and forged-evidence
denial through the production Bearer JSON-RPC client.

## GA-12/15: GUI import and explicit independent Review (2026-11-07)

The Query tab has an **Import Review Draft** action. A draft is a bounded,
SHA-256-validated, **non-executable** snapshot of a prior verified Agentic run.
Import checks current Program identity, executable SHA, modification number,
previous run token, terminal SUCCESS and complete retained evidence, counters,
and every retained finding against the currently active in-memory registry.
It populates only a new Query text area, clearly segregating untrusted excerpts,
sets Agentic mode and resets the in-memory task policy to READ_ONLY with an
8-call ceiling. It does not submit a query, create a plan, call the LLM, run a
tool, persist an approval or Apply. The operator must first click **Submit**
(new planning request) and separately **Approve Plan** with a fresh policy.
The draft's own boolean flags are not authorization. This import requires the
same live Program and prior Agentic generation; it fails closed after restart,
program switch, new run, or modification. Durable offline browsing remains
available via `agentic-read` and is never treated as executable authority.

## GA-12/15: same-CodeBrowser GUI staging regression (2026-11-07)

The deterministic, model-free Xvfb suite now validates the **actual Swing
Query controller** on the same synthetic Program as the completed ReAct
registry. After validating the JSON draft, the test invokes the production
EDT staging function without launching the file chooser or executing a model:
a different chat ID is created, the previous chat's permissive authorization
does not transfer, Accept All remains off, the policy is READ_ONLY with a
strict 8-call limit, and the Query text contains the explicitly untrusted
evidence. The pending-plan and running flags remain false: operator **Submit**
and **Approve Plan** are still separate steps. This is a production GUI-state
integration test, not proof of a human click on the chooser or a restored
provider session. No persistent permissions from a previous chat are copied.

## GA-12/15/18: independently approved follow-up ReAct E2E (2026-11-07)

A deterministic CI-only approval handshake now tests a **second, distinct real
ReActOrchestrator execution** in the same genuine isolated Ghidra 12.1.4 PUBLIC
CodeBrowser. First, completed live findings are exported, checked against the
active Program, and imported into a new Query chat as untrusted observations
with a new READ_ONLY/8-call policy. Before the explicit CI-only approval
marker, the old completed run remains bound and no new native tool is invoked.
The marker provides a **fresh independently approved test plan**, not one
copied from the previous checkpoint; the test creates a separate ReAct object
and runs the actual `ga_get_current_address` tool, checking fresh run ID,
terminal SUCCESS, one tool call, unchanged Program revision and denial of
stale prior checkpoints over authenticated CLI. Neither marker nor test
fixture is packaged as an approval API. The test **does not simulate the
actual user clicking Approve Plan**, does not restore model state, and does
not authorize firmware mutation. Human approval remains mandatory in the GUI.

## GA-12/15/18: actual Approve Plan Swing control + post-exit evidence (2026-11-07)

The isolated CodeBrowser GUI fixture now tests a **third** independent
ReAct run triggered through the actual `Approve Plan` Swing JButton and
production `TabController.handleAgentPlanApproved` route, not by calling
`ReActOrchestrator.analyze` from the harness. The CI-only fixture supplies
a newly proposed test plan and a non-network deterministic scripted provider;
the production controller still snapshots its current independent READ_ONLY
task tool policy. The assertions require a new run generation, a real native
read-only Listing tool, terminal SUCCESS, and unchanged Program revision.
No external model or real-user manual approval is claimed. Tests inject the
scripted ReAct factory via a private, non-API field; normal production uses
the existing constructor.

After CodeBrowser shuts down, separate CLI processes verify and read the
saved SHA-256 checkpoint with no active session. A live resume attempt with
no session must be refused. Offline persistence of **read-only evidence**
does not imply permission to resume a model or reuse Approve Plan.

## GA-12/15/18: actual second Ghidra JVM and reopened synthetic Program (2026-11-07)

The actual Xvfb CodeBrowser/ReAct synthetic E2E now **exits its first Java
process**, then starts a completely new Ghidra 12.1.4 PUBLIC JVM using the
same disposable Ghidra project and opens the same synthetic binary in the
real Swing CodeBrowser. The restarted process checks executable import SHA-256
against the previous checkpoint and **compares** Ghidra's modification number
with the recorded Program revision. A revision mismatch is treated as stale,
not silently coerced into equality: the live Agentic registry must be empty
regardless of whether the reopened Program has an identical revision.
A historical Review Draft is rejected because there is no matching live
registry generation, and no old ReAct run, pending plan, Accept All permission
or per-task tool policy is restored. A new session cannot inherit old Apply
or tool permission from the locally saved evidence. Separately the CLI reads
and verifies old checkpoint facts offline after this actual fresh JVM has also
terminated, without any live authorization.

**Scope:** the old firmware analysis is *not* automatically resumed. In
particular, Ghidra's modification counter is an observed value, not an
independent durable semantic version identifier. This regression does not
establish migration of a historical user CodeBrowser profile (#98), and
requires no external LLM, Wyse, Precision or formal Supervisor testing.

## GA-12: continue verified saved evidence after a real Ghidra restart (2026-11-07)

**Import Saved Checkpoint** is an independent Query-tab action. The operator
selects a locally saved Agentic checkpoint and supplies a NEW investigation
objective; it does not restore a model's hidden state or any old plan. The
Java reader limits the input to 8 MiB, verifies the canonical JSON SHA-256,
the successful/complete retained-evidence contract and source Program
executable SHA-256, and bounds excerpt lengths and the first 20 untrusted
observations. It treats the old Ghidra modification number as historical
metadata, not durable authorizing identity. Rehashed but modified local
evidence remains untrusted; a local checksum does **not** authenticate
authorship. The operator must independently verify such facts.

A valid offline import creates a fresh chat ID, disables Accept All, resets
the tool policy to READ_ONLY/NEXT_TASK/8 calls and stages the new objective
with historical excerpts explicitly labeled **untrusted**. There is NO
automatic tool invocation or Apply. New **Submit → independent plan →
Approve Plan** is required to start a new ReAct generation. An offline
checkpoint never grants access to the old live registry.

The isolated Xvfb/CodeBrowser acceptance scenario now performs:
first ReAct + SHA-256 checkpoint → exits first JVM → new Ghidra JVM opens
the same isolated synthetic Program → rejects old live draft and wrong
source/incomplete/tampered checkpoints → stages verified historical evidence
into a new Query chat → drives the actual production Approve Plan button
with a new deterministic scripted (network-free) plan → executes one real
native read-only tool → writes a **distinct new checkpoint**. Separate
CLI processes must verify both old and new snapshots, which remain
read-only evidence. This does not test private firmware, user profile
migration (Issue #98), hardware execution, external LLM or manual approval.

## GA-12/15: explicit checkpoint provenance across independent reviewed runs (2026-11-07)

`ghidrassist-agent agentic-checkpoint --output NEW.json --parent PRIOR.json`
may optionally record **parent_checkpoint_sha256**, **parent_run** and
`continuation_kind=new-independently-reviewed-run` in the NEW immutable,
SHA-256-verified retained-evidence checkpoint. Before recording this history,
the CLI strictly verifies both complete snapshots, identical original import
SHA-256, different run tokens and no evidence evictions. A corrupt,
incomplete, wrong-firmware or same-run parent fails closed *before* the output
file is created; historical files are never overwritten.

`ghidrassist-agent agentic-lineage-verify --input NEW.json --parent PRIOR.json`
is an **offline, read-only** check: it validates both source payload hashes,
the declared source hash and run, matching firmware import identities, and a
distinct new analysis. It does **not** establish authorship of a locally
rehashed forged file, restore the LLM session or grant access to Ghidra tools,
Review/Apply/Undo or an existing authorization. No active CodeBrowser,
session token or OAuth is required. Source lineage is historical provenance,
not proof the prior run caused the new analysis.

The separate-JVM synthetic Ghidra 12.1.4 ReAct acceptance fixture writes
exactly these parent fields when saving the independently approved second
checkpoint; its post-exit CLI process must verify both endpoints and reject
a reversed/same-file lineage. This is a provenance milestone toward GA-12,
not completed persistent recovery of partial CFG/P-code processing.

Java `AgenticReviewDraft.loadSavedCheckpoint` and Python offline readers
now both explicitly accept nullable evidence text fields while requiring
the keys to be present, with bounded fact/evidence/tool lengths, integral
relevance and nonnegative timestamp. Rows with missing evidence metadata,
fractional relevance, or inconsistent source counters are refused.

## GA-15: bounded ReAct model stream and non-complete source guarantee (2026-11-07)

Streaming callbacks from the model provider are untrusted and can deliver
arbitrarily long updates. `BoundedAgenticStream` caps each iteration's
accumulated response at 128 KiB UTF-16, the incremental GUI preview at 32 KiB,
and reflection at 16 KiB. Final synthesis is similarly bounded at 128 KiB
before verification and display. UTF-16 surrogate pairs (including those spanning separate provider callback chunks) are never split
at a truncation boundary. No unbounded StringBuilder remains on these
provider callback paths; full provider completions are independently
capped even when the stream was short.

Any omitted iteration, synthesis or reflection content invokes
`FindingsCache.markSourceIncomplete`, invalidating previous page
revisions and setting `sourceIncomplete=true` even if the warning finding
would be evicted by a small relevance budget. A truncated source cannot
produce `FindingsPage.complete=true`, a complete local Agentic checkpoint,
or an authorized new evidence Review. The UI may show a bounded preview,
but that is not an assertion that the entire model response was inspected.

The Java21 no-model regression exercises 50,000 synthetic streaming
updates, a one-character overflow, repeated dropped chunks, reset,
surrogate boundaries, cache page-revision invalidation and relevance
pruning. Full Java25 extension build and real Ghidra 12.1.4 scripted
ReAct/JSON-RPC/CLI regression remain required; no private firmware,
OAuth or external LLM is involved. This is a GA-15 long-response safety
milestone, not proof that every native/MCP tool's separate paging,
context-budget and cancellation contract is complete.

## GA-12: fixed-point worklist recovery after an actual process restart (2026-11-07)

The Java25/Xvfb synthetic CodeBrowser CI fixture now exercises the
existing `HardwarePartialStageRunner`,
`HardwareDurableFunctionStages` and
`HardwareDurableStageStore` across **two distinct Ghidra JVMs**.
The first JVM deliberately cancels just after a coherent partial worklist
has been written. A partial result is never eligible for Review/Apply,
Agentic complete-source evidence or the completed function-stage codec.
The second JVM reopens the same disposable Ghidra project and Program,
recovers the exact worklist and checks the resumed fixed point against an
independent cold analysis before committing the completed stage.

The synthetic input key is derived from the actual CodeBrowser Program
SHA-256, all 256 imported fixture bytes, the observed Listing
instruction and the Ghidra language, with an isolated synthetic test
analyzer version. Any differing Ghidra input digest, analyzer version,
MC68332 profile selection, language, translated CFG or solver budget
fails closed. Historical source identity is not authorization to mutate
a Program; no real ECU411 firmware or hardware execution is involved.

This is a regression of durable **translated CFG worklist** recovery,
not proof of authentic P-code extraction for all instruction types or
an end-user restored work session. New model/Review/Apply permissions
continue to require independent approval.
