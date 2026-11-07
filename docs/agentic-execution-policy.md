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
