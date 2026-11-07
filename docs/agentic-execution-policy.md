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
