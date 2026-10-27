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
