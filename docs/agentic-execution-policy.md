# Explicit Agentic execution policy

Call `ReActOrchestrator.analyze(query, context, sessionId, handler, approvedPlan, policy)`
with a `ToolExecutionPolicy(allowedTools, perToolLimits)` supplied by trusted caller
configuration. The existing overload remains unrestricted unless the existing
narrow global/read-only objective rules apply. No free-form natural-language
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
