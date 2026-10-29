# GA-02 — possible first SIMCR source sites inside functions

This read-only, source-provenance enhancement builds on GA-12's
bounded CFG evidence, after integration PR #67–#75.

For each Ghidra function containing a resolved candidate write to
a hypothesized MC68332 SIMCR address, a bounded graph search starts
at that function's local entry and follows modeled Ghidra successors.
It records the first encountered SIMCR full-word literal on each
syntactically explored path, and separately records unknown-width
writes, unresolvable pointer aliases, unknown calls, cycles, missing
successors and search-cap exhaustion. Branches can offer two or more
different possible first source sites.

**This cannot identify the first write after hardware reset.**
The function may not execute at all, may be entered in an unmodeled
way, or have unknown interprocedural and interrupt effects. SIMCR
MM is write-once and the real latched value is UNKNOWN without
stronger evidence. Source first-PC candidates are not runtime
execution epochs or true temporal ordering.

Limits: at most 1,500 nodes per local search, 75 displayed functions;
functions over 50,000 instruction nodes are omitted with a warning.
The algorithm is non-mutating and rejects unexpected/malformed CFG
inputs instead of inventing a value.

Pure Java tests cover branch alternatives, unknown aliases, prior
unknown literal, cycles, dangling CFG edges, missing entry and
work-budget limits. Full Ghidra 12.1.4 build and an actual isolated
test project acceptance are required before merge.

## CFG join correctness hardening (2026-10-29)

A converging diamond in the function CFG is **not** an execution loop.
The bounded intraprocedural walker now uses iterative depth-first
WHITE/GRAY/BLACK discovery: only edges to active GRAY ancestors are
classified as modeled cycles; repeated predecessors of completed BLACK
nodes are ordinary joins. Actual back-edges, unknown aliases, missing
successors, undecoded functions and search exhaustion stay UNKNOWN.
Traversal stops at the first known/unknown SIMCR write on each modeled
path. The change does not establish run-time reachability, timing,
write-once MM state, or interrupt/callee ordering.

Standalone regressions cover converging branches, a common exit, a
true post-join back-edge and the original branch/alias/limit cases.
This corrective candidate is independently stacked on PR #76 and
requires green exact-SHA Ghidra 12.1.4 Actions build and genuine
isolated Ghidra acceptance prior to integration.
