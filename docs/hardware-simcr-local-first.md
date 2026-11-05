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

## 2026-11-05 — bounded local SIMCR source-CFG edges

The possible-first-SIMCR source analysis already refused more than 50,000
CFG nodes, but had **no total successor-edge cap**. A single synthetically
large node could contain hundreds of thousands of duplicate successors,
performing unbounded iteration even with `visitBudget=1`. This is a source
input-volume gap, not evidence of any real MCU execution.

`HardwareSimcrLocalFirst.inspect` now refuses more than **200,000 total
source-CFG successor references**, accumulated over all submitted nodes,
before traversal begins. Crossing the limit is an explicit invalid-input
error: it does not silently produce a partial or false negative first-write
report. The exact limit remains accepted; a backedge in a 200,000-edge
input is still detected and classified `unknownFirstPossible=true`.

Deterministic Java21 regression tests exercise the inclusive cap,
200,001 edges within one node, aggregate overflow across two nodes and
non-poisoning of an independent diamond/first-write result. The full
Ghidra 12.1.4 PUBLIC/Java25 extension build and real isolated synthetic
Ghidra headless integration remain required on exact PR SHA.

No original ECU411, user project, MM-latch activation or hardware RESET
execution is inferred from this bounded source-only graph.
