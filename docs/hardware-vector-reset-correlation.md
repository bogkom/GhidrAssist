# GA-01/02/03/11 — static correlation of RESET calls and image-zero vectors

Source-only functionality, added after the GA-18 API integration (2026-11-03).

The Ghidra Hardware Analysis full report already contains a bounded
RESET-rooted direct-call candidate subset, source-only memory STORE / MOVEC
VBR evidence, and image-zero 68000 exception/interrupt *pointer candidates*.
The new read-only correlation joins those observations by **exact recognized
Ghidra function entry**, rather than assuming vector pointers are invoked
handlers. It displays a separate table and uncapped counts for the observed
subset, with bounded detail. A pointer to an **interior address** is explicitly
not a recognized handler entry. A function outside the bounded subset is
**not** proved unreachable: indirect calls, dynamic branches, exception
paths, analysis gaps, and work budgets remain unknown.

Call-subtree effects use `HardwareCallEffects` (4 hops, 100 functions per
target) and mean only *possible static* P-code STORE or MOVEC VBR sights;
STORE may be non-MMIO. Recursive/unresolved/over-budget effects are labeled
UNKNOWN, never absence. Neither the image-zero vector candidates nor a
RESET call-tree overlap proves the **current VBR**, that an IRQ occurred,
feasible execution order, SIMCR MM write-once latch value, chip-select
hardware mapping or firmware execution.

Sources: `HardwareResetFlow`, `HardwareCallEffects`,
`HardwareInterruptVectors`, new `HardwareVectorResetCorrelation`.
No data type, symbol, memory, review/apply decision, ECU411 project or binary
is changed.

## Evidence and acceptance

- Pure Java 21 adversarial tests: shared/outside/interior targets, VBR +
  STORE candidates, unknown call targets, graph cycles, non-recognized
  RESET, capped display, duplicate slots, invalid pointers and immutability.
- Real Ghidra 12.1.4 PUBLIC headless CPU32 generated fixture: exception
  pointers into a RESET-call node, disconnected exact entry and interior
  pointer must be correlated by **production** Ghidra scanner. Nothing
  about actual physical MCU operation is established.
- Full extension compilation (Java 25) and existing Xvfb/CodeBrowser
  regressions remain mandatory. No additional Wyse or Dell Precision test
  requested for this source-only increment.

## GA-02/03 bounded call-effect ordering regression

`HardwareCallEffects.summarize` now walks the recognized direct-call
subgraph in **breadth-first order** so a first encounter by a longer
path at the depth limit cannot suppress a possible STORE or MOVEC VBR
in a second, shorter path. A separate cycle check over the bounded
observed graph still distinguishes genuine loops from convergent
diamond joins. Missing targets, unknown flow and depth/node limits
remain explicit. The worklist prevents stack overflow on deep call
chains. No state is propagated between functions: this is only
possible-source-effect collection, never runtime order or physical
MCU behavior.

## 2026-11-05 — RESET completeness propagated into vector rows

The vector/RESET correlation has **two independent evidence horizons**:
(1) whether RESET itself and its bounded call graph are established, and
(2) whether an individual vector target's transitive STORE/VBR subtree
contains unknown calls, recursion or caps. An independently closed
per-vector subtree cannot establish a reliable RESET relationship if the
RESET root is missing or its own graph is truncated.

For this reason, `Row.flowUncertain` is now true whenever either
`resetRootRecognized=false` or `resetGraphIncomplete=true`, even if the
vector's local effect summary has no unknowns. Static relation labels,
vector counts and candidate STORE/VBR effects are unchanged; this flag is
not an execution trace or an ISR activation result. Deterministic Java21
regressions cover both image-zero and relocated candidate tables, a
missing RESET root, and retained local effects/counters.

## 2026-11-05 — bounded source inventory and per-handler summary reuse

The same exact function entry can be pointed to by multiple numbered
vector slots. `HardwareVectorResetCorrelation` now evaluates the bounded
read-only STORE/MOVEC call effects of such a function **once per report**
and reuses the immutable summary for every matching vector row.
This memo is never persisted, shared across different Ghidra Programs,
revision changes, or source-table provenance. It does not merge the slots:
each still contributes its own vector number, exact-entry count and
RESET relation.

The source gate checks at most 254 recognized vector slots (2..255),
50,000 source graph nodes, 50,000 observed RESET entries and refuses
null/negative RESET entries or null vector targets with an explicit input
error before sorting or building effects. Java21 tests cover repeated
handler targets, ordering invariance and malformed/oversized data;
full Ghidra 12.1.4 PUBLIC/Java25 build and real synthetic headless
regressions remain required on the exact PR SHA.

This is bounded static source correlation only; no active VBR/IRQ,
executable CALL ordering, MM latch or ECU411 runtime effect is inferred.


## 2026-11-10 — typed handler-rooted STORE/MOVEC and uncertainty witnesses

The vector/RESET report previously displayed only the transitive
`STATIC_CANDIDATE` or `UNKNOWN` effect flags per exact vector handler.
The underlying bounded CALL subtree now preserves deterministic **shortest
function-entry chains** to a modeled generic P-code `MEMORY_STORE` or
`MOVEC_VBR` source. Separate typed paths identify an actually inspected
`UNKNOWN_FLOW` or missing direct-call function
(`MISSING_TARGET`) and an independently **uninspected**
`DEPTH_CUTOFF` or `NODE_CUTOFF` frontier.

The same `HardwareCallEffects.inspect` traversal computes both the old
boolean `Summary` and the new `Detailed` typed witnesses in one
bounded BFS. `summarize` retains its historical signature and conservative
flags. The shortest source chains are canonical by hop count and numeric
function-entry order, not Ghidra reference order; only displayed
vector slots evaluate transitive effects and repeated handler entries share
the same read-only per-report result. All numerical vector counts still
cover the whole bounded input inventory.

A pointer into a function **interior** receives no whole-function
source path. If a candidate handler's function body is missing from the
bounded graph, its path is labeled `MISSING_TARGET`, never a zero-effect
proof. A possible STORE beyond depth/node budget is `UNKNOWN` and has a
typed frontier. Actual unknown control in one sibling and an uninspected
potential STORE in another are shown independently. Recursion-only
uncertainty never invents a missing callee. Report paths are function
entry candidates, **not decoded instruction traces or runtime proof**.

The additional source fields do not infer MCU identity from generic CPU32,
actual RESET execution, an active VBR, ISR execution, a latched SIMCR MM
value, bus/CS physical mapping, or Review/Apply approval. No on-disk
checkpoint or original firmware is mutated.

Java21 synthetic regression checks short and long convergent paths, valid
deep chains without recursion overflow, direct store/VBR, missing source
versus uninspected frontier, independently observed unknown plus frontier,
cycles, input reordering, source record forgery, interior function pointers
and vector-row display caps. Java25 full Ghidra 12.1.4 PUBLIC extension
build, real isolated synthetic headless/vector correlation and existing
Actions security gates are required on the exact final PR SHA.
GA-01/02/03/11/18 remain PARTIAL.
