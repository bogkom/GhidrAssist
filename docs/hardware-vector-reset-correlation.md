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


## 2026-11-10 — selected MC68332 exact-vector SIMCR/MM MAY root correlation

The previous vector/RESET source report identified transitive generic P-code
`MEMORY_STORE`, which is **not** a device-specific SIMCR/MM hit. The
existing `HardwareInterproceduralMmEffects` analysis already models
potential STORE overlap with the MC68332 SIMCR/MM **low byte**, including
unresolved STORE aliases/widths, missing targets and bounded function
witnesses. That source graph was not correlated with handler candidates.

The new read-only `HardwareVectorMmMayCorrelation` section joins **only
exact-entry vector pointers** to independently observed MC68332
SIMCR/MM MAY source summaries. The source solver now accepts bounded
function-entry `inspectRoots` directly rather than fabricating a
CALL-site instruction PC for each vector pointer. Both source inventories
were gathered from the SAME Program analysis. The result exposes:
`STATIC_MAY_MM_LOW_BYTE`, `UNKNOWN` or
`NOT_OBSERVED_IN_BOUNDED_SOURCE`; independent typed shortest
`MM_SOURCE`, `STORE_ALIAS`, observed
`UNKNOWN_FLOW`/`MISSING_TARGET` and uninspected
`DEPTH_CUTOFF`/`NODE_CUTOFF`/`BATCH_CUTOFF` function chains;
cycle/limit flags and bounded inspected function counts.
A generic STORE elsewhere in the handler subtree does not create a
SIMCR/MM candidate.

The service appends this section separately to BOTH the image-zero
vector scan and each scanned candidate relocated MOVEC-to-VBR table,
**only if MC68332 was explicitly selected**. Generic CPU32 retains
its existing 32-bit pointer survey and never receives device-specific
SIMCR/MM semantics. Existing `GhidraInterruptVectorService` overloads
remain compatible; the new optional source graph is provided by the
full Hardware Analysis path.

A maximum of 32 image-zero (12 per relocated table) displayed exact
handler slots receive detailed source inspection. Duplicate vector
slots sharing one exact handler reuse one revision-local summary; at
most 100 functions per handler and four direct CALL hops are examined.
The full validated vector slot inventory is counted, including
interior pointers (which never inherit full-function effects) and
uninspected overflow rows. Source roots are canonically ordered and
share a bounded aggregate solver budget. The report explicitly labels
partial display/analysis and separates the independent RESET graph
confidence horizon.

An image-zero vector or relocated source table is NOT an active
interrupt vector, proven VBR value, executed ISR, feasible CALL route,
latched SIMCR/MM first write, or physical chip-select mapping. The
model does not propagate register values across unresolved CALLs, does
not promote computed CALLs into direct RESET/ISR edges, never writes to
the Program and never grants Review/Apply/Undo permission.
Deterministic Java21 source-only regressions include duplicate exact
targets, missing bodies, alias/unknown/cycles, depth/row caps, 24-bit
MCU boundaries and input reordering. Genuine Ghidra 12.1.4 PUBLIC
headless synthetic integration checks selected/generic image-zero and
relocated reports on exact CI SHA. GA-01/02/03/11/18 remain PARTIAL.

## 2026-11-10 — independent RESET/MM uncertainty and bounded report authenticity

The selected-device vector-handler source report previously set its
`RESET uncertain` row flag when the *handler's* SIMCR/MM source subtree
had an unknown alias, unresolved CALL or cycle, even if the independent
RESET root and direct-CALL graph were complete. It now derives that flag
**only** from RESET recognition and RESET graph completeness. A separate
`MM source uncertain` column reports local aliases, unresolved flow,
cycles and depth/node/batch cutoffs; an MM MAY can coexist with this
uncertainty without changing the RESET relationship. An incomplete RESET
graph likewise cannot invent a local MM source.

The report also gives **displayed-only** MAY/UNKNOWN/NOT_OBSERVED
classification counts. These are explicitly not totals over all 254
possible vector slots; undisplayed exact handlers remain unanalyzed.
Public source row/report constructors now reject contradictory classes,
misrooted or malformed typed paths, inconsistent RESET confidence,
duplicate/out-of-order row slots and falsified distinct-root counts.
Canonical bounded witness text cannot inject Markdown table cells.
The core root solver, source graph, display/inspection budget, 24-bit
selected-MC68332 target gate, and prior public entry points are unchanged.

Java21 negative and independent-confidence regression, Java25 full
extension compilation and genuine Ghidra 12.1.4 PUBLIC synthetic vector
integration are required on the exact final PR SHA. These checks are
static evidence bookkeeping, not VBR selection, executed interrupts,
reachable hardware effects, latched SIMCR MM or authorization to Apply.

## 2026-11-10 — bounded generic CPU32 vector/RESET evidence row integrity

Generic CPU32 vector/RESET source-image reports now validate their public
`Row` and `Summary` boundaries, not only their producer's iterator:
syntactically bounded canonical typed function-entry source paths must be
rooted at the exact handler entry, with no newline/table-cell injection;
a labeled observed source cannot accompany a closed negative effect.
Interior pointers remain UNKNOWN without inheriting source paths. A
missing RESET root cannot falsely assert confident direct-CALL reachability.

The full 254-slot input inventory, exact/interior split, RESET shared and
outside counts, ordered distinct vector slots, read-only bounded display
and report-level source confidence must agree. Null, incorrect, noncanonical
or implausibly oversized report cells fail closed. The historical
seven-field `Row` constructor remains available with `NONE` typed paths.
New **displayed-only** STORE and MOVEC/VBR candidate counters distinguish
analyzed exact-handler rows from undisplayed vector inventory; neither is
a total count of source candidates across the complete vector table.

This generic CPU32 source view intentionally does NOT assign MC68332
SIMCR/MM bit meaning or reinterpret 32-bit pointers as MC68332 24-bit.
The earlier selected-MC68332 **independent** RESET/MM confidence report
is retained. Java21 adversarial regression, Java25 full extension build
and genuine isolated Ghidra 12.1.4 PUBLIC synthetic vector integration
are required at exact PR SHA. Neither vector pointer, RESET static
reachability, STORE nor MOVEC is a runtime execution, latched MM,
active VBR/IRQ, ISR dispatch or physical chip-select mapping.

The displayed-only STORE/MOVEC counters count **vector rows**, not unique
handler function identities: two vector slots pointing to the same
handler legitimately contribute two rows, while its bounded source
analysis remains cached once per revision-local report.
