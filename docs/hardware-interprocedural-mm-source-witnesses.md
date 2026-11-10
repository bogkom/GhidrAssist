# GA-02/03 — bounded interprocedural SIMCR/MM source witnesses

This change records **one shortest deterministic source-only function chain**
for each observed transitive candidate: modeled MM source, uncertain memory
alias, and unknown control-flow/frontier. These witness paths supplement the
existing conservative `mayMm`, `unknownAlias`, `unknownControl`, `cycle`,
`limited` and `visited` flags; they **never** convert a negative bounded
search into proof of no initialization.

- Paths use canonically sorted CALL target adjacency. The shared
  `HardwareCallEffects.FunctionNode` now normalizes target identities
  at construction for both bounded CALL-effect summaries and RESET
  candidate paths; duplicate references are retained, but do not consume
  unique-node capacity. Before this extension the RESET path for a
  converging graph or a bounded subset could depend on Ghidra's reference
  enumeration order. Canonical order is NOT execution order.
- Paths use only the pre-existing canonical CALL target graph. Their
  addresses are function entries, **not** instruction PCs. Each path starts
  at the queried callee, not the caller's CALL instruction. A witness does
  not certify execution, a feasible CFG path, cross-CALL register values,
  a latched SIMCR MM bit, VBR activity, an ISR, or hardware bus mapping.
- The BFS parent tree contains one pointer per uniquely scheduled target,
  bounded by the existing 10,000-node per-source and 16,384-node batch
  budgets. Witness construction is bounded by the 32-edge traversal depth,
  plus at most one unscheduled frontier target (34 addresses total).
  No recursion, new database writes, disk serialization or authentication.
- `MM_SOURCE`, `STORE_ALIAS` and `UNKNOWN_FLOW` are observed properties
  of visited function nodes; `MISSING_TARGET` is a scheduled unrecognized
  source; `DEPTH_CUTOFF`, `NODE_CUTOFF`, `BATCH_CUTOFF` identify a
  potentially unvisited endpoint. An omitted endpoint is never labeled a
  modeled MM STORE. A wholly unresolved indirect CALL has no known chain.
- A detected cycle alone may set `unknownControl` with no `unknownWitness`;
  the `cycle=true` flag remains the authoritative source uncertainty.
  `NONE` in the presentation therefore does not negate an uncertainty flag.
  Every visible CALL row retains its original ordering and cap treatment.
- Source nodes can have multiple possible MM/alias/flow paths. Only the
  shortest canonically selected witness per category is shown. It is a
  reproducible counterexample to a closed negative claim, not a complete
  inventory of all sources.

Deterministic Java21 tests also include two independent RESET/CallEffects
lanes: reversed target and function inventory order, a convergent RESET
path and a truncated budget where a higher-address STORE remains UNKNOWN,
plus the corresponding uncapped positive control.

Deterministic Java21 tests cover converging paths, competing MM sources,
independent alias/unknown witnesses, reversed source enumeration, duplicate
targets, missing nodes, depth/node/batch limits, a cycle without source
fabrication, malformed source-witness construction and a 6,500-node wide
graph. GitHub Actions must additionally pass the complete Ghidra 12.1.4
PUBLIC / Java25 extension build and isolated synthetic headless regressions.

GA-02/03 remain PARTIAL. No original ECU411 firmware, production Ghidra
project, local profile/OAuth, or stopped Wyse/Precision/Supervisor tests.


## 2026-11-10 — independent observed UNKNOWN and skipped-frontier witnesses

The initial source report had only `unknownWitness`. When an earlier BFS
sibling reached a depth/node/batch cutoff before another queued sibling
showed `UNKNOWN_FLOW` or an absent function, that single witness could
misrepresent the **shorter actually inspected uncertainty** as an
uninspected endpoint. This did not clear the existing UNKNOWN/LIMITED
flags but obscured actionable provenance.

The report now carries **two distinct, bounded views**. The primary
`unknownWitness` selects the earliest shortest observed `UNKNOWN_FLOW`
or `MISSING_TARGET` chain whenever one exists; otherwise it retains the
first cutoff for backward-compatible clients. The independent
`frontierWitness` always retains the first canonical
`DEPTH_CUTOFF`, `NODE_CUTOFF` or `BATCH_CUTOFF` chain, even when
an observed unknown chain also exists. Each is independently typed;
malformed or self-contradictory combined evidence is rejected. BFS node
ordering plus numerically canonical adjacency makes both reproducible,
and there is no extra graph traversal or budget. A frontier chain's
last address was **not inspected as a source**. A missing target was
scheduled and checked but had no matching recognized function. Both are
static evidence only, never instructions proved to execute.

Java21 adversarial tests exercise a shallower observed unknown after an
earlier deeper depth frontier; a separately missing function after the
same cutoff; NODE cutoff plus an inspected unknown; reversed source
enumeration; cutoff-only API compatibility; two malformed summary forms
and Markdown disclosure of both paths. The existing exact-head Ghidra
12.1.4 PUBLIC Java25 build and synthetic headless Actions remain the
integration gates. GA-02/03/18 remain PARTIAL.


## 2026-11-10 — computed JSR reports use the same bounded typed chains

`HardwareIndirectMmMay` now displays all four source categories
from its existing target-rooted `HardwareInterproceduralMmEffects`
summary, rather than reducing the result to effect/unknown flags.
Its report record checks that every nonempty chain begins at the
byte-witnessed indirect target (not the caller) and rejects repeated
decoded JSR PCs. A true UNKNOWN_FLOW or checked missing function is
presented independently of an uninspected cutoff; cycles without
observed unknown nodes do not invent a chain. This remains static
candidate connectivity, with no direct/RESET/ISR edge promotion,
runtime write-order or original firmware manipulation.

The GA-01/11 co-location join also rejects overlapping decoded JSR and
MOVEC site PCs across the two otherwise individually valid source lists.
Independent Java21 tests and complete Java25 Ghidra 12.1.4 PUBLIC
synthetic headless tests remain the exact-SHA merge gates.
