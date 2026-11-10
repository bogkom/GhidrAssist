# GA-02/03 — bounded interprocedural SIMCR/MM source witnesses

This change records **one shortest deterministic source-only function chain**
for each observed transitive candidate: modeled MM source, uncertain memory
alias, and unknown control-flow/frontier. These witness paths supplement the
existing conservative `mayMm`, `unknownAlias`, `unknownControl`, `cycle`,
`limited` and `visited` flags; they **never** convert a negative bounded
search into proof of no initialization.

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

Deterministic Java21 tests cover converging paths, competing MM sources,
independent alias/unknown witnesses, reversed source enumeration, duplicate
targets, missing nodes, depth/node/batch limits, a cycle without source
fabrication, malformed source-witness construction and a 6,500-node wide
graph. GitHub Actions must additionally pass the complete Ghidra 12.1.4
PUBLIC / Java25 extension build and isolated synthetic headless regressions.

GA-02/03 remain PARTIAL. No original ECU411 firmware, production Ghidra
project, local profile/OAuth, or stopped Wyse/Precision/Supervisor tests.
