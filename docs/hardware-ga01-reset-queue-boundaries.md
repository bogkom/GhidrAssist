# GA-01 — bounded RESET call queue with source-only cycle detection

The RESET-rooted static CALL inventory is a MAY-path source graph, not a
firmware execution trace. Earlier, the BFS queue was limited only by
**examined** functions. Thousands of convergent CALL edges could repeatedly
queue the same destination and allocate path copies before the visited cap
was enforced.

The revised traversal schedules **at most one queue entry per distinct
destination**. The pending queue is bounded by the requested `maxNodes`
(1..10,000), with a fixed maximum depth (32) and evidence display cap
(1,000). Accepted input is bounded to 50,000 source nodes and 200,000
CALL edges. A newly discovered edge after capacity is exhausted sets
`truncated=true` and `unresolved=true`; skipped nodes never imply that
no hardware STORE/VBR candidate exists.

Since a deduplicated shortest-path tree does not itself reveal all cycles,
the observed known-node graph is checked separately with a nonrecursive
Kahn-style indegree scan. Thus a convergent diamond or duplicated direct
CALL is **not** recursion; a real source CALL backedge is marked
`recursive=true` and `unresolved=true`. This is still source-level,
conditional recursion, not proof of a runtime recursive execution.

Deterministic Java21 tests cover 12,000 duplicate CALL destinations,
a 5,000-destination fan-out with a late hardware write beyond the cap,
cross-edge cycles, acyclic diamond/duplicate edges, and invalid budgets.
CI also builds the full Ghidra 12.1.4 PUBLIC extension on Java25 and
runs existing real isolated synthetic Ghidra headless regressions.
No original ECU411 firmware, working Ghidra Program, profile, OAuth or
stopped Wyse/Precision/legacy Supervisor tests are involved.
