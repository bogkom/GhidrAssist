# GA-02/03/11 — bounded scheduled CALL frontier in effect inventories

`HardwareCallEffects.summarize` reports possible transitive P-code
memory STORE and MOVEC/VBR effects from decoded direct-call targets.
These are static candidates, not a feasible execution trace.

Before this change, `maxFunctions` constrained **visited** functions
but not targets already placed on the BFS queue. A single high-fanout
function could schedule thousands of destinations with a tiny requested
budget, and later effects could be silently omitted. The same type
of defect had already been addressed for a different GA-02/03 callsite
analyzer; this patch covers the separate generic effect inventory
consumed by vector/RESET correlation.

Scheduling now uses the same `maxFunctions` cap as completed visits.
A distinct queued target beyond the cap sets
`truncated=true, unresolved=true` — no negative STORE/VBR conclusion.
Repeated edges to an already scheduled function consume no additional
capacity. Unknown missing callees remain `unresolved=true`.
Collection input is capped at 50,000 functions and 200,000 edges,
and caller-supplied bounds are explicit; all cycle checks remain
nonrecursive and do not mistake a convergent diamond for recursion.

Java21 deterministic regression verifies wide unique fanout,
12,000 duplicate direct edges, thousands of missing targets and
invalid budgets. Full Ghidra 12.1.4 PUBLIC/Java25 extension build
and isolated real synthetic-Ghidra regressions are required on the
exact PR SHA. No active VBR/IRQ, real MM state, hardware bus mapping
or ECU411 behavior is established by these read-only source effects.
