# GA-01/02/03 — modeled CFG write-path relations

This dependency on PR #68 adds an optional, bounded and read-only
site-to-site path analysis for SIMCR, TRAMBAR and CSBAR/CSOR/CSPAR
**inside the same Ghidra function**.

The model examines actual translated Ghidra CFG successors.
For each pair of candidate write instructions it checks whether a
directed modeled path exists from A to B, B to A, both, or neither.
Cycles and budget limits are explicit. A search budget of 1500 visits
and a maximum of 12 stores per function cap cost. Function calls,
computed jumps, gaps and unknown branches stay unresolved; the
algorithm **does not** solve branch feasibility, prove that either
instruction ran, or infer a hardware reset-relative epoch. A missing
modeled path never proves execution impossible.

This is not a register state transfer. In particular the write-once
SIMCR MM latch and simultaneously active CS windows remain UNKNOWN.
The generic CPU32 report avoids naming MC68332 registers as if the
MCU were identified.

This package has pure Java tests for branch forks, cycles, uncertain
gaps, iteration limits, duplicate sites and bounded reporting. Full
Ghidra 12.1.4 build and operator-approved real-Ghidra test on an
isolated project are required before merging.

## 2026-11-27 — local CFG owner and report-boundary hardening

The bounded model now requires an actual graph node at the selected function
entry; it rejects pre-entry instruction nodes, successors targeting pre-entry
code, and MMIO STORE sites unreachable from the function entry. All these
cases produce an empty, explicitly truncated/unknown report rather than a
falsely attributed path relation or an exception that aborts other functions.
Off-graph forward successors still flag uncertain flow; no claim about
runtime reachability, actual MM mode, or a physical bus map is introduced.

Untrusted register descriptions in the read-only Markdown display have
non-alphanumeric characters encoded and are bounded to 64 UTF-16 units
with an abbreviation indicator; raw evidence records are not changed.
Deterministic Java 21 tests cover positive ownership, missing entry, foreign
source/branch, orphaned STORE, budget limits, and adversarial label display.
Full Java 25 extension and genuine isolated Ghidra 12.1.4 PUBLIC CI must
pass at the exact commit before integration. GA-01/02/03/07 remain PARTIAL.


## 2026-11-27 — GA-02/03/12 source-bound CFG and sampled CALL evidence

The source CFG path analyzer now checks the total number of successor
references (200,000), raw STORE observations (50,000), and decoded
nodes (50,000) **before** entry reachability or pair searches. Public
node, successor and STORE coordinates must be unsigned CPU32 32-bit
values; invalid/null successors and oversized individual adjacency
lists are rejected rather than silently skipped. A valid generic CPU32
high address remains eligible; this check never asserts an MC68332
physical-bus alias.

Sampled CALL-site reconciliation verifies that the reported direct and
context-bearing CALL counts match its actual input inventory and that
each retained candidate's count of non-A7 source registers equals the
specific caller's predecessor-agreed input. A mismatch produces
`INCOMPLETE` with UNKNOWN address, word and width, **not** an
apparently unanimous MMIO source. Public sampled-agreement records
must retain two distinct matching CALL provenance receipts, identical
address, width and word candidates, and no source uncertainty; forged
known-address records are refused. All claims remain static MAY
candidates, never executed writes, active SIMCR/MM, VBR/ISR, physical
CS maps or Review/Apply instructions.

Deterministic Java 21 tests cover boundary caps, oversized hostile
graphs, invalid successor/STORE source coordinates, positive valid
high CPU32 paths, invented sampled counts, forged source-register
contexts, duplicate CALL provenance, and preserved clean agreement.
Require complete Java 25 Ghidra 12.1.4 PUBLIC build and isolated
synthetic Ghidra tests on the exact SHA. GA-02/03/12 remain PARTIAL.
