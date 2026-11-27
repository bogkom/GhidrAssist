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
