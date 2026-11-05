# GA-02/03 — conservative adjacent CPU32 indirect JSR source provenance

## Scope

The Automation API call-path service already validates a strictly adjacent
CPU32 instruction pair from the original instruction bytes:

```
MOVEA.L #<exact function entry>,An
JSR     (An)
```

The Ghidra 12.1.4 PUBLIC hardware report previously treated all computed
CALLs as UNKNOWN, and so did not display this *narrow, independently
verified source* at all. Reimplementing another MOVEA/JSR decoder would
risk diverging from the already-tested Automation API.

The existing `AutomationCallPaths.adjacentConstantRegisterCall` verifier
is now publicly reusable by the hardware report. It returns a target
**only** for the exact 6-byte MOVEA.L immediate followed immediately by
the 2-byte `JSR (An)` to the same address register on
`68000:BE:32:CPU32`, and only when Ghidra has already defined an
**exact target Function entry**. The hardware caller additionally
requires both instructions within one caller Function body and all
evidence addresses within the 24-bit MC68332 source range.

## Read-only evidence and safety

A new bounded `HardwareIndirectCallEvidence` section contains the
caller entry, MOVEA instruction, computed JSR PC, candidate exact target
and explicit `adjacent_movea_immediate` provenance. It limits display
to 96 sources and counts omitted candidates. Every nonmatching computed
CALL remains UNKNOWN. Results are sorted, unique by CALL PC, and are
never promoted to a direct CALL graph edge, transitive RESET proof,
GA-12 checkpoint, MCU MM-latch claim, or Review/Apply operation.
The source predicate itself does not imply an executed instruction.

A Java 21 deterministic regression checks bounded source rows,
deterministic ordering, duplicate/bad input, unknown and cap evidence.
A separate **real synthetic Ghidra 12.1.4 PUBLIC/Java25** fixture
tests actual bytecode for:

- an adjacent `MOVEA.L #0x700,A0; JSR (A0)` pointing to a
  defined function containing a candidate SIMCR source STORE;
- an uninitialized `JSR (A1)`;
- `MOVEA.L #0x700,A1; JSR (A0)` (register mismatch);
- `MOVEA.L #0x720,A0; JSR (A0)` (no exact target Function).

The fixture also checks computed-call decoding, no promotion into
Apply-eligible CFG sources, unchanged Program modification number,
repeat determinism and the explicit MC68332 profile gate. The GitHub
Actions workflow pins Ghidra release SHA-256, Java25, extension
packaging and tested harness hashes.

No original ECU411 firmware, user Ghidra project/profile or stopped
Wyse/Precision/Supervisor infrastructure is touched.

## Remaining gaps

Computed CALLs beyond the exact adjacent immediate form, including
branch-dependent addresses, memory-loaded vectors, address-register
arithmetic and nonadjacent provenance, remain UNKNOWN. This patch does
not enable any implicit cross-function dataflow or prove that the
24-bit CPU32 logical address corresponds to a physical chip-select.

## 2026-11-05 — additional bounded source paths (GA-02/03)

The Automation API had already implemented a more general **strictly
straight-line** CPU32 fall-back for `JSR (An)`: walk back no more than
four decoded instruction boundaries to a `MOVEA.L #<exact entry>,An`,
allowing only zero to three interposed `NOP` and/or `MOVEQ #imm,Dn`
instructions (both leave An intact). The hardware report previously
showed only the adjacent pair. It now reuses the same original byte
checker, with an **additional Function-body containment requirement for
every instruction** in the traced source chain. It never speculates
through branches, memory loads, ADDQ/CLR, arbitrary register writes,
or missing exact target Functions.

The report preserves three distinct source labels:
`adjacent_movea_immediate`, `bounded_movea_nop_chain` and
`bounded_movea_safe_chain`. Strictly bounded, sorted and unique
display rows include MOVEA PC, JSR PC, target and provenance.
Unresolved, over-budget and uninspected calls remain UNKNOWN.
These are **possible static source paths**, not guaranteed or executed
dispatch, and remain outside direct CALL graph, RESET reachability,
MC68332 active MM latch and all Review/Apply/Undo decisions.

A dedicated real synthetic Ghidra 12.1.4 PUBLIC/Java25 fixture
decodes bytecode for both allowed chains and negative controls
(unsupported CLR.L, mismatched A1/A0, absent exact Function).
It checks all per-source evidence, unchanged Program revision,
repeat determinism, generic CPU32 gate and non-promotion to Apply.
Java21 independently verifies allowed label integrity and output
bounds. Existing adjacent source and Automation API call-path
regressions must remain green on the exact PR SHA.
