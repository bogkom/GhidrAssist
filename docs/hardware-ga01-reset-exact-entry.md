# GA-01/02/03/11 — RESET vector must be an exact function entry

Status: **candidate, pending exact-SHA GitHub Actions**; baseline protected
`master` `8454e54d26fa49eb23ab40ce1174641261429cb7`.

## Confirmed source-level problem

`GhidraHardwareFlowService.resetStaticCandidates` previously called
`getFunctionContaining(vector.resetPc())` and unconditionally fed the
**containing function's ENTRY** to `HardwareResetFlow.trace`.
When the RESET vector points into the **interior** of that function, the
prefix preceding the vector PC is *not* reachable by simply starting
execution at that vector. The old code could nevertheless classify a
`JSR` in this earlier prefix as a possible RESET initialization path,
and correlate its potential MMIO STORE or VBR effects to RESET/ISR.

This is not resolved by marking the whole execution as "candidate only":
it incorrectly assigns even **static reachability**.

## Fail-closed policy

- When the image-zero reset vector PC is exactly the recognized Ghidra
  function entry (valid even address), retain the original bounded
  source-only RESET graph and vector correlation.
- When the vector PC is inside a recognized function body **but not equal
  to the function entry**, report
  `UNKNOWN RESET ROOT — INTERIOR FUNCTION POINTER`.
  Keep the containing function identity for an operator, but do **not**
  traverse its earlier prefix, manufacture an alternate function entry,
  or claim any of its CALL descendants were reached from RESET.
- The resulting RESET root status is unrecognized, direct-call visited set
  empty, graph incomplete. GA-11 vector and candidate VBR correlation
  therefore retain `RESET_ROOT_UNKNOWN` rather than inheriting a
  possibly false reachable CALL subtree.
- Missing/unreadable vector, invalid PC, absent function and generic
  non-68000 language continue to fail closed as before.
- No write, disassembly, function definition, automatic repair or
  Review/Apply/Undo operation is triggered by production Analyze.

## Deterministic verification

The Java21 `HardwareResetFlowSelfTest` covers exact vs interior, odd
and invalid 32-bit vector/entry coordinates and demonstrates the false
positive if an interior address is rounded backward to a CALL-bearing
function entry.

The Ghidra 12.1.4 PUBLIC/Java25 isolated real synthetic headless test
`reset-interior` creates in a throwaway Program:

- A recognized MMIO-writing leaf at `0x500`.
- A CPU32 function at `0x620` containing `JSR 0x500` followed by
  `RTS` at `0x626` (both **real Ghidra-decoded**).
- RESET vector PC `0x620` exact -> original static CALL relation to
  `0x500` remains (positive control).
- Same Program RESET vector PC `0x626` interior -> no falsely reached
  `0x500` or `0x620`, no recognized RESET root, and explicitly
  unknown GA-11 vector relation.
- Same-revision replay does not resurrect the previous root; report
  revision stays unchanged during read-only analysis. Replay assertions
  compare the **RESET candidate set, root/unknown status and vector
  relation**, not the entire report text: valid GA-12 computed-vs-reused
  cache counters can differ while the source evidence stays identical.

The workflow builds the full extension using SHA-verified Ghidra
12.1.4 PUBLIC and Java25; a Java21 standalone test is separate.
Artifacts include the synthetic report, extension and harness SHA-256
receipts. No user/project firmware, Wyse/Precision, Supervisor timer,
AI model or production Ghidra profile is used.

## Limitations

Even an **exact** Ghidra function entry remains only a static source
candidate: it does not prove ROM was mapped at reset, the PC was
executed, branches were feasible, SIMCR/MM latched, VBR selected,
interrupts fired, nor external CS wiring. An interior RESET PC could
be a valid executable address in real hardware, but the analysis lacks
a safe source-sliced CALL graph rooted exactly there; it stays UNKNOWN
rather than falsely assuming the whole containing function runs.
