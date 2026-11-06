# GA-01/02/03/11 — computed CALL references cannot create direct RESET/MMIO/ISR edges

Status: **CI candidate**, 2026-11-06. Base: protected `master`
`4580d07412c3417df65be5a6a70ac28fc1a0d07f`.

## Problem

Ghidra's source instruction `getFlows()` can contain references created by
a user or analysis. The existing GhidrAssist flow service first marked a
computed `JSR (An)` as uncertain, but then separately used the number of
`getFlows()` targets to decide whether to append a **direct** callee to
`staticCalls` and `mmCallSites`. If an indirect call had one reference
to a function, that reference could be treated as a trusted direct CALL
edge, incorrectly promoting transitive STORE, VBR, RESET and ISR evidence.

That matters even if `unresolvedFlow=true`: an additional **positive**
reachable graph edge is false static evidence, not just a confidence warning.

## Implementation and boundary

A new pure Java21 `HardwareDirectCallGate.directCandidate` requires
**all** conditions: a decoded CALL instruction, a decoded **non-computed**
flow type, and **exactly one** Ghidra flow target. Production still
requires the destination to be an exact recognized Ghidra function entry.

- `JSR (An)` with a user-defined `RefType.COMPUTED_CALL` reference:
  `UNKNOWN` callee and no graph edge even when the reference points to a
  real function and `getFlows()` yields exactly one target.
- Byte-proven bounded `MOVEA.L #imm,An; ...; JSR (An)` remains a
  **display-only** source possibility through the existing
  `HardwareIndirectCallEvidence` and Automation API validator. It is
  not a direct global RESET or MMIO path, nor a checkpoint or Apply right.
- Genuine decoded direct `JSR absolute` and exactly recognized targets
  retain their previous static candidate behavior.
- Unknown computed CALL keeps `uncertainFlow` and `mmCallSites` with
  null targets; `HardwareInterproceduralMmEffects` reports unknown
  callee/flow. RESET source reachable nodes cannot include the untrusted
  callee, and VBR/ISR vector correlation remains source-only/uncertain.
- Generic CPU32 has no implicit MC68332 register map. Nothing is taken
  as proof of an executed call, latched MM, active VBR/ISR or physical
  chip-select bus mapping.

## Deterministic CI evidence

Java21 `HardwareDirectCallGateSelfTest` exercises computed/direct/
non-CALL status with zero, single and multiple XREF counts. It proves,
using synthetic `HardwareResetFlow`, `HardwareCallEffects`,
`HardwareInterproceduralMmEffects` and
`HardwareVectorResetCorrelation`, that a false computed edge would
fabricate RESET-reachable MMIO/VBR/ISR, while the correct case retains
an explicit UNKNOWN and direct-JSR control.

The real isolated Ghidra **12.1.4 PUBLIC / Java25** fixture
`indirect-reset-xref` creates actual disassembled CPU32 instructions:

- `0x600: JSR 0x700; RTS` — genuine direct call.
- `0x680: JSR (A1); RTS` — computed and register value unknown.
- `0x700: MOVE.W #0x40CA,(0x00FFFA00).L; RTS` — source MMIO leaf.
- A `USER_DEFINED COMPUTED_CALL` XREF at `0x680 -> 0x700`, plus
  a candidate image-zero vector #26 to the leaf `0x700`.
- Switch image-zero RESET PC from `0x600` (positive static graph)
  to `0x680` (unknown computed flow, leaf not RESET-reachable).
  Check interprocedural MM unknown, vector relation, exact Program
  revision unchanged during Analyze and conservative repeated cache.

The workflow builds the full extension from a **SHA-pinned** official
Ghidra 12.1.4 PUBLIC zip, runs the real synthetic Ghidra and records
extension/harness SHA-256. Java21 gate runs independently.

## Remaining limitations

A source CALL graph remains a bounded static hypothesis, not proof of
feasible branches or actual execution. A computed call may in fact
target `0x700` at runtime, but without the required source proof it
cannot be promoted to the **direct** graph. Indirect target-specific,
isolated MAY edges require a separately designed provenance model.
Unknown indirect CALLs, tail jumps, source caps, MM latch, VBR relocation,
interrupt state and physical bus configuration remain UNKNOWN.

No original ECU411 firmware/project, user profile, OAuth, stopped
Wyse/Precision/legacy Supervisor, or model-based tests are involved.
