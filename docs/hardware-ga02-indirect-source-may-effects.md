# GA-02/03/11 — bounded MAY effects for byte-witnessed indirect CALLs

Status: **candidate until exact-SHA CI PASS**, 2026-11-06.
Base protected `master` `9fe79e53bbfd98c5357ea5286fde12946375f640`,
after directly safety-tested PR #185.

## Scope

`HardwareIndirectCallEvidence` already displays source candidates
where the shared Automation API verifier has matched **actual CPU32
instruction bytes**: `MOVEA.L #imm,An`, at most three supported
`NOP/MOVEQ` instructions, and `JSR (same An)` targeting an
exact recognized function entry. Such a witness is NOT the same as
a direct CALL and is not proof of actual execution or feasible
branch conditions.

A new independent **read-only** `HardwareIndirectMayEffects`
joins *only the already collected* bounded witnesses with the
existing static `HardwareCallEffects` inventory for their target.
The section states whether a target's bounded static CALL subtree
contains a **modeled Listing/P-code memory write** or a candidate
VBR write. Ghidra 12.1.4 can represent direct absolute-address
`MOVE.W #imm,(addr).L` as a P-code `COPY` to a memory varnode
rather than a `PcodeOp.STORE`; the production flow service now
counts its existing `HardwareDataflow.STORE_DIRECT/INDIRECT`
translation too. Otherwise the source graph could falsely report
no memory write for a real decoded direct SIMCR store.
The result is **MAY** for the witnessed source (not for runtime),
and a memory STORE is **not necessarily MMIO**.

- No mutation of `staticCalls`, `HardwareResetFlow` reachability,
  `mmCallSites`, vector correlation, Ghidra Program, Apply/Undo,
  revision, durable stages or automation control state.
- Explicit MC68332 profile selection is required in the Hardware
  Analysis integration; generic CPU32 does not inherit device MMIO.
- At most **16** witnesses get a transitive effect computation;
  all extra witness rows have an explicit omitted count. An absent
  witness is not an absent computed CALL.
- The transitive inventory is bounded to **4 CALL levels and
  100 inspected functions** per distinct target, with per-invocation
  reuse for duplicate targets (never a cross-revision cache).
- Missing function, source graph gap, depth/node limit and cycle
  never make an unconditional no-effect claim:
  `UNKNOWN` is different from
  `NOT_OBSERVED_IN_BOUNDED_SOURCE`. A possible STORE/VBR is
  reported as `STATIC_MAY_CANDIDATE` even if other paths are
  uncertain; such a candidate still does not prove a write executed.

## Regression

Independent Java21 tests cover a source witness to a memory/VBR
leaf, no false RESET graph reachability, ordinary closed source
without observed effect, unknown targets, unknown inner CALLs,
cycles with positive MAY-VBR, depth truncation, duplicate target,
source sorting and immutable rows, cap/omission, bad inputs.

The **existing real isolated Ghidra 12.1.4 PUBLIC/Java25**
fixtures `indirect-adjacent` and `indirect-bounded` now assert
an additional MAY-effect section. Genuine CPU32 byte-witnessed
`JSR (A0)` points to a local SIMCR-writing function `0x700`:
the section may report a memory STORE while the direct RESET
graph remains unchanged. An unknown `JSR (A1)` with a
user-inserted `COMPUTED_CALL` XREF cannot create a witness or
a positive MAY row. Nonconforming source sequences remain
UNKNOWN, and no Ghidra project writes occur during Analyze.

A dedicated source-only GitHub workflow runs the Java21 gate.
Existing exact-SHA real synthetic headless workflows and full
extension compilation must remain green before integration.

## Evidence limitations

None of this proves a runtime JSR, RESET path, valid stack,
actual SIMCR/MM write, active VBR/ISR, interrupt enable,
physical chip-select configuration, or verified MCU profile
import. This report has no Review/Apply/Undo authority.
Unknown indirect CALL sites outside the bounded verifier
remain UNKNOWN. No original ECU411 firmware/projects,
Wyse/Precision, stopped Supervisor or AI-model tests used.
