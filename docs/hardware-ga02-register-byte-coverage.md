# GA-02/03/06 — profile-width coverage of static CALL STORE candidates

Status: **candidate until CI PASS on exact PR SHA**, 2026-11-06.
Base: protected `master` `151c85fba07428d9427d5dcc27c4fff970b1ee34`.

## Problem and bounded scope

Previous GA-02/03 CALL lanes already preserve a source `STORE` whose known
8/16/32-bit extent touches the **base address** of a tracked MMIO register,
even if the STORE starts before it. That identifies a possible source alias,
but does **not** say whether one byte, the whole register, or multiple adjacent
registers are covered. Reporting only the starting address and STORE width
can invite a false full-register value interpretation.

The new **read-only** `HardwareRegisterByteCoverage` annotates only the
already-displayed one-hop and two-hop CALL candidates, and only after an
**explicit MC68332 profile** selection. It uses the register offset and 8/16/32
bit width from the current built-in profile for both potential 4 KiB
internal windows (MM0/MM1). It counts byte intersections on the modeled
24-bit address bus and labels each pair:

- `EXACT_BYTE_RANGE`: same start and byte count as the register interval.
- `SPANNING_WHOLE_REGISTER`: all documented register bytes touched, but
  STORE extends into neighboring bytes/registers.
- `PARTIAL_REGISTER`: only some of the register bytes touched.

An 8-bit write to `SIMCR+1` is thus `PARTIAL_REGISTER` (not a complete
16-bit SIMCR value); a 32-bit STORE at `0xFFFA66` intersects the two
16-bit `CSOR6` and `CSBAR7` intervals. A STORE at `SIMCR-2` can
span all of SIMCR without being an exact range match. Two registers
in the output do **not** mean two executed writes.

## Fail-closed properties

The new analysis has a hard cap of 128 source STORE rows and 256 printed
STORE/register intersections. Unknown source addresses/widths and known
addresses outside the built-in profiled ranges remain explicitly separate;
truncated display has a retained exact omission count. Null, foreign
25-bit addresses and generic `CPU32` profile cannot be promoted to an
MC68332 width assertion. Input is sorted for deterministic results.
No CALL target, source candidate, CFG state, source revision or cache key
is changed. The existing one-hop/two-hop unknown and omitted counts remain
authoritative; this is **not** a newly complete source-graph scan.

The profile's register widths and physical PDF page labels are **metadata
claims**, not independently authenticated manual or silicon facts.
The result never asserts a complete known register value, hardware accepting
a write (even for READ_ONLY registers), an activated MM bank, actual RESET or
CALL execution, interrupt activity, real chip-select bus mapping, or permission
for Review/Apply/Undo. It does not identify MC68332 from generic CPU32.

## Regression

`HardwareRegisterByteCoverageSelfTest` (Java 21) checks exact SIMCR
16-bit coverage, partial SIMCR MM byte, a spanning 32-bit STORE crossing
two adjacent CS registers, MC68332 MM0/MM1 alternatives, single-byte
SYPCR and READ_ONLY RSR metadata, unknown/foreign address and width gates,
bounded omission, input order, and consumption of both one-hop and two-hop
source candidates.

Existing real synthetically imported Ghidra 12.1.4 PUBLIC tests for
two-hop CALL additionally require deterministic width/page metadata in
the read-only report without generic CPU32 promotion or Ghidra project
mutation. Full Ghidra 12.1.4 PUBLIC / Java 25 extension build and
source-only Java21 tests must pass on the **exact new PR HEAD SHA**.

No private firmware, user settings, Wyse/Precision GUI, stopped legacy
Supervisor/timers or AI-model tests are used.
