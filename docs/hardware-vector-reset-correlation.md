# GA-01/02/03/11 — static correlation of RESET calls and image-zero vectors

Source-only functionality, added after the GA-18 API integration (2026-11-03).

The Ghidra Hardware Analysis full report already contains a bounded
RESET-rooted direct-call candidate subset, source-only memory STORE / MOVEC
VBR evidence, and image-zero 68000 exception/interrupt *pointer candidates*.
The new read-only correlation joins those observations by **exact recognized
Ghidra function entry**, rather than assuming vector pointers are invoked
handlers. It displays a separate table and uncapped counts for the observed
subset, with bounded detail. A pointer to an **interior address** is explicitly
not a recognized handler entry. A function outside the bounded subset is
**not** proved unreachable: indirect calls, dynamic branches, exception
paths, analysis gaps, and work budgets remain unknown.

Call-subtree effects use `HardwareCallEffects` (4 hops, 100 functions per
target) and mean only *possible static* P-code STORE or MOVEC VBR sights;
STORE may be non-MMIO. Recursive/unresolved/over-budget effects are labeled
UNKNOWN, never absence. Neither the image-zero vector candidates nor a
RESET call-tree overlap proves the **current VBR**, that an IRQ occurred,
feasible execution order, SIMCR MM write-once latch value, chip-select
hardware mapping or firmware execution.

Sources: `HardwareResetFlow`, `HardwareCallEffects`,
`HardwareInterruptVectors`, new `HardwareVectorResetCorrelation`.
No data type, symbol, memory, review/apply decision, ECU411 project or binary
is changed.

## Evidence and acceptance

- Pure Java 21 adversarial tests: shared/outside/interior targets, VBR +
  STORE candidates, unknown call targets, graph cycles, non-recognized
  RESET, capped display, duplicate slots, invalid pointers and immutability.
- Real Ghidra 12.1.4 PUBLIC headless CPU32 generated fixture: exception
  pointers into a RESET-call node, disconnected exact entry and interior
  pointer must be correlated by **production** Ghidra scanner. Nothing
  about actual physical MCU operation is established.
- Full extension compilation (Java 25) and existing Xvfb/CodeBrowser
  regressions remain mandatory. No additional Wyse or Dell Precision test
  requested for this source-only increment.
