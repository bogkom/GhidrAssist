# P-code memory STORE alias safety

Incremental correctness hardening for stages 2 and 4.

A decoded Motorola instruction with a P-code STORE must **not** be treated
as a read-only/no-effect (`OTHER`) step merely because the shorthand
instruction/operand parser does not support its addressing mode. Examples
include multi-register MOVEM, memory-indirect and stack/predecrement forms.

- `GhidraHardwareFlowService` now emits an unresolved memory STORE step
  when the instruction has P-code STORE effects but no trusted, modeled
  address. The existing `HardwareDataflow` logic clears tracked
  peripheral constants and records `priorUnknownStore`.
- A constant P-code address is only accepted when **exactly one** STORE
  occurs and its destination is resolved. A mix of known/unknown pointers
  or several stores is explicitly unknown, rather than choosing the first
  resolvable address and generating false SIMCR/CSBAR evidence.
- This may suppress some previous candidate hardware snapshots: that is a
  deliberate safety tradeoff until full alias and multi-store modeling
  exists. P-code stores remain static; no execution path, CPU identity,
  active MM state or hardware wiring has been proven.
- No firmware, Ghidra symbols or memory map is modified by this analysis.
  The change is covered by pure Java negative cases and the full
  Ghidra 12.1.4 compilation via GitHub Actions.

Still open: interprocedural call summaries, side effects on address
registers from pre/post-increment instructions and explicit memory-space
alias analysis. A call boundary remains conservative.
