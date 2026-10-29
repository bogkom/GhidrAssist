# GA-08 — static A-register pointer role hints

This package exposes only **read-only** candidate roles for address registers
at CFG/P-code resolved indirect hardware register writes. Grouping is by
function entry, A0–A7, selected MCU module and MM window. Two distinct code
sites and two register targets are needed for any role hint. Unknown calls,
unknown destination stores, and propagation limits force uncertainty.

Generic CPU32 never asserts MC68332-specific pointer names. Even a
`REVIEW_ONLY` candidate describes **a register at a code site**, not a
Ghidra local variable, decompiler HighVariable, storage location, active
hardware device or executed path. There is no rename or Apply path.

Role hints are included in the detailed Analyze report and the existing
seven-column manual naming CSV with `NEVER_AUTO_APPLY`. Actual local
variable renames need separate decompiler-variable lifetime proofs and
safe reversible preflight.

Tests: pure Java synthetic alias/conflict cases, complete 12.1.4 extension
CI; separately approved local Ghidra acceptance before merge.
