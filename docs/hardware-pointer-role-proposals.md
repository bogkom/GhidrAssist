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

## 2026-10-29 — register reuse across modules/MM modes

The prior role grouping considered each function/A-register/module/MM
tuple separately. A register such as A0 can be reused for unrelated
functions at different PCs; two apparently well-supported groups for
SIM and QSM (or for both MM0 and MM1) do **not** establish a stable
register variable. Every same-function, same-A-register group now gets
`SCOPE_CONFLICT` when more than one module/MM scope appears.

This suppresses the otherwise attractive `p_hw_*_candidate` name hint.
It does not assert that the mixed scopes were executed and never
names a Ghidra HighVariable or performs an Apply. `NEVER_AUTO_APPLY`
remains on all CSV records. Other distinct A-registers are evaluated
independently. A human may still inspect true register lifetimes.
