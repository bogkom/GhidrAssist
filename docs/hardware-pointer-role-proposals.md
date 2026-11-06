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

## 2026-11-04 — bounded, formula-safe pointer hint CSV (GA-08/13)

Pointer-role proposal rows are appended to the **same** seven-column
read-only Review CSV as register and function-name hints. The 2026-11-04
GA-08/13 hardening in merged PR #143 introduced a shared
`HardwareNamingReview.cell` encoder, but this third producer still
had its own unlimited, quote-only cell function.

This update reuses the established **512-character** source-field
encoder for all pointer-role text values (including imported function
names and direct `Proposal` fields), with a visible
`[SOURCE_TRUNCATED]` marker. It normalizes control line breaks,
keeps valid Unicode surrogate pairs intact, and guards formulas
hidden after whitespace and Unicode format controls. Normal
Ghidra-produced pointer rows already prepend a literal `A0..A7 in`
to the name, reducing formula risk, but the public row serializer also
accepts independently constructed Proposal records. Neither route
may generate unbounded or executable spreadsheet data.

`csvRows` now rejects a null collection or null row. Exports
are capped at **5000 pointer-role rows**; additional rows produce a
counted **`OMITTED_ROWS`** record in the same seven-column schema,
including `POINTER_ROLE_EXPORT_INCOMPLETE` and
`INCOMPLETE_EXPORT_NEVER_AUTO_APPLY`. This marker discloses
lost source hints and is **not** an action request, approved rename,
complete evidence set or verified provenance of an editor.

The existing Java 21 pointer-role regression and shared GA-08/13
CSV safety workflow cover formula prefix, a million-character
imported function name, the 5000/5001 budget, null input and unchanged
ordinary candidates. Full Ghidra **12.1.4 PUBLIC / Java 25** build and
applicable synthetic headless CI must PASS at the exact PR SHA.

No local variable/HighVariable rename, transaction, audit author,
program modification, original ECU411 firmware or stopped
Wyse/Precision/legacy Supervisor operation is introduced.


## 2026-11-06 — GA-05/08 safe, typed Ghidra pointer variable names

The original `HardwarePointerRoleReview` remains **source-only**.
It detects patterns of A-register use but cannot identify a durable
Decompiler `HighVariable`, named Ghidra local, or argument. Never
promote its hints to Apply input.

An independent **Review pointers...** UI now examines only the
**currently selected Ghidra Function's existing DB variables**:
`Function.getParameters()` and `Function.getLocalVariables()`.
The explicit MC68332 device hypothesis must be selected. Only a
Ghidra `Pointer` DataType, a generated `param_N`/`local_*` name,
unambiguous variable ordinal **and** exact `VariableStorage`
qualify for a new neutral type-only placeholder suggestion
(`ga_arg_ptr_candidate_N` or `ga_local_ptr_candidate_N`).
This is **not** a hardware-register name or proof of pointer values.
No variable is created from the pseudocode text; non-pointer types,
source `USER_DEFINED`, user-named variables, ABI auto-parameters,
forced-indirect arguments and unassigned storage are excluded.

All review checkboxes default to **unchecked**. The user must
explicitly check rows, confirm the dialog, and **confirm Apply again**.
Immediately before modification, the service requires an exact
Ghidra Program identity, language, executable SHA, MCU-selection
and modification/Undo revision matching its review snapshot.
It then re-resolves every existing `Variable` by exact Ghidra
Function entry, kind, ordinal and storage, rechecks original name,
pointer datatype, SourceType, dynamic ABI status and collisions
among all variables in the function. The entire selected batch is
renamed in a **single native undoable Program transaction**;
on any failure, all edits roll back together.

After Apply, existing report/revision caches are invalidated.
The Java21 policy regression covers stale storage, altered datatype,
manual/source names, namespace collisions, missing evidence,
duplicates, source bounds, unassigned storage and lack of implicit
A-register application. A separate genuine synthetic Ghidra
12.1.4 PUBLIC / Java25 integration regression creates actual typed
pointer Function variables and verifies atomic refusal,
explicit Apply, native Undo/Redo and stale replay refusal.

This does not yet offer hardware-specific pointer-role names,
cross-function type inference or a trustworthy identity for
Decompiler `HighVariable` temporary values; those remain GA-08
PARTIAL. It does **not** create an append-only authorship journal
or authorize naming on original ECU411 firmware/project. No
stopped Wyse/Precision/legacy Supervisor process is restarted.
