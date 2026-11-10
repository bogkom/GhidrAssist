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

## 2026-11-10 — per-instruction-PC evidence identity and revision ambiguity

A duplicated Listing instruction PC is only an identical source witness if
its A-register, module, selected MM interpretation and hardware target are
identical. Different targets or pointers at the same PC, or different
function names for the same function entry in one input collection, yield
`PATH_UNCERTAIN` and no candidate hint. The read-only parser also limits
site inventory to 120,000 entries prior to grouping. This is an evidence
consistency guard, not an invented stable decompiler HighVariable or
permission to Apply a pointer/argument rename. No runtime execution or
active MC68332 memory mapping is inferred.

## 2026-11-10 — real Ghidra scoped pointer variables versus A-register hints

Function-DB pointer parameters and locals already have an isolated, explicit
Review/Apply/Undo mechanism with native transactional receipts. This is
**not** a conversion from an A0..A7 role observation into a decompiler
HighVariable. Its receipt audit and post-write Ghidra transaction checks now
reject a surviving CURRENT approval on a live variable that lost pointer
type, USER_DEFINED source, or acquired auto/forced-indirect ABI semantics.
Revision and storage equality remain mandatory. A-register role hints
continue to be read-only, PATH_UNCERTAIN or REVIEW_ONLY, never Apply input.

## 2026-11-10 — type-specific existing Function-DB variable Review

Unlike static A-register MMIO hints, an exact Ghidra Function-DB parameter
or local has assigned storage, datatype and function-relative first use.
Scoped-pointer previews now include datatype path/size and first-use offset
in their in-memory typed identity; the live Apply transaction refuses
replayed legacy source-only observations and changed pointer target types
or first-use positions, even if pointerType, name and storage appear the
same. A trusted original executable checksum and native Program revision
remain separate requirements. This does not make a physical A0..A7 reuse
hint a stable HighVariable, prove runtime execution or authorize new names
without explicit user Review. The existing v1 durable receipt format does
not yet contain the entire datatype path and must not be over-interpreted
as cross-restart proof of pointee type equality.

## 2026-11-10 — GA-08/12/13 typed pointer receipt v2 (cross-JVM audit)

The **same** existing explicitly approved Ghidra Function-DB Review→Apply
transaction now saves an immutable `GA13-POINTER-VARIABLE-2` Option value:
function entry, kind, ordinal, exact storage, original and approved names,
source SHA-256 and reviewed revision **plus exact Ghidra DataType path/length
and function-relative first-use offset**. The new fields come from the
already live-rechecked typed preview, not from A-register hypotheses or
decompiler HighVariable inference. Every receipt is written atomically with
its corresponding name; native Ghidra Undo/Redo controls both.

A fresh read-only Program audit resolves each current Ghidra variable and
rechecks pointer type, USER_DEFINED SourceType, ABI auto/forced status,
storage, imported source identity, **datatype path/size and first use**.
Changed type or first-use is `TYPE_IDENTITY_CHANGED`; unavailable live
type/scope is `TYPE_IDENTITY_UNVERIFIED`. The canonical audit CSV retains
its original columns and appends four explicit reviewed/current type/scope
columns. Historical `GA13-POINTER-VARIABLE-1` records remain readable and
checksum-verified, but are **`LEGACY_TYPE_UNVERIFIED`**, never upgraded
retroactively to an approved typed identity. There is no silent schema
migration or weakening of existing Review/Apply permissions.

Java21 policy tests cover v1 canonical reopening, v2 typed round-trips,
changed pointee identity, first use, missing live evidence, invalid metadata,
forged current states and CSV. Real isolated Ghidra 12.1.4 PUBLIC/Java25
CI checks Option bytes, typed audit, forged audit witnesses and native
Undo/Redo. The receipt checksum detects corruption; it does not authenticate
a user or firmware bytes. Static source evidence does not prove executed
MMIO, active ISR/VBR or latched SIMCR MM. No user firmware/project,
Wyse/Precision/Supervisor work, OAuth or host settings are modified.
GA-08/12/13/18 remain PARTIAL and GA-14 remains deferred.
