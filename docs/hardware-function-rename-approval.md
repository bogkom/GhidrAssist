# Hardware Analysis: reviewed, bulk-applied function names

**Stage 5, optional:** Hardware Analysis now exposes **Review names...** beside
the explicit profile selector. It uses the exact proposal snapshot produced
during the current analysis; after a Program change it refuses to act.

## What can be renamed

- Only the **user-selected MC68332 hypothesis**, never the generic CPU32
  architecture. The method does not attempt to identify the physical ECU MCU.
- Only a Ghidra-generated `FUN_...` or `SUB_...` function name with a strong
  multi-register hardware WRITE role signature.
- At least three distinct direct write instruction sites and three distinct
  hardware-register names, with no existing symbol collision.
- Proposed names include `HW_MC68332_`, the conservative role,
  `_CANDIDATE_` and the original function start address.

## Reviewed Ghidra changes

A resizable table shows per-row preflight `READY`, `NAME_COLLISION`,
`NAME_CHANGED`, `WEAK_OR_UNREVIEWED` or `INVALID` and the evidence role.
Eligible proposals are initially checked for convenience. The user can bulk
select or clear and must **explicitly approve** and confirm again.

Immediately before application, the service re-fetches every original Ghidra
Function and the complete symbol namespace **inside one Program transaction**.
Any renamed/stale function, invalid role or conflicting target aborts the
entire operation and rolls back the transaction, rather than overwriting a
user name. Ghidra **Undo** is available after a successful commit.

A new Hardware Analysis run is necessary after renaming; the evidence cache
and old CSV snapshot are invalidated. Nothing is written to the firmware
binary or connected hardware.

## Limitations

This is a compiler-checked implementation, not an assertion that the UI or
all Ghidra SymbolTable behaviors have been user-tested on a real project.
The role is still a *static candidate*; output does **not** imply execution,
reset-path reachability, a specific physical MCU or electrical CS wiring.

Local variable, argument and data-pointer renaming and full path-sensitive
interprocedural analysis remain outside this increment.

## 2026-11-03 — revision-bound final function rename approval

The reviewed naming proposal is now bound to the exact completed Analyze
snapshot: live Ghidra Program identity, modification/Undo counter, language,
original-import SHA metadata and manually selected MC68332. The GUI rechecks
the snapshot **after** the final modal confirmation; the production rename
service requires and rechecks it **before and inside** its single Ghidra
transaction, prior to changing any names. Stale, wrong-profile, cloned
program or missing receipts fail closed even if symbols retain the same name.
All previously required collision, preflight, explicit approval and Ghidra
Undo rules are preserved. Ghidra SourceType still does NOT identify whether
the previous change came from a human, script or model. Static function role
hints are not proof of executed MCU initialization or active hardware.
No user program, private firmware, or profile is modified by this code change.

## GA-13 — approved function rename receipts in the Program transaction

Prior iterations only produced read-only naming previews and Ghidra
`USER_DEFINED` function symbols. `SourceType` does **not** identify
which human, model or script initiated the change. An explicitly
user-confirmed Apply now also writes a bounded, versioned **per-function
operation receipt** into the **same Ghidra Program transaction** as
the `setName` call. Neither Analyze nor preview creates a receipt.

Receipt storage uses a dedicated Ghidra Program **Options** category,
`GhidrAssist Function Rename Receipts`, with keys
`FN_<8-digit-24-bit-entry>`. It is **Program-local**, not the user
Ghidra profile, original firmware, external file, RAG database, network
service or OAuth credentials. Fields record the original Ghidra import
SHA metadata (`UNKNOWN` if unavailable), reviewed modification number,
function entry, before/after names, static role, register evidence names
and distinct write-site count. All fields are size bounded and
deterministically encoded in `GA13-FUNCTION-RENAME-1` format.

Every selected entry is revalidated **before** writing anything.
An existing receipt at the same address refuses an additional
automatic rename instead of replacing previously retained evidence.
All changes share Ghidra's native single undoable transaction:
a failed preflight, collision, write or corrupt receipt must roll back
the whole batch. A successful Undo should restore **both** the
function name and the Program-local receipt; Redo restores both.
The new `HardwareFunctionRenameService.receipt(program,address)`
is a **read-only** accessor and rejects malformed data rather
than inventing an audit record.

The stored SHA-256 checksum detects accidental corruption or
truncation; it is **not a signature or proof of honest provenance**.
No actor identity or durable cryptographic attestation is created.
A current or later `USER_DEFINED` symbol does not prove a human
editor, execution of code, specific MC68332 behavior, or retained
permission to Apply again. Receipts may be altered by other scripts
with Program write access and are subject to Ghidra Undo/Redo and
save. This is an initial operation-level provenance subset of GA-13,
**not** the complete, tamper-proof history of arbitrary edits.

The exact-commit gate includes a Java21 source-only checksum,
version, UTF-8, source SHA, 24-bit address and evidence-limit suite;
a **real isolated synthetic Ghidra 12.1.4 PUBLIC / Java25**
`function-rename` mode tests two names, preflight rejection,
transactional receipt creation, Undo, Redo and second Undo.
The existing full extension build and unrelated hardware
regressions remain required. Tests do not use the original ECU411
Program or restart the stopped Wyse/Precision/legacy Supervisor.

## GA-13 follow-up — genuine Ghidra save/reload across JVM boundary

A transactionally stored `HardwareFunctionRenameReceipt` passed
source-only Java21 and real Ghidra **Apply/Undo/Redo** CI on PR #146.
That proves the record shares the **current Program transaction**,
but does not by itself prove recovery after process exit and restart.

A separate `receipt-restart` synthetic-only acceptance mode now
tests **two separate Java 25 / Ghidra 12.1.4 PUBLIC processes** using
the **same private synthetic Ghidra project**. The runner imports
`vectors-full.bin` and `vectors-short.bin` only once. JVM #1
creates the genuine CPU32 test function, applies a reviewed
GhidrAssist function rename and its Program Options receipt, calls
Ghidra `Program.save`, releases Program consumers and closes the
project. JVM #2 independently opens that saved project **without
reimport**, checks the renamed Ghidra Function and decodes the
versioned receipt from Program Options, then verifies that inspecting
it did not modify the Program revision.

The test requires a checked source-import SHA (or explicit UNKNOWN),
reviewed modification number, old/new names, static role and
register evidence. It asserts that the record's operation origin
still says **actor UNKNOWN**: persistence is neither authentication
nor proof of executed firmware. JSON evidence for the two processes
is stored separately; the workflow fails if either phase fails,
rather than reporting a single-process success as restart support.

This test touches synthetic/private test data only; no actual
ECU411 firmware or production Ghidra project is opened or changed.
The work remains within GitHub Actions, with the historical
Wyse/Precision and legacy Supervisor services stopped.
