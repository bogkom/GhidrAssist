# GA-13 — Review provenance and SourceType (partial)

This candidate builds from immutable PR #53 head. It adds evidence
**at review time**, not a durable per-symbol authorship database.

Existing symbol: for a register or annotation proposal, the review UI
queries Ghidra's primary symbol at the proposed address and displays its
current name and `Symbol.getSource()` classification. If no source can be
established, it remains UNKNOWN. Other row kinds have no per-symbol source.

**Do not equate `USER_DEFINED` with a human editor.** Ghidra may
use this SourceType for changes made programmatically by an extension or
script. Likewise `ANALYSIS` doesn't prove which analyzer or AI acted.
The string “GhidrAssist review proposal” identifies this proposal's
generation process only, never a prior editor, verified CPU or hardware
configuration.

The Review/Apply dialog adds three read-only columns and an optional
**Export review CSV...** action. It exports a local snapshot of proposed
definitions, current symbol/source classifications, preflight decisions,
selected checkboxes and evidence. It asks before overwriting an existing
file. CSV is never uploaded to GitHub, RAG or an API by the feature.

The existing Apply action, default selection policy, collision checks and
single Ghidra Undo transaction remain unchanged. Export does not start a
transaction. The CSV is not a persistent audit log of subsequent changes;
a future implementation would need explicit verified per-change author data
and testable transaction receipt / Undo correlation.

Validation: deterministic standalone Java CSV/provenance tests and full
Ghidra 12.1.4 extension build in Actions. On a disposable project COPY,
verify SourceType display, checkboxes, CSV, Undo, stale-program guard and
absence of OAuth edits before merging. No local PASS is implied by CI.

## 2026-11-04 — Unicode format controls in local CSV

The read-only `Export review CSV...` path treats leading Unicode
`Cf` formatting code points (WORD JOINER, zero-width joiners, bidi marks
and supplementary format tags) as ignorable **for formula-prefix
detection only**. Some importers may discard these controls before
interpreting `=`, `+`, `-`, or `@`, even though CSV cells are quoted.
A suspicious cell is prefixed with an apostrophe; the original visible
text, quotes and Unicode code points are otherwise retained.

The detector iterates **code points**, not UTF-16 code units. Java 21
regressions check BMP and supplementary Unicode formats, mixed spacing
and harmless format controls inside ordinary identifiers. The existing
5000-row/512-character limits and omission markers are unchanged.
This is a defense-in-depth safeguard for *untrusted review text*, not
proof that an arbitrary spreadsheet importer handles every encoding
the same way. No CSV import/Apply, automatic rename, Ghidra Program
mutation or external upload is introduced.

## GA-13 — new per-function GhidrAssist operation receipts

The read-only review CSV documented above still does not authenticate
who made a pre-existing change. A separate, explicitly approved
**function renaming** code path now proposes recording a limited
operation receipt in the Ghidra Program Options category
`GhidrAssist Function Rename Receipts`, **in the same transaction**
as Ghidra's function-name edit.

This receipt names the **GhidrAssist approval operation**, original
function name, proposed source-only role, import SHA metadata and
reviewed Program revision. It does not claim that any individual
user, assistant, model or third-party script authored earlier data,
and is not a complete per-symbol or per-variable audit. Ghidra
Undo/Redo must move the receipt and function name together; any
malformed persisted entry must be rejected rather than silently
trusted. The v1 record has a checksum for accidental corruption
only, not a cryptographic identity signature or actor attestation.

This is separate from the preview CSV and from GA-12 analysis
checkpoints. It changes neither export/Apply permission nor
the physical interpretation of MCU firmware.


## 2026-11-06 — GA-13 current-revision saved rename audit

A single read-only **Rename audit CSV...** action now inspects every
versioned receipt stored in the **current Ghidra Program's** transactional
`GhidrAssist Function Rename Receipts` Options category. It works
independently of Analyze, the explicitly selected MCU, and permission
to Review/Apply. No local preferences, firmware images, OAuth or other
projects are read or modified. The new
`HardwareFunctionRenameService.audit(program)` builds an immutable
snapshot by correlating each canonical receipt with its **currently
existing** Ghidra Function and `Symbol.getSource()` value.

Each report row includes: 24-bit function entry, before/approved/current
names, approved analysis revision and current Program revision, original
import SHA metadata, role and contributing register names, distinct
write-site count, Ghidra SourceType, conservative operation origin
(`actor UNKNOWN`) and explicit audit status.

The read-only states are `CURRENT_APPROVED_NAME`,
`NAME_CHANGED_AFTER_APPROVAL`, `FUNCTION_MISSING`,
`SOURCE_CHANGED`, `SOURCE_UNVERIFIED` and
`SOURCE_TYPE_CHANGED`. A changed name cannot silently masquerade
as an unchanged approved name. Missing Program SHA does not become
a verified source identity. An invalid checksum, unsupported record
version, duplicate key, inconsistent key/function address or oversized
receipt inventory **blocks the entire export** rather than turning
partial records into approved facts. Export re-checks Program identity
and the complete Options/current-symbol snapshot **after the modal
Save/Overwrite dialogs**, preventing a stale CSV from being saved.

CSV fields share the existing per-cell 512-character cap, Unicode
control protection, formula-prefix hardening and RFC-style escaping
used by read-only Review provenance. The audit is never Apply input
and contains no reusable approval token. Max 4096 persisted receipts;
excess entries reject rather than silently truncating an audit.

**Undo/Redo scope:** receipts are saved in the same Ghidra Program
transaction as the approved rename. The audit shows the currently
persisted approved state; native Undo removes both name and receipt,
Redo restores both. **It is not an append-only history of discarded
or undone decisions**; erased receipts cannot prove who approved,
undid or redid a change. `USER_DEFINED` does not authenticate
a human/AI author. A checksum detects accidental corruption only.

Regression gates:
- Java21 pure receipt codec, original review CSV and bounded
  current-Program audit state/CSV tests;
- genuine Ghidra 12.1.4 PUBLIC / Java25 two-function Apply,
  collision rollback, Undo/Redo and second Undo with audit assertions;
- genuine cross-JVM save/open of the same isolated synthetic project
  with read-only audit and revision-unchanged verification;
- complete extension build. No Wyse/Precision, stopped Supervisor
  or private ECU411 project.

GA-13 remains **PARTIAL**: a separately authorized, trustworthy
and appropriately protected event journal would be necessary to
retain explicitly rejected proposals, Undo/Redo operations after
reversal and user/AI identities. That is not fabricated here.
