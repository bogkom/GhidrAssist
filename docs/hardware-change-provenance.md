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


## 2026-11-10 — source SHA-256 syntax before an APPROVED-CURRENT audit claim

GA-08 pointer-variable and GA-13 function-rename receipts are versioned
Program-local operation records. Their historical schemas deliberately
allow the original import checksum to be `UNKNOWN` or other bounded
legacy text. Previously, comparing two identical malformed nonempty
strings (for example lowercase `unknown`, `not-a-sha` or 64 non-hex
characters) could produce `CURRENT_APPROVED_NAME`, even though those
strings were never executable SHA-256 values.

The **read-only audit classification** now requires **exactly 64 ASCII
hexadecimal digits** for both the stored and current executable SHA-256
metadata before a row can be `CURRENT_APPROVED_NAME`. Valid hex digits
are compared case-insensitively. Any missing, malformed, legacy or
unverifiable identity becomes `SOURCE_UNVERIFIED`, even if the two
strings are equal. Two different syntactically valid digests still
produce `SOURCE_CHANGED`. Missing symbols/variables, changed storage,
changed name/type and all revision-bound CSV fences remain conservative.

No receipt is silently rewritten, rejected merely because it is old,
or upgraded to authenticated identity. SHA syntax is **necessary but
never sufficient** to authenticate binary bytes or an editor: Ghidra
source metadata can be missing/spoofed and the Options checksum is
not a signature. No new privileges, Apply action, Undo journal,
firmware access or user-profile state. Java21 negative regressions
cover lowercase UNKNOWN, false matching short/64-character values,
Unicode lookalikes, malformed live metadata and valid mixed-case
SHA equivalents. Full Ghidra 12.1.4 PUBLIC Java25 build and isolated
synthetic headless CI remain required before merge.

## 2026-11-10 — source-cell loss receipt even without omitted rows

A CSV within the 5000-row limit may still contain truncated 512-character
source cells. The export now adds a counted `TRUNCATED_SOURCE_ROWS` audit
receipt with `EXPORT_INCOMPLETE` and `INCOMPLETE_EXPORT_NEVER_AUTO_APPLY`;
`OMITTED_ROWS` remains independent when additional rows were excluded.
Rows with multiple truncated fields count once. This changes only the
local read-only export, not Ghidra selections, Apply, Undo, persisted
checkpoint identity or claims about who authored a SourceType symbol.

## 2026-11-10 — source-bound persisted rename receipt audit state

GA-13 no longer trusts a directly constructed `CURRENT_APPROVED_NAME` flag
in public rename audit snapshots. Each row must agree with the stored
receipt, current observed function name, Ghidra SourceType, and the
syntactically valid full import SHA-256; an unknown source is recorded as
`SOURCE_UNVERIFIED`. Duplicated, omitted/null and unordered direct snapshot
rows fail closed. Exporting a current-approval CSV requires a current,
exact same-Program and explicitly selected MC68332 revision fence both
before and after serialization. A saved receipt identifies one extension
operation, not the authenticated human/AI editor, active hardware, or a
durable history of Undo after Ghidra removes its receipt.

## 2026-11-10 — scoped-variable GA-13 receipt audit source assertions

The existing function-local pointer parameter and local variable approval
records share a single native Program transaction with the corresponding
USER_DEFINED symbol name edits. The read-only public audit now verifies its
CURRENT_APPROVED_NAME label against the receipt's exact function/kind/
ordinal/storage, a syntactically valid full firmware import SHA-256, the
live pointer data type, USER_DEFINED source and a non-auto/non-forced ABI
parameter. A replaced argument, changed datatype, alternate import,
changed name or a caller-supplied contradictory audit State is not presented
as approved-current. A direct public snapshot must have complete, unique
and deterministically ordered rows. The CSV revision fence requires the
same in-memory Program, modification and selected MC68332 profile; a
Ghidra Undo removing a receipt is not an append-only operator history.
The implementation never identifies an authenticated editor or allows
automatic Apply from static A-register role hints.
