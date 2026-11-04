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
