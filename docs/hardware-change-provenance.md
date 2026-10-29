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

## 2026-10-29 — local provenance CSV hardening

Quoted CSV cells alone do **not** stop Microsoft Excel/LibreOffice
from interpreting `=HYPERLINK(...)`, `+1`, `-1` or `@SUM(...)`
as formulas. GhidrAssist now prefixes formula-looking fields with an
apostrophe, including when hidden behind whitespace, tabs, BOM or
zero-width spaces. Quotes, commas and line breaks remain escaped.
This is a read-only audit export, **never** an Apply instruction.

Export retains at most 5000 Review rows. Larger snapshots append
`OMITTED_ROWS` with the exact omitted count and a
`INCOMPLETE_EXPORT_NEVER_AUTO_APPLY` decision. The displayed/exported
subset must never be mistaken for a full authorship audit. SourceType
still cannot identify human versus script/AI authors; no Ghidra writes
or remote transmission are introduced.

## 2026-10-29 — per-cell provenance limit

The existing row cap (5,000) was insufficient: an untrusted Ghidra symbol,
proposed name or evidence string could still contain millions of characters,
causing a large export and multiple temporary copies during normalization.
Each raw CSV cell is now truncated to **512 characters before allocating
normalized strings** and includes an explicit `[SOURCE_TRUNCATED]` marker.
Spreadsheet formula prevention still applies to the retained prefix, including
initial signs hidden after whitespace. The exported CSV is **not** a complete
audit of truncated evidence and remains never auto-applicable.

Negative offline tests include million-character input fields and combined
row/cell limits. A full extension build for Ghidra 12.1.4 and actual isolated
Review/export acceptance remain required. Original evidence must be opened
in Ghidra before naming or applying any change.
