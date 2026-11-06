# GA-10 — Sourced bitfield evidence (candidate implementation)

Source baseline: PR #53 (commit `bd0a0a60eaa610e19581bd67fd16d29c637bfb8e`).
The decoder is limited to *explicitly selected MC68332* and bitfield
definitions carrying a verified source-page marker in `HardwareProfiles`.

## Behavior

- The current integration annotates **only direct immediate `MOVE.W #...` to
  SIMCR** in Listing/XREF Analyze output, and only for the concrete selected
  device. The original read-only evidence rows remain visible for every site.
- SIMCR `MM` (mask 0x0040), `SUPV` (0x0080), and `IARB` (0x000F)
  are decoded as masked values using the existing MC68332 profile metadata,
  with the PDF physical-page references from those definitions.
- All other SIMCR bits remain `UNINTERPRETED`; other registers without
  sourced field definitions return `NO_SOURCED_FIELDS`.
- Unknown constants, wrong access width, out-of-range values, missing device,
  generic CPU32 and unrecognized registers do **not** produce device assertions.
- No claim is made that a code site was reached. This is **not** a reset/first
  successful write or a confirmed write-once MM latch state. The CFG/P-code
  path conditions and actual runtime hardware configuration remain unknown.
- No symbols, memory regions, types, Ghidra database, OAuth tokens or RAG
  documents are modified. Review / Apply is unchanged.

## Verification

GitHub Actions: standalone Java regression `hardware-bitfield-decoder-tests.yml`
and full Ghidra 12.1.4 extension build `hardware-extension-build.yml`.
The workflow result must be checked for the exact PR head before accepting.

Pending isolated real-Ghidra acceptance: on a project COPY of ECU411, select
MC68332 and verify a directly recognized `MOVE.W #0x40CA` SIMCR site
shows MM=1, SUPV=1 and IARB=0xA with PDF evidence; non-MOVE.W sites
must not gain synthetic bitfield values. In generic CPU32 survey mode
no MC68332 bitfield interpretation may be displayed. Ensure no write to
the project and compare with the existing CSBOOT table and RESET report.
No Supervisor plan is approved or submitted by this code change.

## 2026-11-03 — strict shared PDF page-claim validation

The GA-10 decoder and GA-06 external profile preview now use the same
`ManualPdfPageClaim` **syntax-only** validator. A label such as
`PDF pages 219-220` must contain exactly one bounded ascending
numeric claim, with no malformed range tail, contradictory second claim
or explicit UNKNOWN/UNVERIFIED/AMBIGUOUS qualifier. A descending range
or excessive page number never licenses decoding a bit as source-backed;
it remains `NO_SOURCED_FIELDS` or an unverified profile page instead.
This parser does **not** verify actual PDF bytes or an edition. Tests
are standalone Java and extension CI only, no host or firmware files.


## 2026-11-06 — GA-10/16 SIMCR+SYNCR sourced field/page consolidation

This larger acceptance package explicitly selects **MC68332** and binds both
SIMCR and SYNCR complete-word literals to the printed/physical folios of
the publisher-hosted [MC68332UM](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf),
**Motorola 1995**. The public PDF has 265 physical pages. Page numbers below
are **one-based physical PDF pages**, not the printed appendix labels.

| Register | Modeled fields | Printed page | Physical PDF page | Unmodeled mask |
|---|---|---|---|---|
| SIMCR | EXOFF 0x8000, FRZSW 0x4000, FRZBM 0x2000, SLVEN 0x0800, SHEN[1:0] 0x0300 | D-5 | 219 | |
| SIMCR | SUPV 0x0080, MM 0x0040, IARB[3:0] 0x000F | D-5/D-6 | 219–220 | **0x1430**, all other bits uninterpreted |
| SYNCR | W 0x8000, X 0x4000, Y[5:0] 0x3F00, EDIV 0x0080 | D-6 | 220 | |
| SYNCR | RSTEN 0x0004, STSIM 0x0002, STEXT 0x0001 | D-7 | 221 | **0x0078**, including SLIMP/SLOCK status bits |

**Scope:** field interpretations apply only to complete, direct,
full-width `MOVE.W #literal` source candidates under the explicitly
selected MC68332 profile. The analyzer now displays SYNCR alongside SIMCR,
and the Overview counts its source sites independently. Neither literal
value nor a control-field name establishes execution, reset values, an
active clock, or the first write to write-once MM. RSR status fields,
unknown/reserved bits, partial writes, indirect stores and unrecognized
registers remain uninterpreted.

`HardwareBitfieldSourceLedger` emits **15 immutable field-to-page claim
records** into Full Evidence, canonical exported Markdown and read-only
RAG context, showing register, field, exact mask, edition claim, source
URL and physical PDF page. Focused SIMCR/SYNCR RAG retrieval includes only
the relevant register's citations and explicitly counts omitted rows when
its context budget is exceeded. Generic CPU32 mode has no device field
interpretation and no MC68332 source ledger.

**Source authentication boundary:** visual inspection of the
publisher-hosted D-5/D-6/D-7 pages identifies these fields and folios.
The portable runtime ledger is still **CLAIM_ONLY**: it does not read a
local PDF, authenticate its bytes, independently identify the edition,
or attest physical hardware. The dedicated official-PDF Actions gate
downloads from the NXP URL, checks the **exact SHA-256 pin** (to be set
from a reviewed external run), verifies 265 physical pages and the
three printed folios with PDF text extraction. Until that gate passes
on an exact PR HEAD, the PDF-byte evidence is **INCONCLUSIVE**.
Do not populate a claimed checksum from a URL or from unknown user files.

**CI acceptance:** independent Java21 bitfield/page parser/source-ledger
and context-selection regressions; Java21 Overview; Ghidra 12.1.4
PUBLIC/Java25 full extension build; isolated real CodeBrowser/Xvfb
checking published field-page ledger and focused RAG. No local
Wyse/Precision or legacy Supervisor sessions and no private ECU411
firmware/project. GA-10 and GA-16 remain **PARTIAL** outside these
explicitly modeled fields and pages: broader register tables, verified
local document ingestion and folio/table correlation still require
separate evidence.
