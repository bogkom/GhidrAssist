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
downloads from the NXP URL and checks the reviewed **exact SHA-256 pin**:
`02c2cb99738dd45a785798bba3e7dcc34bb0d54fb5fba42900e6ecb8356bf28a`.
On the tested public GitHub runner (Actions
[42233819507](https://github.com/bogkom/GhidrAssist/actions/runs/42233819507)),
the pinned bytes passed the 265-page check and extracted-text assertions
for physical folios 219/220/221. The runtime ledger publishes this
expected publisher checksum as provenance metadata but **does not**
authenticate any local/RAG-imported copy; do not silently substitute
a different file or infer hardware state from PDF content.
The final PR HEAD requires independent passing CI evidence.

**CI acceptance:** independent Java21 bitfield/page parser/source-ledger
and context-selection regressions; Java21 Overview; Ghidra 12.1.4
PUBLIC/Java25 full extension build; isolated real CodeBrowser/Xvfb
checking published field-page ledger and focused RAG. No local
Wyse/Precision or legacy Supervisor sessions and no private ECU411
firmware/project. GA-10 and GA-16 remain **PARTIAL** outside these
explicitly modeled fields and pages: broader register tables, verified
local document ingestion and folio/table correlation still require
separate evidence.


## 2026-11-09 — GA-06/10/16 bounded physical-page field-name witnesses

The MC68332UM publisher-PDF CI gate already pins SHA-256
`02c2cb99738dd45a785798bba3e7dcc34bb0d54fb5fba42900e6ecb8356bf28a`,
validates the 265-page document and maps printed Appendix D-5/D-6/D-7 to
physical PDF pages 219/220/221. A new, independent Java21
`HardwareBitfieldPageWitness` now correlates the existing 15
SIMCR/SYNCR field claim records with **literal field-name tokens on
their claimed physical folios**, without inspecting adjacent pages to
fill gaps. The official-PDF Actions job extracts the exact three pages
from SHA-checked publisher bytes and requires real source-text
witnesses for `SHEN` on physical page **219** and `STEXT` on page
**221**. Deterministic synthetic regressions also cover the other
nine discriminative names, wrong/missing folios, word-substring
attacks, oversized page text and generic CPU32 scope.

`MM`, `W`, `X` and `Y` are **SHORT_NAME_AMBIGUOUS** even if
those short strings appear in PDF prose. A literal name on a page
gives only `NAME_ON_CLAIMED_PAGE`: it is **not independent
verification** of the mask, register layout, reset values, printed
edition, CPU variant, runtime write, or active MM. Publisher SHA
validation is a separate CI gate; supplying arbitrary extracted text
to this pure Java inspector **never authenticates a local/RAG PDF**.

The inspector is bounded to 16 one-based physical pages and 256 KiB
text per page, emits immutable per-field rows with the actual matching
folio numbers, and has no document/network/Ghidra database access.
Runtime `HardwareBitfieldSourceLedger` remains clearly `CLAIM_ONLY`
until real local PDF authentication and page-region checks are
implemented. No user files, ECU411 firmware or OAuth are read or
modified. GA-06/10/16 remain PARTIAL; GA-08/13 retain their separate
Review/Apply/Undo protection track.


## 2026-11-09 — GA-06/10/16 SIMCR/SYNCR diagram bit positions and mask cross-check

Manual visual inspection of the SHA-pinned **publisher** MC68332UM
(Appendix **D-5, physical PDF 219** and **D-6, physical PDF 220**)
established the following independent reviewed register-diagram
positions. The profile values are then compared with masks derived
*from those bit positions*, rather than just finding a field name
somewhere in the PDF text:

| Register | Diagram page | Reviewed fields (MSB:LSB = profile mask) | Bits intentionally unmodeled |
|---|---|---|---|
| SIMCR | D-5 / PDF 219 | EXOFF 15=8000, FRZSW 14=4000, FRZBM 13=2000, SLVEN 11=0800, SHEN 9:8=0300, SUPV 7=0080, MM 6=0040, IARB 3:0=000F | `0x1430` |
| SYNCR | D-6 / PDF 220 | W 15=8000, X 14=4000, Y 13:8=3F00, EDIV 7=0080, RSTEN 2=0004, STSIM 1=0002, STEXT 0=0001 | `0x0078` (including status flags SLIMP/SLOCK) |

**Physical diagram page and prose source-page claim are deliberately
different fields.** For instance, the SUPV description is on PDF 220
while its **bit position is drawn on PDF 219**. Likewise RSTEN,
STSIM and STEXT are drawn on PDF 220 but their textual descriptions
continue on PDF 221. A test must not use the following description
folio as a substitute for the original diagram.

`HardwareBitfieldLayoutWitness` is a bounded, read-only, manually
reviewed 15-field reference. It compares independently computed masks
against the selected concrete MC68332 profile and requires the
characteristic bit-number header and **ordered diagram label row**
on each exact physical page. It distinguishes matching, missing,
mismatched or unexpected profile definitions and cannot independently
authenticate arbitrary caller-supplied extracted PDF text.

The existing official NXP PDF CI checks the immutable reviewed
SHA-256 `02c2cb99738dd45a785798bba3e7dcc34bb0d54fb5fba42900e6ecb8356bf28a`,
265 physical pages, and extracts exact pages 219–221; it now also
tests the ordered D-5/D-6 diagram rows and **all 15 masks** against
the separately reviewed bit positions on the *same pinned bytes*.
Java21 synthetic adversarial tests reject changed masks, omitted or
extra definitions, swapped/malformed diagram pages and unbounded text.

This is stronger source checking than a field-name match, but still
**not an automatic PDF image/layout parser, independent proof of
all prose semantics, MCU identity, reset value, actual register write
or active SIMCR/MM**. It does not authenticate local/RAG PDFs; the
runtime bitfield ledger remains clearly source metadata, not an
Apply authorization. No original firmware/project changes or
Wyse/Precision/Supervisor tests were performed.


## 2026-11-09 — GA-06/10/16 MC68332UM Table D-2 chip-select address witnesses

A separate read-only, bounded `HardwareSimChipSelectTableWitness` now
checks **26 device-specific register addresses** against Table D-2
SIM Address Map in the manufacturer manual, not merely names or general
SIM aperture claims. The reviewed source is the **same publisher**
MC68332UM SHA-256
`02c2cb99738dd45a785798bba3e7dcc34bb0d54fb5fba42900e6ecb8356bf28a`
with 265 pages; Table D-2 spans printed **D-4 / physical PDF 218**
and **D-5 / physical PDF 219**.

The exact reviewed rows are CSPAR0/1 (`$YFFA44/46`),
CSBARBT/CSORBT (`$YFFA48/4A`), and CSBAR0–10 / CSOR0–10,
at `$YFFA4C + 4*n` and `$YFFA4E + 4*n`. Each must appear
on its exact table folio and agree with the explicitly selected
MC68332 profile module, offset and 16-bit register metadata. The
page break is critical: **CSBAR4 at $YFFA5C is on D-4/PDF 218,
while CSOR4 at $YFFA5E is on D-5/PDF 219**. Neither matching a name
on another page nor a wrong address under an otherwise correct name
can satisfy the witness.

This is intentionally an exact source-row cross-check, not a full
register-field parser or bus simulation. Synthetic Java21 tests
exercise 26 valid row agreements, changed address/name semantics,
swapped/omitted folios, duplicate source rows, foreign CPU32 profile
and text bounds. The official Actions job validates the publisher
SHA and 265 physical pages **before** extracting physical PDF 218–221
and requiring all 26 witnesses from the real extracted text.
No local/RAG copy is authenticated by the parser.

**Limit:** this proves reviewed manufacturer **source-page address
rows** agree with selected metadata on the tested document. It
does **not** establish execution, pin assertion, CSPAR/CSOR
configuration, SIMCR/MM activation, CSBAR window presence on a
physical external bus, or permission to change Ghidra symbols or
memory blocks. Unmodeled device-specific registers and unverified
folio citations remain hypotheses; GA-06/10/16 stay PARTIAL.

## 2026-11-09 — SIM Table D-2 address/byte-width/access witnesses (GA-06/10/16)

The publisher `MC68332UM.pdf` Appendix **D-4** on physical PDF
page **218** contains SIM Table D-2 through `CSBAR4` at row
`$YFFA5C`. The continuation on Appendix **D-5** / PDF page **219**
starts with `CSOR4` at row `$YFFA5E`; `CSBAR8` and `CSOR8`
are therefore on **219**, whereas `CSPAR0`, `CSPAR1`,
`SYPCR`, `SWSR`, `PORTE0`, `DDRE`, `PFPAR` and
`CSBAR0` are on **218**. The pages were visually reviewed from
the official PDF before creating the independent source reference.

The crucial distinction: Table D-2 prints **aligned 16-bit row
addresses**. For lower-byte registers, the actual device-profile
address is **row + 1**. Thus SYPCR = `0xFFFA21` vs table row
`$YFFA20`, SWSR = `0xFFFA27` vs table row `$YFFA26`,
PORTE0 = `0xFFFA11` vs row `$YFFA10`. The status/register
width must not be fabricated from the row label: SYPCR/SWSR
are 8-bit; CSPAR0/1 and CSBAR/CSOR are 16-bit. The table marks
`S` supervisor-only and `S/U` configurable for selected
ports; this does not prove privilege or runtime status.

The bounded, **read-only** `HardwareSimD2RegisterWitness`
compares ten independent expected row/byte-offset/width/access/page
records against the selected concrete MC68332 profile and checks
that the corresponding field name occurs after exactly the table
row address, before the next printed `$YFFAxx` row (allowing
one wrapped label). A wrongly placed/missing folio or mismatched
profile definition cannot pass as complete. The official PDF CI
first validates the fixed publisher digest
`02c2cb99738dd45a785798bba3e7dcc34bb0d54fb5fba42900e6ecb8356bf28a`,
then extracts physical pages 218/219 from the **same** 265-page PDF
and executes source-table tests. Java21 synthetic regression covers
lower-byte offsets, different width/access, wrong/missing folios,
falsified row names and bounded input.

The matching row is a *publisher source address claim*, not
verification of a particular ECU configuration, runtime module
mapping/MM, initialized watchdog, active chip select, physical
memory layout, or authorization for Ghidra Apply. Generic CPU32
never inherits these MC68332-specific registers; no original
ECU411 firmware or user Ghidra project is accessed.
