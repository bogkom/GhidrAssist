# RAG manual set for CPU32 / MC683xx (source and edition manifest)

**Scope:** engineering reference material only. An opened program with Ghidra language `68000:BE:32:CPU32` does **not** identify its physical MCU. Selecting MC68332 for ECU411 is an explicit hypothesis. This document is a recommended **download / RAG ingestion checklist**, not a statement that a PDF has already been downloaded or indexed. Revisions and official filenames are significant; never silently transfer offsets, reset values, or register fields between devices.

## Priority A: essential manuals

| RAG library | Original filename | Publisher source | Purpose / model scope |
|---|---|---|---|
| `CPU32-common` | `M68000PRM.pdf` | [NXP Programmer's Reference](https://www.nxp.com/docs/en/reference-manual/M68000PRM.pdf) | Motorola 68000 programmer reference incl. CPU32 instruction semantics, address forms, MOVEC/VBR, stack and exceptions; **not** an MCU peripheral map |
| `MC68332` | `MC68332UM.pdf` | [NXP MC68332 User's Manual](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf) | Device authority: Appendix D register summary, SIM/SIMCR, CS/TPU/QSM/TPURAM (265 PDF pages in checked copy) |
| `MC68336-376` | `MC68336376UM.pdf` | [NXP MC68336/376 User's Manual](https://www.nxp.com/docs/en/user-guide/MC68336376UM.pdf) | **Combined** manual (434 PDF pages in checked copy); MC68336 and MC68376 do not have identical modules |
| `MC68336-376` | `MC68336376UMD.pdf` | [NXP separate Appendix D](https://www.nxp.com/docs/en/user-guide/MC68336376UMD.pdf) | **Separately paginated** 94-page register summary; do not confuse page index with full-manual Appendix D |
| `CPU32-common` | `SIMRM.pdf` | [NXP SIM reference](https://www.nxp.com/docs/en/reference-manual/SIMRM.pdf) | SIM functionality and CS/boot semantics; device-specific variants must be checked in the appropriate user's manual |

## Priority B: targeted module manuals and model comparisons

| RAG library | Filename | Publisher source | What to use it for |
|---|---|---|---|
| `MC68331` | `MC68331UM.pdf` | [NXP MC68331 documentation](https://www.nxp.com/products/MC68331) | MC68331 device-specific SIM, QSM and GPT; PDF available via NXP product's documents, **direct PDF URL not verified here** |
| `MC68331` | `MC68331TS.pdf` | [NXP MC68331 documentation](https://www.nxp.com/products/MC68331) | Technical summary, fast feature comparison, **not** a substitute for UM register tables |
| `MC68332` | `MC68332TS.pdf` | [NXP MC68332 documentation](https://www.nxp.com/products/MC68332) | Feature/functional block comparison, not detailed hardware reset truth |
| `CPU32-common` | `TPURM.pdf` | [NXP TPU reference](https://www.nxp.com/docs/en/reference-manual/TPURM.pdf) | TPU/TPU2 operation, channel modes and microcode feature differences |
| `MC68336-376` | `MC68336376UM05.pdf` | [NXP separate section 5](https://www.nxp.com/docs/en/user-guide/MC68336376UM05.pdf) | SIM, reset, chip selects and bus; print 5-1 starts on PDF page 1 |
| `MC68336-376` | `MC68336376UM12.pdf` | [NXP separate section 12](https://www.nxp.com/docs/en/user-guide/MC68336376UM12.pdf) | TPURAM, including 3.5 KiB RAM behavior |
| `MC68376-only` | `MC68336376UM13.pdf` | [NXP separate section 13](https://www.nxp.com/docs/en/user-guide/MC68336376UM13.pdf) | **TouCAN is model-specific; never assign it to MC68336/MC68332** |
| `MC68336-376` | `MC68336376UM08.pdf` | [NXP separate section 8](https://www.nxp.com/docs/en/user-guide/MC68336376UM08.pdf) | QADC module |
| `MC68336-376` | `MC68336376UM10.pdf` | [NXP separate section 10](https://www.nxp.com/docs/en/user-guide/MC68336376UM10.pdf) | CTM4 module |
| `MC68336-376` | `MC68336376UM09.pdf` | [NXP separate section 9](https://www.nxp.com/docs/en/user-guide/MC68336376UM09.pdf) | QSM detailed interactions |
| `MC68336-376` | `MC68336376UM11.pdf` | [NXP separate section 11](https://www.nxp.com/docs/en/user-guide/MC68336376UM11.pdf) | TPU section |

NXP also lists **CPU32RM** (architecture), **QSMRM** (queued serial), **GPTRM** (GPT), **QADCRM** (QADC), and **CTMRM** (timer). Some reference PDFs are marked **Account Required** on NXP; do not promise unauthenticated direct downloads. Prefer the official product document list and verify rights and revision. See [NXP MC68331 documents](https://www.nxp.com/products/MC68331) and [MC68376 documents](https://www.nxp.com/products/MC68376?tab=Documentation_Tab).

## Known Appendix D pagination: exact PDF edition matters

| Source PDF | Printed D-1 | Physical PDF page (1-based) | Evidence |
|---|---|---:|---|
| `MC68332UM.pdf` (checked complete copy) | D-1, `Table D-1 Module Address Map` | **215** | SIM=128 @$YFFA00, TPURAM CNTL=64 @$YFFB00, QSM=512 @$YFFC00, TPU=512 @$YFFE00 |
| `MC68336376UM.pdf` (checked complete copy) | D-1 | **319** | Table D-1 lists additional SRAM, MRM, QADC, CTM4 and TouCAN; model exclusions are meaningful |
| `MC68336376UMD.pdf` (checked standalone Appendix D) | D-1 | **1** | Same printed D-1 but independent PDF page indexing |

PDF references are edition-specific, not fixed constants applicable to alternate scanners/revisions. The same printed page may occur at several PDF offsets. A PDF with a different basename such as `apdreg.pdf` is **UNKNOWN until manually identified**; do not infer its MCU from Appendix D alone.

## Ingestion strategy

1. **Use distinct RAG libraries/model tags**: `CPU32-common`, `MC68331`, `MC68332`, `MC68336-376`, and `external-CAN` where supported. The current application library model may not expose these exact library IDs; they are suggested source groups, **not UI options promised to exist**.
2. Prefer **one authoritative complete manual per model** first. If also indexing split chapters for more precise page references, keep them as **separate documents** with original filenames. Avoid unnecessary full/split duplicates in a single narrow search.
3. Keep original filename, manufacturer, revision or mask set, SHA-256, PDF page (1-based), printed page, chapter/table number, and applicability. Treat PDF text extraction and detected columns as **unverified** until source layout is inspected. The application currently saves source name/path, hash and PDF page; not all revision/printed-page fields are fully indexed.
4. A PDF row that merely resembles a register is not enough to auto-create CPU profiles, hardware names or Ghidra data. Bit positions, reset values, access widths and low/high byte positions require verified diagrams and a device-scope match.
5. For external CAN clues (`0xFF8800` CS7 candidate), keep Bosch CC770 and Intel 82527 manufacturer documentation in a separate `external-CAN` group. Their 15-object register similarities must **not** prove the exact controller or MCU; retrieve an authorized copy from the manufacturer/distributor rather than an unverified mirror.
6. Do **not** index firmware binary, exported proprietary disassembly or the private ECU411 image into a public/shared RAG source; cloud AI queries may transmit selected context.

## What the implementation can validate automatically

- Exact known canonical filenames can tag a **document identity candidate** and its model scope in RAG chunks. This is not CPU detection: source labels explicitly state `FILENAME_MATCH_ONLY`.
- A standalone Appendix D remains a different RAG document from its full-book counterpart.
- Module table extraction admits non-power-of-two widths, especially **TouCAN 384 bytes** from the 68336/376 table; the `(MC68376 Only)` restriction is retained in extracted candidate evidence.
- All detected PDF geometry rows remain non-actionable until checked against source diagrams and a deliberately chosen CPU profile.

## Printed page label enhancement

On import, a PDF page chunk now includes both `pdf_page` (1-based physical PDF
page) and, where a manufacturer's **User's Manual header** contains a clear
page label, `printed_page=D-1` or `printed_page=5-1` with the flag
`PDF_TEXT_HEADER_CANDIDATE`. If missing or ambiguous, `printed_page=UNKNOWN`
is explicitly recorded. The detector never promotes `Table D-1` in body
text into a printed page index. Unlike a PDF page number, a printed page
label is relative to the manual's original layout and may be shared by both
a full book and its separately published chapter.

This remains text-layer evidence only. Alternative manufacturers' PDFs may
use different headers; geometry/visual inspection is still necessary before
auto-importing bitfield tables.

## Version / provenance checklist when collecting PDFs

Use the original manufacturer basename when possible (the index's filename collisions are not silently merged). For another revision with the same name, retain it in a clearly named local version folder and review the application’s same-name handling before indexing it alongside the earlier edition. A renamed variant should initially remain UNKNOWN in automatic filename-scoping, rather than pretending to have the original document's verified revision.

Never infer that **MC68331**, **MC68332**, **MC68336**, and **MC68376** have interchangeable peripheral register tables merely because CPU32 instruction semantics overlap.
