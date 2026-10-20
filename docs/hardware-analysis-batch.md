# Hardware-analysis script batch — Ghidra 12.1.4

**Status: experimental, script-only.** Changes in this batch have not yet been compiled or run against the user's Ghidra installation. The original working `GhidrAssist_SIMCR_MM_Report.java` remains unchanged. No automatic changes to the Ghidra program, ECU, u-Link NT, memory blocks, symbols or code.

## Why this batch exists

On `ECU_FLASH 512KB.bin` the earlier standalone reconnaissance, using an MC68332-specific address catalog under the generic CPU32 ISA, found 111 candidate sites in 120,461 disassembled instructions. Three major potential initialization functions were identified by the existing Ghidra names, with distinct values in CSPAR1, CSBAR2 and five CSOR registers. Such candidate matches **do not prove** the ECU uses an MC68332, that these functions execute, or that an address window is active.

## One installation, one later test round

Copy the new files from the GitHub `ghidra_scripts` directory into an **enabled Ghidra Script Manager source directory**. Keep the already working `hardware_profiles.tsv` beside the scripts:

| Script | What it does | Requires extension rebuild? |
|---|---|---|
| `GhidrAssist_SIMCR_MM_Report.java` | Existing working CPU32 SIMCR/register reference inventory | No; unchanged |
| `GhidrAssist_ChipSelect_Map.java` | Conditional MC68332 CSBAR, CSOR and CSPAR candidate windows per function, overlaps, direct callers, VBR sites | No |
| `GhidrAssist_Pcode_Address_Probe.java` | P-code constant STORE addresses, conservative local address-register pointers, VBR instruction sites | No |
| `GhidrAssist_Export_Hardware_Context.java` | Generate a Markdown evidence report suitable for manual GhidrAssist RAG import and a CSV of **review-only** candidate labels | No |

When testing this batch, run the three **new, uniquely named scripts** against the same Ghidra program and send their logs or generated report. There is no need to reinstall or compile the GhidrAssist extension for these script-only changes. The export script **asks you to select a destination**; it writes the Markdown and adjacent `_name_preview.csv` only after the selection. It asks confirmation before replacing either existing file. None of the scripts alters the Ghidra database.

For the markdown: go to GhidrAssist's RAG tab and manually add the generated `.md` to the desired document library. This is an **import handoff**, not automatic integration or proof that AI will use the source correctly.

## Expanded CPU32 family evidence catalog

The optional `hardware_profiles.tsv` now includes **120 additional documented candidate entries**, on top of the earlier MC68332 index:

- **MC68331:** SIMCR/MM at both module-map locations (NXP [MC68331 Technical Summary](https://www.nxp.com/docs/en/data-sheet/MC68331TS.pdf)).
- **MC68336 and MC68376:** SIMCR/SYNCR, CSBOOT and CS0..10 CSPAR/CSBAR/CSOR, and `QADCMCR` (NXP [MC68336/376 Register Summary](https://www.nxp.com/docs/en/user-guide/MC68336376UMD.pdf)).
- **MC68376 only:** `CANMCR` (TouCAN module at `YFF080`), which can be a useful distinguishing clue when the firmware directly accesses it.

**Interpretation:** CPU32 mode will find many common SIM register addresses associated with several possible MCU models. Do not count this as multiple different hits or assign a chip model from shared register addresses. A TouCAN-specific address can strengthen a hypothesis but still does not prove physical processor identity; bus writes can refer to external peripherals, unused space or other devices. The standalone chip-select map script deliberately remains **MC68332-specific** until bitfield compatibility of other devices is implemented and verified.

## Interpretation principles

1. The selected Ghidra ISA `68000:BE:32:CPU32` is **not a processor identification**. The MCU-specific meaning of 0xFFFA00 and other addresses remains conditional on the real chip.
2. A **CSBAR** value specifies candidate base/size only. For MC68332, the BLKSZ table is 2/8/16/64/128/256/512/1024 KiB and base address is selected by ADDR[23:11].
3. **CSOR** constrains byte-lane, R/W, function code/address space, timing and bus response. **CSPAR** assigns pins to CS output or alternate/discrete function. Decode all together; boot CS has distinct reset rules. The CSOR BYTE field is relevant to 16-bit port handling and must not be used as a universal enable bit for every port.
4. MM is write-once after reset on MC68332. Reports group candidate register writes **within individual disassembled functions only**, in Listing order; they do not prove reset order, branch reachability or last-write-wins across actual execution paths.
5. Possible address-window **overlap is not a definitive conflict**, since bus function codes, R/W, priorities, reset state and pin modes may make windows mutually exclusive.
6. VBR is a CPU control register, not the SIM memory map. It must be resolved separately. Likewise, TRAMBAR and other movable internal regions require verified bit-field decoding.
7. No observed CSBAR/CSOR pair identifies attached flash/RAM without verified wiring. **Never use an inferred window directly as a programming address with u-Link NT**.

Primary device reference: [MC68332 User's Manual](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf), particularly system integration module and Appendix D register maps.


## Field-test results: second batch (2026-10-20)

The user successfully ran all three batch scripts on `ECU_FLASH 512KB.bin` (`68000:BE:32:CPU32`):

- `GhidrAssist_ChipSelect_Map.java`: 120,461 disassembled instructions scanned; **96** candidate register sites in the chip-select-map subset (as expected, this script does not include all registers used by the broad reconnaissance scanner). Three possible configuration groups appeared in Ghidra functions `fun_reset` (31 sites; direct callers at `0x3020` and `0x3308`), `configure_sim_qsm_tpu_and_chip_selects` (28 sites; caller at `0x8468`) and `app_initialize_hardware` (31 sites; caller at `0x6E658`). Caller XREFs do **not** establish live execution.
- `GhidrAssist_Pcode_Address_Probe.java`: 4 `MOVEC ...,VBR` candidate sites at `0x3050`, `0x8440`, `0x6E670` and `0x700A0`. Two tentative source values `0x000000`, two unresolved. **0 extra P-code / register-indirect matched addresses** — this means the current restricted algorithm found no additional candidates, *not* that indirect hardware writes do not exist.
- `GhidrAssist_Export_Hardware_Context.java`: generated a local Markdown RAG source with **111** references across **32** distinct candidate addresses. The original CPU32-family CSV mistakenly proposed device-specific names for unverified processors; this revision intentionally suppresses those proposals in family mode.
- The default Ghidra Save dialog originally led to names ending `.txt.md`. The exporter now converts the dialog's `.txt` extension to `.md`, and derives a matching `_name_preview.csv` filename.

For potential MC68332 register semantics, **CSBOOT 512 KiB at `0x000000–0x07FFFF`** matches the firmware image size, but this is *not* proof of wiring/boot source. **CS0/CS1 both cover `0xF80000–0xF8FFFF`** with separate lower/upper BYTE assignments; **CS9 covers `0xF00000–0xFFFFFF`** but may differ by RW, bus function codes or other runtime gating. The decoder now labels shared address ranges by the known access conditions, rather than declaring every overlap a conflict.

The [MC68332 User's Manual, section 4.8 and tables 4-20 through 4-22](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf) defines CSPAR 2-bit pin assignments, CSBAR block sizes, BYTE lane selection and CSOR access/function-space fields. Particular cautions: CSOR BYTE=`00` disables chip-select assertion, R/W=`00` is reserved, SPACE=`00` is CPU space rather than ordinary program/data memory, and upper/lower BYTE pairs are often intentional. Internal register/RAM accesses take precedence over matching external chip-select targets.

**Still to verify:** the real processor, multi-function execution order, branch-sensitive register values, time-varying MM/TRAMBAR/VBR maps, external device wiring and u-Link NT access routes. Do not flash an inferred window or automatically modify any Ghidra symbol.

## Work remaining — seven planned areas

| Planned area | Covered in batch | Important remaining tasks |
|---|---|---|
| 1. Processor profiles and register index | MC68331/332/336/376 candidate TSV; script-only model definitions | Add other **verified** concrete MCUs; widths, reset values, field tables, source page refs |
| 2. SIMCR/MM and related register access | Earlier scanner plus local P-code and address-register heuristics | Full intra/inter-basic-block SSA propagation, branch-sensitive execution ordering |
| 3. Actual firmware tests | Previous scanner was tested successfully | **These three new scripts have not been run in Ghidra**; test and fix API/runtime issues |
| 4. VBR and **all dynamic memory areas**, especially chip selects | Conditional per-function CSBAR/CSOR/CSPAR hypotheses, VBR sightings | Full state graph from reset, CSBOOT behavior, peripheral RAM, MM, access function codes, alternate buses, CPU-space and overlap priority |
| 5. Naming | Review-only candidate names exported to CSV | Verified profile plus explicit user approval; optional reversible Ghidra transaction, collision checks |
| 6. UI and RAG/AI | Markdown report importable in existing RAG | Native UI, evidence-backed search at analysis time, source-page citations and automatic context routing |
| 7. Robust PDF knowledge | Existing PDF page-aware indexing from earlier work remains | Verified table/relation extraction, address and bit-field parsing with provenance, OCR optionally later |

The batch is **not** a claim that all seven milestones are finished. At most it advances prototypes in several areas simultaneously. The separate reminder for reviewing dynamic chip-select maps with u-Link NT remains gated on confirmed completion of the majority of phases, including full stage 4.
