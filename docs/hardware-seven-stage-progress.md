# Hardware Analysis — seven-stage implementation ledger

Status: **IN PROGRESS — several implemented components, not seven fully validated stages**; branch `feature/hardware-analysis-seven-stages`.
Last planned baseline: `master` commit `c64cff446f5b54e780ba1a83b3386ce1dd296369`.
Owner-facing rule: **no requests for manual script tests until all seven areas have implementation and automated validations**. Work must remain restartable by checking branch commits and GitHub Actions.

| Stage | Goal | Existing evidence | Exit criteria and caveats |
|---|---|---|---|
| 1 | Explicit MCU profiles and sourced register index | CPU32 family, MC68331/332/336/376 candidate TSV, 68332 internal profile | Source-indexed, validated register candidates with model scope and provenance; unknown remains unknown |
| 2 | SIMCR/MM, access widths and P-code/indirect resolution | working stand-alone direct scanner, limited P-code probe | Harden classifications and safely represent state as conditional, not runtime-verified |
| 3 | Real firmware validation / reproducible regressions | `ECU_FLASH 512KB.bin` in private `bogkom/GhidrAssist-Firmware-Tests`; 13 opcode fragments verified at separate offsets against user's Ghidra logs | Run independent byte-level fingerprints and synthetic regression in CI, never upload full firmware to public repository |
| 4 | VBR/TPURAM/CSBOOT/CS0–10 dynamic mappings | several initialization variants, read-only CS-window sketches | Model per-function snapshots, bus-space/lane/RW conditions, alternative epochs; full CFG paths may remain unknown |
| 5 | Safe naming workflow | preview-only CSV | Collision-safe proposal and explicit review; **never** auto-apply uncertain processor names |
| 6 | UI and RAG context | GhidrAssist existing tabs and Markdown RAG | Integrated read-only hardware report view and source-backed, locally exportable context |
| 7 | PDF manuals / register tables | PDFBox page-indexed RAG with uncertainty flags | Table candidate extraction with explicit page and “unverified layout” provenance, no invented semantics |

## Implemented in this branch — restart checkpoint

- **Stage 1/4:** `ChipSelectModel.java` implements conditional MC68332 CSBAR base/size, CSPAR pin assignments, CSOR BYTE/RW/SPACE and overlap classification with synthetic regressions. It **does not** compute live runtime states or execution history.
- **Stage 2:** `SimcrMmAnalyzer.java` now includes width-correct direct `CLR.W` and `CLR.B` MM clear candidate classification; broader indirect/CFG propagation remains open.
- **Stage 3:** `FirmwarePatternScanner.java` and its synthetic self-test decode only raw 68k `MOVE.W`, `MOVE.L`, `CLR.W` absolute-long patterns and `MOVEC ...,VBR`. Their matches require Ghidra disassembly validation; **no private firmware is stored in public CI**.
- **Stage 4:** `HardwareInventoryService.java` gives user/profile-labeled read-only Ghidra evidence, conditional per-function CS snapshots and VBR sightings. No dynamic lifetime or predecessor-state claims.
- **Stage 5:** `HardwareNamingReview.java` and integrated hardware report produce **CSV-only**, globally collision-checked label suggestions. CPU32-only mode emits no MCU-specific labels. There is no name-application code.
- **Stage 6:** `HardwareAnalysisTab.java` is added to the extension's tab panel. It runs the scanner with a SwingWorker, exports a Markdown report for manual RAG ingestion and CSV for name review. No API credits or Ghidra project changes.
- **Stage 7:** `ManualRegisterHints.java` adds page-scoped, **explicitly unverified** register/address text-row candidates to RAG PDF indexing when table layout is ambiguous. It never converts candidates into hardware profiles automatically.
- CI: `hardware-profile-tests.yml` tests all pure-Java models; `hardware-extension-build.yml` builds the entire GhidrAssist extension against verified Ghidra 12.1.4. Ghidra script API build remains independent.

### Original firmware private validation (outside public CI)

In the private 524,288-byte test BIN, an even-offset raw byte search found **506** candidate Motorola `33 FC` patterns whose absolute long destination is in `0xFFF000–0xFFFFFF`. This is **not** 506 disassembled instructions or actual executed writes: raw patterns can occur in data and are an independent regression inventory only. Known earlier SIMCR/TRAMBAR/CSBAR7/VBR bytes matched at 13 previously recorded locations. The private file itself is never published in this repo.

### Still genuinely unfinished

Full multi-basic-block constant propagation, branch-aware state transitions, reset path selection, MM write-once timing, peripheral RAM relocation, chip-select bus function codes and physical wiring validation, robust PDF table geometry, and optional reversible **manually approved** renaming. Tests against the user's installed Ghidra session are still outstanding; do not describe all seven stages as complete.

## Verified test firmware facts

- Private repo: `bogkom/GhidrAssist-Firmware-Tests`, `main`, file `ECU_FLASH 512KB.bin`, 524288 bytes, Git blob SHA `9a27ebc2c216a8888e8d49ab2f7d34ca03ac85f9`.
- At file offsets `0x2BCA`, `0x2BD2`, `0x2D22`, `0x9C98`, `0x9D62`, `0x6E96C`, `0x6EAC8`, the raw bytes match the absolute `MOVE.W #imm,(0xFFxxxx).L` initialization sites reported in Ghidra.
- Four `MOVEC A0,VBR` instruction prefixes are also present at `0x3050`, `0x8440`, `0x6E670`, `0x700A0`.
- This comparison is not yet a full binary hash match against Ghidra's local import.
- Keep private binary outside public repository, artifacts and public GitHub Actions logs.

## Continuation / incident procedure

1. Inspect `feature/hardware-analysis-seven-stages` and last commit; inspect CI.
2. Read this ledger and the changed files, continue on the same branch.
3. Make a commit after each completed independent component, rather than a giant uncommitted patch.
4. Open a PR only after meaningful checks; merge only when the relevant automated checks pass.
5. If interruption occurs, next assistant may resume by examining last commit/PR without requiring the user to repeat goals.

No MCU identification, verified RAM wiring, active runtime path or u-Link NT programming address may be asserted from static candidate matches.
