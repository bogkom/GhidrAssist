# Hardware Analysis — seven-stage implementation ledger

Status as of **2026-10-21, after merged PR #29**: **IN PROGRESS — incremental foundations across all seven areas, not a complete hardware reverse-engineering solution**. Current baseline: `master` commit `6716037459d16ce09a279bfe341e2247816e4b75`. The original `feature/hardware-analysis-seven-stages` branch and older checkpoints below are historical. Check current `master` and merged PRs before implementing any further work.

Owner-facing rule: consolidate implementation and automated validations rather than requesting repeated manual Ghidra tests after every small commit. Unverified MCU identity and execution remain explicit.

| Stage | Goal | Existing evidence | Exit criteria and caveats |
|---|---|---|---|
| 1 | Explicit MCU profiles and sourced register index | CPU32 family, MC68331/332/336/376 candidate TSV, 68332 internal profile | Source-indexed, validated register candidates with model scope and provenance; unknown remains unknown |
| 2 | SIMCR/MM, access widths and P-code/indirect resolution | working stand-alone direct scanner, limited P-code probe | Harden classifications and safely represent state as conditional, not runtime-verified |
| 3 | Real firmware validation / reproducible regressions | `ECU_FLASH 512KB.bin` in private `bogkom/GhidrAssist-Firmware-Tests`; 13 opcode fragments verified at separate offsets against user's Ghidra logs | Run independent byte-level fingerprints and synthetic regression in CI, never upload full firmware to public repository |
| 4 | VBR/TPURAM/CSBOOT/CS0–10 dynamic mappings | several initialization variants, read-only CS-window sketches | Model per-function snapshots, bus-space/lane/RW conditions, alternative epochs; full CFG paths may remain unknown |
| 5 | Safe naming workflow | preview-only CSV | Collision-safe proposal and explicit review; **never** auto-apply uncertain processor names |
| 6 | UI and RAG context | GhidrAssist existing tabs and Markdown RAG | Integrated read-only hardware report view and source-backed, locally exportable context |
| 7 | PDF manuals / register tables | PDFBox page-indexed RAG with uncertainty flags | Table candidate extraction with explicit page and “unverified layout” provenance, no invented semantics |

## Historical foundation — original seven-stage branch

- **Stage 1/4:** `ChipSelectModel.java` implements conditional MC68332 CSBAR base/size, CSPAR pin assignments, CSOR BYTE/RW/SPACE and overlap classification with synthetic regressions. It **does not** compute live runtime states or execution history.
- **Stage 2:** `SimcrMmAnalyzer.java` now includes width-correct direct `CLR.W` and `CLR.B` MM clear candidate classification; broader indirect/CFG propagation remains open.
- **Stage 3:** `FirmwarePatternScanner.java` and its synthetic self-test decode only raw 68k `MOVE.W`, `MOVE.L`, `CLR.W` absolute-long patterns and `MOVEC ...,VBR`. Their matches require Ghidra disassembly validation; **no private firmware is stored in public CI**.
- **Stage 4:** `HardwareInventoryService.java` gives user/profile-labeled read-only Ghidra evidence, conditional per-function CS snapshots and VBR sightings. No dynamic lifetime or predecessor-state claims.
- **Stage 5:** `HardwareNamingReview.java` and integrated hardware report produce **CSV-only**, globally collision-checked label suggestions. CPU32-only mode emits no MCU-specific labels. There is no name-application code.
- **Stage 6:** `HardwareAnalysisTab.java` is added to the extension's tab panel. It runs the scanner with a SwingWorker, exports a Markdown report for manual RAG ingestion and CSV for name review. No API credits or Ghidra project changes.
- **Stage 7:** `ManualRegisterHints.java` adds page-scoped, **explicitly unverified** register/address text-row candidates to RAG PDF indexing when table layout is ambiguous. It never converts candidates into hardware profiles automatically.
- CI: `hardware-profile-tests.yml` tests all pure-Java models; `hardware-extension-build.yml` builds the entire GhidrAssist extension against verified Ghidra 12.1.4. Ghidra script API build remains independent.

### Original firmware evidence and later private-only CI

In the private 524,288-byte test BIN, an even-offset raw byte search found **506** candidate Motorola `33 FC` patterns whose absolute long destination is in `0xFFF000–0xFFFFFF`. This is **not** 506 disassembled instructions or actual executed writes: raw patterns can occur in data and are an independent regression inventory only. Known earlier SIMCR/TRAMBAR/CSBAR7/VBR bytes matched at 13 previously recorded locations. The private file itself is never published in this repo.

### Still genuinely unfinished (post-PR #24)

Exact reset-to-application and interprocedural/exception CFG paths, complete pointer/alias and P-code reasoning, physical CS wiring and active bus-cycle state, a confirmed physical MCU identity, path-sensitive TRAMBAR/CS/VBR memory epochs, broad trustworthy PDF register/bitfield/reset table reconstruction, and a collision-safe undoable **function/variable** rename approval UI. The new bounded SIMCR/MM history counts sites since *function entry*, not accepted writes since hardware reset. Do not describe all seven stages as completed.

## Four-area follow-on (PR #12, 2026-10-21)

- **CFG:** bounded intraprocedural constant propagation with conservative branch joins, loop convergence and call barriers (`HardwareDataflow`). Ghidra Listing flow edges and multi-hop **static** caller evidence are consumed by `GhidraHardwareFlowService`. Indirect or exception-dependent execution order is not proven.
- **Indirect access:** selected A0–A7/D0–D7 immediate constants, copy/arithmetic and simple displacement-based STOREs, plus local P-code constant STORE pointers. Indexed/aliased and unknown branches remain unhandled rather than guessed.
- **Memory epochs:** snapshots after SIMCR/MM, TRAMBAR, CSBAR, CSOR, CSPAR and VBR candidate sites. CS decoding remains MC68332-*conditional*, pin/RW/SPACE restrictions remain necessary, no live ECU state is claimed.
- **AI/RAG + names:** `HardwareEvidenceCache` keeps local evidence per Program after an explicit analysis; relevant Query, Agentic and hardware-related Explain Line prompts receive bounded, prominently caveated evidence. Optional `#hardware` forces retrieval. Existing review-only, collision-checking CSV naming remains; no automatic labels.
- **CI:** `HardwareDataflowSelfTest`, `HardwareContextSelectorSelfTest`, model/address regression and full Ghidra 12.1.4 extension build. Public CI contains synthetic samples only.

**Scope boundary:** the four *implementation tracks* are now represented in code. A fully exact cross-procedure and exception-aware runtime state graph, real-hardware validation and safe flash address inference are **not implemented or proven**. Do not ask for separate manual tests of individual commits; test later as one package after automated validation.

## Post-PR #18 implementation checkpoint (2026-10-21)

| Change | Merged PR | Verification | Main scope |
|---|---|---|---|
| Resizable, bulk-selectable reviewed full MC68332 module regions | [#18](https://github.com/bogkom/GhidrAssist/pull/18) | Previously user-tested and CI passed | D-1 full module apertures, Undo-safe Review / Apply |
| Coordinate-backed PDF D-1 module candidate extraction | [#19](https://github.com/bogkom/GhidrAssist/pull/19) | Java + Ghidra 12.1.4 CI passed | Candidate-only page evidence for RAG, **not** trusted imported CPU definitions |
| Source-backed MC68332 module/field/access metadata | [#20](https://github.com/bogkom/GhidrAssist/pull/20) | Java + Ghidra 12.1.4 CI passed | Appendix D-1/D-2, MM write-once metadata, 8-bit RSR, unknown resets remain unknown |
| Strictly parsed indexed A/D addressing | [#21](https://github.com/bogkom/GhidrAssist/pull/21) | Java + Ghidra 12.1.4 CI passed | CFG-conservative index + scale + displacement; unknown aliases remain unresolved |
| Private raw ECU411 fingerprints | [private PR #1](https://github.com/bogkom/GhidrAssist-Firmware-Tests/pull/1) | Private GitHub Actions passed | 512 KiB Git blob identity, 7 MOVE.W candidates, 3 SIMCR stores, 4 VBR markers; no private artifacts |
| Hardware function naming CSV candidate roles | [#22](https://github.com/bogkom/GhidrAssist/pull/22) | Java + Ghidra 12.1.4 CI passed | No renaming; multiple direct writes + collisions + manual MCU selection |
| Focused AI/RAG evidence sections | [#23](https://github.com/bogkom/GhidrAssist/pull/23) | Java + Ghidra 12.1.4 CI passed | Don't fill focused queries with irrelevant hardware/telemetry sections |
| Function-local MM write candidate path counts | [#24](https://github.com/bogkom/GhidrAssist/pull/24) | Java + Ghidra 12.1.4 CI passed | Bounded 0/1/2+ earlier SIMCR candidate sites, call uncertainty, **not** reset-relative verification |

Detailed docs: [PDF profile metadata](hardware-sourced-profiles.md), [indexed CFG](hardware-indexed-addressing.md), [function naming](hardware-function-naming-review.md), [RAG relevance](hardware-rag-relevance.md), [MM write-once candidate histories](hardware-mm-write-history.md).

**Current testing rule:** automated synthetic and private raw-fingerprint checks are green, but integrated correctness on the actual *Ghidra program database* (including indirect control flow, Memory.join, typed registers, Undo, and hardware-state inference) still requires a future consolidated integration/regression run. Do not misreport pure-Java tests as full execution-path validation.

## Further changes merged after PR #25 (2026-10-21)

| PR | Scope | Evidence and limitations |
|---|---|---|
| [#26](https://github.com/bogkom/GhidrAssist/pull/26) | RAG manual guide, edition/filename-scoped metadata and MC68336/376 D-1 variants | Java + Ghidra 12.1.4 CI passed; TouCAN 384-byte aperture/MC68376-only qualifier remains a **candidate**. [RAG catalog](rag-cpu32-manual-catalog.md) |
| [#27](https://github.com/bogkom/GhidrAssist/pull/27) | Hardware state soundness after unknown/overlapping STOREs | Java + Ghidra 12.1.4 CI passed; unknown aliases now invalidate stale register constants. [Safety notes](hardware-unknown-store-safety.md) |
| [#28](https://github.com/bogkom/GhidrAssist/pull/28) | Resizable **Review names...** for function naming, re-preflight, collision controls and Undoable one-transaction approval | Java + Ghidra 12.1.4 CI passed; actual Ghidra UI interaction still needs eventual consolidated hands-on test. [Guide](hardware-function-rename-approval.md) |
| [#29](https://github.com/bogkom/GhidrAssist/pull/29) | Printed-page candidate metadata alongside physical PDF page, edition-safe source labels | Java + Ghidra 12.1.4 CI passed; header-missing/ambiguous labels remain UNKNOWN. |
| [private PR #2](https://github.com/bogkom/GhidrAssist-Firmware-Tests/pull/2) | Verified Ghidra 12.1.4 headless decoding of seven ECU411 MOVE.W and four MOVEC VBR sites in a disposable private project | **Private** headless and raw fingerprint workflows passed; no CFG execution, function naming, MCU identification or hardware wiring validation. |

**Remaining high-value tracks (not complete):** broaden verified register/bitfield/reset tables across actual PDF editions with document-specific geometry tests, resolve interprocedural reset/exception paths and bus-state conditions, add local variable/pointer naming with alias/risk controls, and verify Hardware Review/Undo/RAG behavior in a consolidated real Ghidra project test. Firmware identity remains a hypothesis. The published public CI contains no private BIN.

## Verified test firmware facts

- Private repo: `bogkom/GhidrAssist-Firmware-Tests`, `main`, file `ECU_FLASH 512KB.bin`, 524288 bytes, Git blob SHA `9a27ebc2c216a8888e8d49ab2f7d34ca03ac85f9`.
- At file offsets `0x2BCA`, `0x2BD2`, `0x2D22`, `0x9C98`, `0x9D62`, `0x6E96C`, `0x6EAC8`, the raw bytes match the absolute `MOVE.W #imm,(0xFFxxxx).L` initialization sites reported in Ghidra.
- Four `MOVEC A0,VBR` instruction prefixes are also present at `0x3050`, `0x8440`, `0x6E670`, `0x700A0`.
- This comparison is not yet a full binary hash match against Ghidra's local import.
- Keep private binary outside public repository, artifacts and public GitHub Actions logs.

## Continuation / incident procedure

1. Inspect current `master`, merged PRs **#18–#29**, and the latest GitHub Actions runs. Do not repeat completed work.
2. Inspect the private `bogkom/GhidrAssist-Firmware-Tests` repository for its merged PR **#1** and private Actions, but never publish or copy `ECU_FLASH 512KB.bin` into this public repository.
3. Use isolated feature branches and commit a validated implementation batch before PR. Both pure-Java tests and the exact Ghidra 12.1.4 extension build must pass for relevant code changes.
4. Merge through PR only after successful checks. Never publish a stable GitHub Release without owner approval; keep Ghidra memory/symbol modifications reviewed and undoable.
5. Resume from this ledger and the linked files without requiring the owner to restate the seven-point scope.

No MCU identification, verified RAM wiring, active runtime path or u-Link NT programming address may be asserted from static candidate matches.
