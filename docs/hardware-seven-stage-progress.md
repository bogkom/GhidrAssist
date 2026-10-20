# Hardware Analysis — seven-stage implementation ledger

Status: **IN PROGRESS**; branch `feature/hardware-analysis-seven-stages`.
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
