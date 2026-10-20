# Hardware Analysis: CPU profiles and dynamic address-space mapping

**Status:** experimental implementation merged to `master`. Compiled and installed with Ghidra 12.1.4 by the project user; initial read-only script test on a real ECU firmware completed. The physical processor identity is **not verified** for that firmware.

## Evidence and selection

The Ghidra language ID 68000:BE:32:CPU32 describes an instruction architecture, **not a concrete processor**. The generic CPU32 profile must not silently inherit MC68332 peripheral maps. MC68332 must be chosen explicitly (or supported independently by convincing hardware/firmware evidence).

Initial MC68332 register definitions in HardwareProfiles.java are based on the [NXP MC68332 technical summary](https://www.nxp.com/docs/en/data-sheet/MC68332TS.pdf). Expand the index using the original PDF manuals, documenting each address, bit field, width, permission, reset value, source page and confidence. Never assume that a partial catalog is exhaustive.

## Phases / progress

1. **Profiles and register index — IN PROGRESS:** CPU32 generic profile plus initial MC68332 register catalog for SIMCR, SYNCR, CSPAR0/1, CSBARBT/CSORBT and CSBAR0..10/CSOR0..10; MM-dependent internal register location; preliminary CSBAR window-size decoder. Not a complete device register index.
2. **SIMCR/MM read-only analyzer — FIRST IMPLEMENTATION:** Scan XREF and direct operands for potential SIMCR accesses at both candidate locations. Report candidate immediate word writes and distinguish definite bit effects at the instruction level from unresolved cases. Static sites do not prove runtime execution order. Follow-up: P-code analysis, constant propagation, register-based pointers, byte accesses to SIMCR+1, control-flow reasoning.
3. **Test in real firmware — IN PROGRESS:** Initial run on `ECU_FLASH 512KB.bin` using a user-selected, **hypothetical** MC68332 profile found three direct word stores to `0xFFFA00`, at `0x00002BCA` (`0x40CA`), `0x00009C98` (`0x4848`) and `0x0006E96C` (`0x40CA`), scanning 120,461 instructions with three XREFs. All values have bit 6 (`0x0040`) set. No actual processor identity or runtime execution has been verified. Next: inspect containing functions, reset/init paths, indirect writes, false positives and a test with a confirmed MC68332 program.
4. **VBR, memory and chip-select dynamic mapping — NOT STARTED:** Detailed requirements below.
5. **Proposed safe naming — NOT STARTED:** evidence-backed names, confidence levels, collision avoidance, preview and user approval, reversible Ghidra transaction.
6. **Hardware Analysis UI and RAG/AI integration — NOT STARTED:** register-aware context with traceable source PDF pages; deterministic evidence analysis must not need LLM calls.

### Experimental usage

Run ghidra_scripts/GhidrAssist_SIMCR_MM_Report.java directly in Ghidra Script Manager. It is standalone; no extension build is required for script-only updates. Select CPU32 for exploratory investigation or a concrete, evidenced device for conditional bit decoding. Output is read-only and appears in the script console. The permanent UI is planned for stage 6.

## Required stage 4: all dynamically determined address spaces

**Never replace the following with a single, fixed address-to-device table.** Track a series or graph of candidate hardware states, each with a sequence of writes, originating path, supporting instruction addresses, confidence and unresolved assumptions.

- **SIMCR MM relocation:** Both 4 KiB internal module windows, 0x7FF000–0x7FFFFF (MM=0) and 0xFFF000–0xFFFFFF (MM=1). Include initial states, device-specific restrictions and uncertain control flow. **MC68332-specific constraint:** MM is write-once after reset ([MC68332 User's Manual, D.2.1](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf)); several instruction sites writing MM=1 cannot be counted as repeated successful relocations. A write to `0xFFFA00` only addresses SIMCR if the MM=1 mapping is active at that point.
- **All chip selects:** CSBOOT and CS0..10. Resolve CSBAR address + block size (2 KiB to 1 MiB), CSOR access conditions and timing, CSPAR pin assignments. Do not equate a CSBAR range with an enabled/selected device.
- **Bus-address-space dimensions:** As applicable, model supervisor/user, program/data/CPU-space function codes, interrupt acknowledge, read/write, 8/16-bit port and byte lanes, DSACK/wait states, precedence and possible overlapping windows.
- **All dynamically relocated internal regions:** Include modules and parameter RAM such as SIM, QSM, TPU and TPURAM/TRAMBAR where supported by the **selected device**, not by CPU32 architecture alone.
- **VBR and vector table:** Track changes in vector-base location and exception-vector addressing separately from changes in chip-select mappings.
- **Conditional and evolving configuration:** Track reset/boot state, branch-dependent writes, last-write-wins where provable, ambiguous order and competing maps. Present alternatives rather than inventing a single certain final configuration.
- **External device association:** An address window does not prove ROM, RAM, flash or peripheral contents. Report chip-select behavior separately from board-specific wiring.
- **u-Link NT relevance:** Provide a later export of candidate active regions with size, effective access conditions, confidence, programming/debugging caveats and exact code evidence for user review with [u-Link NT](https://www.usbjtag.com/). No physical hardware programming is implemented or assumed.



### Standalone script (no extension rebuild needed)

The entry-point `ghidra_scripts/GhidrAssist_SIMCR_MM_Report.java` is now a **standalone GhidraScript**. Its CPU32 mode performs cautious **family reconnaissance**, rather than stopping with an error. A selected device profile gives conditional decoding of immediate writes and reports the corresponding function. Neither mode changes the Ghidra database.

Copy **only the updated Java script** into a Script Manager source directory and refresh the script list. This does not require rebuilding or reinstalling the main GhidrAssist extension. The script has built-in MC68332 SIMCR candidate locations (`0x7FFA00`, `0xFFFA00`) so it still works without any companion file.

To extend it with new devices or register candidates, place `ghidra_scripts/hardware_profiles.tsv` beside the script and edit it. Its rows have seven **TAB-separated** columns:

```text
processor_id  family  register  absolute_address  width_bits  bit_mask  role
```

The spaces above are for illustration; actual entries must use TAB characters. Role `SIMCR_MM` enables *conditional* bit decoding and requires a documented, low-byte MM mask in a 16-bit register. Role `OTHER` records an access without making up bit semantics. Processor profiles must be based on documented evidence; do not copy MC68332's addresses to every CPU32 device. The optional TSV is **additional** to the built-in MC68332 profile; adding rows expands the selectable devices and families. An incorrect or conflicting row raises an error instead of being silently accepted.

**Interpreting CPU32 mode:** a hit means "this instruction refers to an address used by a documented candidate device", not "this binary uses that exact chip". With the initial catalog, CPU32 uses only MC68332 candidate addresses; the scope becomes broader as verified profiles are added. Results include the containing function, existing Ghidra symbol if any, matching candidate registers and limitations. Indirect writes and actual runtime paths are not resolved yet.

### Second field-test milestone: extended MC68332 register search

After the initial CPU32 reconnaissance test on `ECU_FLASH 512KB.bin` identified three potential SIMCR/MM write sites in functions `fun_reset`, `configure_sim_qsm_tpu_and_chip_selects` and `app_initialize_hardware`, the optional `ghidra_scripts/hardware_profiles.tsv` catalog was populated with additional **documented MC68332 register-address candidates**.

The catalog adds SYNCR, CSPAR0/1, CSBARBT/CSORBT, CSBAR0..10/CSOR0..10, TRAMMCR/TRAMBAR, QSMCR and TPUMCR, at both MM=0 and MM=1 locations, using Appendix D of the [MC68332 User's Manual](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf). This is an **exploratory index**, not an instruction that firmware uses MC68332 or that any chip select is active.

To test without recompilation: download **only** `ghidra_scripts/hardware_profiles.tsv` from GitHub, copy it **beside the existing working Java script** in the Script Manager source directory, and run the script in `CPU32` mode. Verify that output includes `Additional hardware catalog:` with the loaded file path and new-entry count; if that line does not appear, the TSV is in the wrong directory. The Java script and extension do not need to be replaced.

This milestone only catalogs accesses; **do not** treat immediate words written to CSBAR or CSOR as a final map. The future path-aware decoder must combine CSBAR size/base, CSOR enable/access conditions, CSPAR pin mode, bus function codes, and firmware execution phase (and recognize indirect writes). `VBR` is a CPU control register, not a memory-mapped SIM register and must be analyzed separately.

### First field-test record (2026-10-20)

- Program: `ECU_FLASH 512KB.bin`; Ghidra language `68000:BE:32:CPU32`; device profile **manually selected** as `MC68332` for a provisional test, **not confirmed hardware identification**.
- Script: `ghidra_scripts/GhidrAssist_SIMCR_MM_Report.java`.
- Result: 120,461 disassembled instructions scanned; 3 XREFs to relevant SIMCR candidate locations; 3 `SET_MM` **candidate instruction sites**, no matching clear sites.
- Candidate writes: `0x00002BCA: MOVE.W #0x40CA,($00FFFA00).L`; `0x00009C98: MOVE.W #0x4848,($00FFFA00).L`; `0x0006E96C: MOVE.W #0x40CA,($00FFFA00).L`.
- Conditional decode for an actual MC68332 SIMCR: both constants encode MM=1; `0x40CA` contains SUPV=1 and IARB=10, `0x4848` contains SUPV=0 and IARB=8. Other SIMCR fields differ too.
- Evidence limits: these are **static code sites** only. They do not establish that all branches execute, that MM is updated three times, or that the processor is MC68332. The active map must be resolved before interpreting writes as peripheral effects.
- Follow-up: group findings by containing function and callers; check firmware entry/reset initialization; look for register-indirect writes and chip-select setup. Do not automatically change Ghidra labels.

### Evidence classification

Manual-verified device facts, code-located facts, path-dependent possibilities, inferred register values, and externally confirmed physical wiring must be kept distinct. Avoid silent renaming or automatic memory-block creation from uncertain hypotheses.

### Milestone reminder

Once **at least four of the six stages** are verified completed, **including stage 4**, remind the user to review every dynamic chip-select window and associated address space in the context of u-Link NT. Do not trigger the reminder earlier.
