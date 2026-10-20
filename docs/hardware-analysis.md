# Hardware Analysis: CPU profiles and dynamic address-space mapping

**Status:** experimental implementation on feature/hardware-analysis. No claim of a successful compile or firmware validation.

## Evidence and selection

The Ghidra language ID 68000:BE:32:CPU32 describes an instruction architecture, **not a concrete processor**. The generic CPU32 profile must not silently inherit MC68332 peripheral maps. MC68332 must be chosen explicitly (or supported independently by convincing hardware/firmware evidence).

Initial MC68332 register definitions in HardwareProfiles.java are based on the [NXP MC68332 technical summary](https://www.nxp.com/docs/en/data-sheet/MC68332TS.pdf). Expand the index using the original PDF manuals, documenting each address, bit field, width, permission, reset value, source page and confidence. Never assume that a partial catalog is exhaustive.

## Phases / progress

1. **Profiles and register index — IN PROGRESS:** CPU32 generic profile plus initial MC68332 register catalog for SIMCR, SYNCR, CSPAR0/1, CSBARBT/CSORBT and CSBAR0..10/CSOR0..10; MM-dependent internal register location; preliminary CSBAR window-size decoder. Not a complete device register index.
2. **SIMCR/MM read-only analyzer — FIRST IMPLEMENTATION:** Scan XREF and direct operands for potential SIMCR accesses at both candidate locations. Report candidate immediate word writes and distinguish definite bit effects at the instruction level from unresolved cases. Static sites do not prove runtime execution order. Follow-up: P-code analysis, constant propagation, register-based pointers, byte accesses to SIMCR+1, control-flow reasoning.
3. **Test in real firmware — NOT STARTED:** Verify read-only analysis against a confirmed MC68332 program and a CPU32 program with unidentified exact chip. Compare the report against Listing, XREFs and real MCU initialization code; investigate missed indirect writes and false positives.
4. **VBR, memory and chip-select dynamic mapping — NOT STARTED:** Detailed requirements below.
5. **Proposed safe naming — NOT STARTED:** evidence-backed names, confidence levels, collision avoidance, preview and user approval, reversible Ghidra transaction.
6. **Hardware Analysis UI and RAG/AI integration — NOT STARTED:** register-aware context with traceable source PDF pages; deterministic evidence analysis must not need LLM calls.

### Experimental usage

Compile and install the GhidrAssist extension including the two new Java classes, then run ghidra_scripts/GhidrAssist_SIMCR_MM_Report.java from Ghidra Script Manager. Select MC68332 **only** when justified. Its output is a read-only report in the script console; the generic CPU32 choice intentionally does not enable the MCU-specific analysis. The permanent UI is planned for stage 6.

## Required stage 4: all dynamically determined address spaces

**Never replace the following with a single, fixed address-to-device table.** Track a series or graph of candidate hardware states, each with a sequence of writes, originating path, supporting instruction addresses, confidence and unresolved assumptions.

- **SIMCR MM relocation:** Both 4 KiB internal module windows, 0x7FF000–0x7FFFFF (MM=0) and 0xFFF000–0xFFFFFF (MM=1). Include initial states, device-specific restrictions and uncertain control flow.
- **All chip selects:** CSBOOT and CS0..10. Resolve CSBAR address + block size (2 KiB to 1 MiB), CSOR access conditions and timing, CSPAR pin assignments. Do not equate a CSBAR range with an enabled/selected device.
- **Bus-address-space dimensions:** As applicable, model supervisor/user, program/data/CPU-space function codes, interrupt acknowledge, read/write, 8/16-bit port and byte lanes, DSACK/wait states, precedence and possible overlapping windows.
- **All dynamically relocated internal regions:** Include modules and parameter RAM such as SIM, QSM, TPU and TPURAM/TRAMBAR where supported by the **selected device**, not by CPU32 architecture alone.
- **VBR and vector table:** Track changes in vector-base location and exception-vector addressing separately from changes in chip-select mappings.
- **Conditional and evolving configuration:** Track reset/boot state, branch-dependent writes, last-write-wins where provable, ambiguous order and competing maps. Present alternatives rather than inventing a single certain final configuration.
- **External device association:** An address window does not prove ROM, RAM, flash or peripheral contents. Report chip-select behavior separately from board-specific wiring.
- **u-Link NT relevance:** Provide a later export of candidate active regions with size, effective access conditions, confidence, programming/debugging caveats and exact code evidence for user review with [u-Link NT](https://www.usbjtag.com/). No physical hardware programming is implemented or assumed.

### Evidence classification

Manual-verified device facts, code-located facts, path-dependent possibilities, inferred register values, and externally confirmed physical wiring must be kept distinct. Avoid silent renaming or automatic memory-block creation from uncertain hypotheses.

### Milestone reminder

Once **at least four of the six stages** are verified completed, **including stage 4**, remind the user to review every dynamic chip-select window and associated address space in the context of u-Link NT. Do not trigger the reminder earlier.
