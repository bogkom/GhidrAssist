# Hardware Analysis — resizable Review / Apply and full MC68332 module regions

The **Review / Apply…** dialog is resizable. It displays proposed actions, their source and current status, including **READY**, **UPGRADE**, **ALREADY_PRESENT**, **BLOCKED**, or **MANUAL_REVIEW**. Selecting a concrete **MC68332** profile is explicit acceptance of the MCU hypothesis, not automatic proof of the CPU type.

Applicable and non-conflicting internal module regions and register definitions are **selected by default**. Definitions already present in the project or blocked by pre-existing memory, data, code or user symbols are never selected. External CS7/CS8 devices, relocated TPU RAM and the VBR base remain manual decisions. **Select applicable** and **Clear selection** change multiple checkboxes at once; no project changes happen until the user presses **Apply selected…** and confirms again. There is also a field for the optional VBR address, with immediate validity feedback.

## MC68332 Appendix D-1: full module apertures

The official *MC68332 User's Manual*, **Appendix D REGISTER SUMMARY, page D-1**, gives the following **module sizes** rather than only the size of the implemented register subranges. For **MM=1**, the Y bit in the manual is selected accordingly.

| Module | Size (bytes) | MM=1 base | Full allocated address range | GhidrAssist |
|---|---:|---|---|---|
| SIM | 128 (`0x80`) | `0xFFFA00` | `0xFFFA00–0xFFFA7F` | `SIM_REGISTERS_MM1` |
| TPURAM control | 64 (`0x40`) | `0xFFFB00` | `0xFFFB00–0xFFFB3F` | `TPURAM_CONTROL_MM1` |
| QSM | 512 (`0x200`) | `0xFFFC00` | `0xFFFC00–0xFFFDFF` | `QSM_MM1` |
| TPU | 512 (`0x200`) | `0xFFFE00` | `0xFFFE00–0xFFFFFF` | `TPU_MM1` |

Source: [NXP MC68332 User's Manual, Appendix D](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf). The detailed register table D-7 identifies implemented register locations, reserved holes and RAM subregions. **Full memory-block extent does not imply that every byte is an implemented hardware register**: such bytes remain undefined/untyped.

Other optional hardware hypotheses are separate: relocated `TPURAM_2K_CANDIDATE` at `0xFFF000–0xFFF7FF`, and external `CS7_DEVICE_CANDIDATE` / `CS8_DEVICE_CANDIDATE`. Neither the manual selection nor a static CSBAR write proves a device is actually present. VBR requires a manually entered, verified base and 1024 entirely undefined mapped bytes; no existing code is replaced.

## Upgrade previous GhidrAssist memory maps

The 2026-10-21 interim builds proposed shorter blocks for QSM/TPU and separate queue or parameter memory blocks. The latest **Review / Apply** handles both original short and intermediate split layouts.

- `QSM_CONTROL_MM1` at `0xFFFC00` and `QSM_QUEUE_MM1` at `0xFFFD00` can be combined with uninitialized gap blocks into a single full `QSM_MM1` 512-byte block.
- `TPU_CONTROL_MM1` at `0xFFFE00` and `TPU_PARAM_RAM_MM1` at `0xFFFF00` can be combined analogously into `TPU_MM1` 512-byte block.
- `TPURAM_CONTROL_MM1` may be extended from 8 bytes to 64 bytes if still a GhidrAssist-created, uninitialized block.

The migration is conservative: only recognized GhidrAssist-owned names and exact start addresses are eligible. Initialized, overlapping user memory blocks or unknown objects are shown as **BLOCKED** and are not selected. Existing register types and labels are not cleared. Changes and expansions are performed in **one Ghidra Program transaction**; exceptions roll back the transaction. Ghidra's Undo can reverse completed changes. The original BIN is never overwritten.

A normal scan remains **read-only**. Mapping blocks may help Ghidra resolve static references but will not automatically solve arbitrary indirect pointer analysis. Re-run Analyze after applying definitions; if necessary, run Ghidra Auto Analyze to update XREFs.

**Testing status:** GitHub Actions compiles the complete extension against Ghidra 12.1.4 and tests the pure-Java register and gap-planning logic. This does **not** constitute a runtime test of Ghidra's Memory.join, dialog events or Undo against a particular project. For first deployment, use a saved backup/copy of the Ghidra project.
