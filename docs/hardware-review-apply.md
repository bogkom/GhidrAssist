# Hardware Analysis: typography, Listing navigation and explicit Ghidra project edits

The Hardware Analysis tab now uses the same saved font family and size as **Settings → Response Appearance**; switching back to the tab refreshes the appearance. Double-click on a hexadecimal address or `FUN_...` function address in the report to navigate using Ghidra's GoToService. Navigating to unmapped addresses may require an approved memory definition first.

## Explicit review (opt-in)

The existing **Analyze current program** button remains entirely read-only. A separate **Review / Apply hardware definitions...** button becomes available after analysis. You must explicitly choose **MC68332 — user-selected device hypothesis** and rerun analysis before applying its MCU-specific definitions. This is a **manual assumption**, not MCU detection.

The review table contains individually checkable items (all unchecked by default), with a compact action bar ordered **Analyze**, **Review / Apply**, **Export MD**, **Export CSV**:
- source-backed uninitialized memory regions from **MC68332 User's Manual, Appendix D, Table D-7** (MM=1), proposed 2KiB relocated TPURAM and external CS7/CS8 candidate windows;
- the register-control and RAM ranges are *separate*; addresses explicitly marked "NOT USED" are not silently mapped as valid registers;

| Item | MM=1 range | Size | Note |
|---|---|---:|---|
| `TPURAM_CONTROL_MM1` | `FFFB00–FFFB3F` | `0x40` | TPURAM control module, including unused slots |
| `QSM_CONTROL_MM1` | `FFFC00–FFFC1F` | `0x20` | QSM/SCI/QSPI registers |
| `QSM_QUEUE_MM1` | `FFFD00–FFFD4F` | `0x50` | Receive/transmit/command queue RAM |
| `TPU_CONTROL_MM1` | `FFFE00–FFFE27` | `0x28` | TPU registers |
| `TPU_PARAM_RAM_MM1` | `FFFF00–FFFFFF` | `0x100` | TPU Parameter RAM |
| `TPURAM_2K_CANDIDATE` | `FFF000–FFF7FF` | `0x800` | Independently mapped standby TPURAM array |

QSM spans `FFFC00–FFFDFF` and TPU spans `FFFE00–FFFFFF` in the overall chip module map. **They are not entirely occupied by implemented registers/RAM.** In particular, `FFFC20–FFFCFF`, `FFFD50–FFFDFF`, and `FFFE28–FFFEFF` remain unmapped by the proposed plan. The precise field labels and implemented bytes within queue/parameter RAM require additional work. Source: [official MC68332 User's Manual, table D-7](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf).
- individual MM=1 16-bit register data types and labels, which can be applied only where memory has already been mapped or one of the selected blocks creates it;
- an optional 256×32-bit `CPU32_VBR_256_VECTORS` data structure at a **manually entered, four-byte-aligned** VBR address.

The UI presents the selected count and asks for an additional confirmation that it will modify the current **Ghidra program database**. All changes are performed inside a **single undoable Ghidra transaction**. If an exception occurs, it rolls back the whole transaction. Conflicting items are skipped without clearing existing bytes, instructions, user labels or data. Exception: if a legacy **uninitialized** GhidrAssist block has exactly the target name and start, but is shorter (e.g. 2-byte QSMCR/TPUMCR or 8-byte TPURAM control), the extension creates an adjacent uninitialized suffix and joins it into the original block in the same undoable transaction. Occupied suffixes and arbitrary user blocks are never extended.

**Ghidra address spaces versus memory blocks:** ordinary MMIO regions and TPURAM should normally be modelled as uninitialized blocks inside the existing processor address space. Overlay address spaces are needed only after demonstrating alternative memory mappings and must not be invented from CPU32 language selection. GhidrAssist deliberately does not create a CS9 1MiB block or overlapping CS0/CS1 blocks from static evidence.

## Limitations and interpretation

- Mapping a proposed memory block is not proof that a chip physically exists there or that CPU's MM bit was set.
- New memory blocks and typed registers make symbols and known static references easier to inspect. They **do not automatically resolve** accesses through unknown pointer expressions or prove all XREFs. Ghidra analysis/ref refresh may still be necessary.
- Applying the optional VBR structure requires an entirely undefined existing 1024-byte region; if Listing has already defined bytes as data/code, the VBR apply action **skips**, rather than clearing or overwriting them.
- Review approval is explicit **per item**; default selection is none. Applying changes clears the cached evidence, so run Hardware Analysis again after edits.
- Always use Ghidra's **Undo** (or a saved project snapshot) to roll back accepted changes. The imported BIN is never rewritten by GhidrAssist.
- This initial transaction-based implementation needs actual Ghidra runtime validation; passing Ghidra API compilation is not a substitute for exercising the dialog and undo workflow.

