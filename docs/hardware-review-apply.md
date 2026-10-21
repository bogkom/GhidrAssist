# Hardware Analysis: typography, Listing navigation and explicit Ghidra project edits

The Hardware Analysis tab now uses the same saved font family and size as **Settings → Response Appearance**; switching back to the tab refreshes the appearance. Double-click on a hexadecimal address or `FUN_...` function address in the report to navigate using Ghidra's GoToService. Navigating to unmapped addresses may require an approved memory definition first.

## Explicit review (opt-in)

The existing **Analyze current program** button remains entirely read-only. A separate **Review / Apply hardware definitions...** button becomes available after analysis. You must explicitly choose **MC68332 — user-selected device hypothesis** and rerun analysis before applying its MCU-specific definitions. This is a **manual assumption**, not MCU detection.

The review table contains individually checkable items (all unchecked by default):
- candidate uninitialized memory regions for SIM registers, TPURAM controller registers, QSMCR and TPUMCR, proposed 2KiB relocated TPURAM at `0xFFF000`, and external CS7/CS8 address windows;
- individual MM=1 16-bit register data types and labels, which can be applied only where memory has already been mapped or one of the selected blocks creates it;
- an optional 256×32-bit `CPU32_VBR_256_VECTORS` data structure at a **manually entered, four-byte-aligned** VBR address.

The UI presents the selected count and asks for an additional confirmation that it will modify the current **Ghidra program database**. All changes are performed inside a **single undoable Ghidra transaction**. If an exception occurs, it rolls back the whole transaction. Conflicting, partially mapped or already defined items are skipped without clearing existing bytes, instructions, user labels or data.

**Ghidra address spaces versus memory blocks:** ordinary MMIO regions and TPURAM should normally be modelled as uninitialized blocks inside the existing processor address space. Overlay address spaces are needed only after demonstrating alternative memory mappings and must not be invented from CPU32 language selection. GhidrAssist deliberately does not create a CS9 1MiB block or overlapping CS0/CS1 blocks from static evidence.

## Limitations and interpretation

- Mapping a proposed memory block is not proof that a chip physically exists there or that CPU's MM bit was set.
- New memory blocks and typed registers make symbols and known static references easier to inspect. They **do not automatically resolve** accesses through unknown pointer expressions or prove all XREFs. Ghidra analysis/ref refresh may still be necessary.
- Applying the optional VBR structure requires an entirely undefined existing 1024-byte region; if Listing has already defined bytes as data/code, the VBR apply action **skips**, rather than clearing or overwriting them.
- Review approval is explicit **per item**; default selection is none. Applying changes clears the cached evidence, so run Hardware Analysis again after edits.
- Always use Ghidra's **Undo** (or a saved project snapshot) to roll back accepted changes. The imported BIN is never rewritten by GhidrAssist.
- This initial transaction-based implementation needs actual Ghidra runtime validation; passing Ghidra API compilation is not a substitute for exercising the dialog and undo workflow.

