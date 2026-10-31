# GA-02/03 — CFG/P-code MMIO candidate provenance

This standalone sibling improvement builds on PR #67 without changing
its immutable tested commit or Supervisor artifact reference.

The existing Ghidra CFG engine already resolves some address-register
indirect stores and computes function-local SIMCR write predecessor
candidate counts. This module renders the evidence as a **distinct**
read-only report:

- Which source instruction and function contain a possible MMIO store.
- Whether its candidate address was direct or resolved indirectly.
- Whether a whole 16-bit literal was actually known. Byte, long and
  unknown-width writes remain unknown for full-word register values.
- Whether a prior SIMCR candidate occurs along some, all modeled or
  no modeled *function-local* CFG predecessors. Unknown call effects,
  aliases and truncation override this with UNKNOWN.

None of these classifications certifies that the firmware executed
the path, the MCU recognized the address mapping or a write-once SIMCR
MM bit latched the literal. In particular, even a source-site with no
predecessor in the modeled function is not a first write after reset.

The direct-XREF register inventory and candidate RESET direct-call
graph remain separate; this report does **not** join them as a real
timed hardware state. CSBAR/CSOR registers are not automatically
combined across branches or functions into a physical memory map.

Pure Java regression tests cover aliases, width, unknown calls,
branch dependence and profile selection. Full Ghidra 12.1.4 extension
CI and explicit real-host review remain required before merge.
