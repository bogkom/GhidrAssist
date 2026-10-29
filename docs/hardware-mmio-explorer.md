# GA-09 — MMIO access references explorer

Independent candidate based on PR #53 commit `bd0a0a60eaa610e19581bd67fd16d29c637bfb8e`.

After Analyze, choose **MMIO accesses...** to open a separate resizable table.
The main Analyze report remains focused on initialization registers. The
explorer lists all references recorded by `HardwareInventoryService`, including
the rest of the configured MCU register catalog.

Columns: instruction PC, register hypothesis, MMIO address, access category,
candidate literal word, evidence quality, function, instruction and profile
scope. The filter searches visible column values (case-insensitive), with
counter and double-click / **Go To Listing** navigation. A changed active
program prevents navigation on stale results. No Ghidra database edits.

Safety: `REFERENCE / UNKNOWN` is not converted into a hardware READ.
A `WRITE CANDIDATE` is based on Listing syntax, not proof of runtime access.
Literal values are displayed only if the existing scanner extracted a direct
complete-word constant. Generic CPU32 remains an address survey; MC68332
selection remains an explicit user assumption.

Required validation: deterministic `hardware-mmio-explorer-tests.yml`,
complete Ghidra 12.1.4 extension build, then isolated project UI acceptance
confirming that opening/filtering/navigating does not modify Ghidra project
content, OAuth config, Review / Apply or RAG. No local test PASS is claimed.

## 2026-10-29 — unnormalized 16-bit literals

The read-only MMIO Explorer accepts a *source-only* direct word candidate
only when the supplied value is in the unsigned 16-bit range
`0x0000..0xFFFF`. Values outside it (negative or above 65535)
are explicitly `UNKNOWN` with an `OUT-OF-RANGE WORD CANDIDATE` note,
never silently masked into another plausible-looking peripheral value.
A documented 16-bit source site still does not establish execution,
the active MM mode or physical wiring. The original firmware/project
is unchanged.
