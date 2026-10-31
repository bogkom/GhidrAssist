# Conditional Chip Select source-consensus safety

The previous read-only Chip Select sketch was guarded by caveats, but
built a map with source-address-order last-write-wins. Two different
CSBAR/CSOR writes in alternative firmware branches could therefore
appear as one selected register value.

This package removes that implicit choice. For each function and MM
address hypothesis, GhidrAssist now passes to the existing conditional
CS table only register names for which **all Listing/XREF candidate
writes have the same known 16-bit literal**. Any unknown write or
conflicting literal excludes that register. Duplicated agreeing
static sites remain one word *candidate*, not proof of execution.

This does not verify MM latch state, actual peripheral decode,
external chip wiring, feasible branch conditions, or order after RESET.
Unknown indirect aliases and interprocedural effects still require
separate CFG evidence and can invalidate any supposed hardware state.

A separate deterministic pure Java self-test covers conflicts, missing
literals and multiple writes; full Ghidra 12.1.4 extension CI and
host acceptance remain necessary.
