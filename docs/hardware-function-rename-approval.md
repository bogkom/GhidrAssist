# Hardware Analysis: reviewed, bulk-applied function names

**Stage 5, optional:** Hardware Analysis now exposes **Review names...** beside
the explicit profile selector. It uses the exact proposal snapshot produced
during the current analysis; after a Program change it refuses to act.

## What can be renamed

- Only the **user-selected MC68332 hypothesis**, never the generic CPU32
  architecture. The method does not attempt to identify the physical ECU MCU.
- Only a Ghidra-generated `FUN_...` or `SUB_...` function name with a strong
  multi-register hardware WRITE role signature.
- At least three distinct direct write instruction sites and three distinct
  hardware-register names, with no existing symbol collision.
- Proposed names include `HW_MC68332_`, the conservative role,
  `_CANDIDATE_` and the original function start address.

## Reviewed Ghidra changes

A resizable table shows per-row preflight `READY`, `NAME_COLLISION`,
`NAME_CHANGED`, `WEAK_OR_UNREVIEWED` or `INVALID` and the evidence role.
Eligible proposals are initially checked for convenience. The user can bulk
select or clear and must **explicitly approve** and confirm again.

Immediately before application, the service re-fetches every original Ghidra
Function and the complete symbol namespace **inside one Program transaction**.
Any renamed/stale function, invalid role or conflicting target aborts the
entire operation and rolls back the transaction, rather than overwriting a
user name. Ghidra **Undo** is available after a successful commit.

A new Hardware Analysis run is necessary after renaming; the evidence cache
and old CSV snapshot are invalidated. Nothing is written to the firmware
binary or connected hardware.

## Limitations

This is a compiler-checked implementation, not an assertion that the UI or
all Ghidra SymbolTable behaviors have been user-tested on a real project.
The role is still a *static candidate*; output does **not** imply execution,
reset-path reachability, a specific physical MCU or electrical CS wiring.

Local variable, argument and data-pointer renaming and full path-sensitive
interprocedural analysis remain outside this increment.
