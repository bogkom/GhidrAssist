# CFG hardware state safety: unknown and overlapping STOREs

A previous implementation retained known CSBAR/SIMCR 16-bit values across an
unresolved indirect STORE. That was unsafe because the unknown pointer might
target one of the tracked MMIO registers; the later CS epoch could show stale,
apparently valid values.

The dataflow model now:

- Invalidates **all** tracked 16-bit peripheral values after a STORE whose
  effective destination is unknown (including an unresolved indexed alias).
  `priorUnknownStore` is retained in later snapshots and reported next to
  candidate SIMCR/MM write history.
- Invalidates the affected register when an 8-bit, 16-bit, or 32-bit write
  overlaps any byte of an existing tracked word (e.g. SIMCR low-byte write to
  `...A01` invalidates an earlier word at `...A00`).
- Restores an exact register word value only after a fully known 16-bit
  overwrite at the register's aligned address.
- Treats an unknown-size memory operation as an invalidation barrier. CPU
  identity, actual execution, MM write-once acceptance and external CS wiring
  remain unproven.

This is deliberately **conservative**: unknown aliases can reduce the number
of inferred memory epochs. A later improvement should use Ghidra P-code
def-use/alias sets to prove a store cannot overlap MMIO before retaining
constants. The Ghidra program database is unchanged; only the read-only
analysis and its source-backed report change.

Pure Java tests cover an unknown register pointer, a SIMCR low-byte overlap,
a 32-bit overwrite spanning CSBAR, and re-establishment of a known value after
a clobber. No private firmware is stored in public CI.
