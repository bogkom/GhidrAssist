# Static 68k indexed address candidates (CFG-conservative)

This increment resolves a supported subset of Motorola/Ghidra memory operands:

- `(A0,D1.W)`, `16(A0,D1.W*2)`, `($20,A3,A2.L)` and corresponding decimal/hex displacements. The decoder enforces the full string syntax, valid A-register bases, 16/32-bit index width and scale values of 1/2/4/8.
- A word index is **sign-extended** before scaling; the final effective address uses the CPU32 24-bit address bus. This is an address candidate in the selected architecture, **not** a proof that the address is physically decoded.
- Only when both the base and index registers have predecessor-agreed constants at the STORE site is an effective address published. Branch conflicts, unknown register contents, call barriers and truncated CFG analysis remain **unresolved**.
- PC-relative, bracketed memory-indirect, indirect aliases, and nonconforming expressions are intentionally not guessed. If the Ghidra operand rendering differs from the strict grammar, the STORE remains unresolved.
- An indexed memory access is still only a static disassembly site, not evidence that the instruction executes or that MM has already been relocated.

The bridge translates parsed operands to `HardwareDataflow`, which computes the address and integrates it with existing CS/SIM candidates. Synthetic regressions exercise word signed arithmetic, long indexes, different branch predecessors, and an unknown index.

**Remaining:** global value tracking beyond calls, alias analysis, loops with large path combinations, exception/reset-origin CFGs, dynamic RAM maps and physical chip-select wiring. Do not use this output to infer flash programming addresses.
