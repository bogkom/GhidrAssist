# Static 68k indexed address candidates (CFG-conservative)

This increment resolves a supported subset of Motorola/Ghidra memory operands:

- `(A0,D1.W)`, `16(A0,D1.W*2)`, `($20,A3,A2.L)` and corresponding decimal/hex displacements. The decoder enforces the full string syntax, valid A-register bases, 16/32-bit index width and scale values of 1/2/4/8.
- A word index is **sign-extended** before scaling; the final effective address uses the CPU32 24-bit address bus. This is an address candidate in the selected architecture, **not** a proof that the address is physically decoded.
- Only when both the base and index registers have predecessor-agreed constants at the STORE site is an effective address published. Branch conflicts, unknown register contents, call barriers and truncated CFG analysis remain **unresolved**.
- Register arithmetic follows the **actual operand width**: `ADDQ/SUBQ.B` and `ADDQ/SUBQ.W` on Dn wrap only the low byte/word, without carrying into untouched high bits. Operations on An adjust the full address register (including `ADDQ.W`); a Dn arithmetic instruction with no trustworthy width clobbers its modeled constant. Synthetic tests cover signed subtraction and carry/borrow boundaries before an indirect STORE.
- PC-relative, bracketed memory-indirect, indirect aliases, and nonconforming expressions are intentionally not guessed. If the Ghidra operand rendering differs from the strict grammar, the STORE remains unresolved.
- An indexed memory access is still only a static disassembly site, not evidence that the instruction executes or that MM has already been relocated.

The bridge translates parsed operands to `HardwareDataflow`, which computes the address and integrates it with existing CS/SIM candidates. Synthetic regressions exercise word signed arithmetic, long indexes, different branch predecessors, and an unknown index.

**Remaining:** global value tracking beyond calls, alias analysis, loops with large path combinations, exception/reset-origin CFGs, dynamic RAM maps and physical chip-select wiring. Do not use this output to infer flash programming addresses.

## 2026-11-05 — contextual indexed operands and source integrity

The indexed address model is now exercised with a genuinely decoded
CPU32 `MOVE.W D0,1(A1,D1.W)` after two direct CALLs. The accepted
predicate requires predecessor-agreed constants for both base and
index at that exact STORE PC, with sign extension of D1.W and a
24-bit effective-address mask. Conflicting or absent D1 remains
an unresolved alias; it does not become zero and does not authorize
a Register Review/Apply proposal.

Results must be checked on the **exact synthetic Ghidra 12.1.4
PUBLIC/Java25 workflow SHA**, not inferred from pure-Java tests
alone. The test adds evidence of supported syntax only, not support
for complex 68020 full-extension or memory-indirect addressing.

### Confirmed parser gap from real 12.1.4 PUBLIC Ghidra CI

The first run of the real `two-hop-indexed` harness on PR #168
did not pass: the **actual Ghidra CodeBrowser/Listing operand was
`(0x1,A1,D1w*0x1)`**, whereas `HardwareIndexedAddress.parse`
understood only dotted index-width suffixes and decimal scales
(e.g. `1(A1,D1.W*1)`). The test failure was evidence of a real
production decoding gap rather than a fabricated test case.

The strict decoder now additionally accepts Ghidra's undotted
`D1w`/`A2l` and hexadecimal scale `*0x1/0x2/0x4/0x8`
renderings, while still rejecting unsupported index sizes/scales,
PC-relative, memory-indirect and malformed expressions. Dedicated
Java21 source tests and the genuine synthetic two-hop Ghidra test
must both pass on the same exact PR SHA. This is not a reason to
infer unknown index registers or hardware activity.
