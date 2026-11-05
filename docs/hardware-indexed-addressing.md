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

### Confirmed second real CPU32 decode gap: MOVEQ signed literal

The same headless fixture showed another exact Ghidra 12.1.4 PUBLIC
spelling difference: `moveq -0x1,D1` has operand representation
`-0x1` **without a leading `#`**. The existing
`GhidraHardwareFlowService.immediate` refused it; the translated
instruction became `CLOBBER_POINTER(D1)`. The outer caller entered
the first JSR without D1, so both otherwise distinct indexed MMIO
candidates remained unresolved. When a validated D1=-1 constant was
manually seeded in a test-only diagnostic, the same real decoded
leaf produced the expected modulo-24-bit address `0xFFFA00`.

The production gate now permits a bare signed numeric immediate
**only when the opcode is `MOVEQ`** and Ghidra supplies a real
`Scalar`. All other numeric operands still require `#`; plain
register and memory operands remain rejected. The shared strict
register-operand Java21 regression tests both positive and negative
forms. The diagnostic reflection was removed from the final harness.
No global propagation or hardware execution is implied.

## 2026-11-05 — 32-bit extension width and operand-input bounds

The Motorola CPU32 indexed operand parser is source-only, so parsing an
impossible extension constant must **not** be a way to manufacture a
valid 24-bit register address. Previously the grammar accepted a positive
64-bit displacement such as `0x100000000`. The downstream effective
address was masked to 24 bits, making this unencodable displacement appear
as a plausible MC68332 MMIO source.

The strict indexed parser now bounds raw operands to 128 UTF-16 code units
before normalization and restricts the full displacement to signed
`-0x80000000` through unsigned `0xFFFFFFFF`, preserving hexadecimal
32-bit renderings of otherwise negative offsets. Parsing an overrange,
overflowing or excessively long expression returns UNKNOWN. The
public source-level `HardwareDataflow.Step` indexed constructor enforces
the same numeric limits and rejects malformed synthetic input before
a solve can publish evidence.

Java21 tests cover inclusive boundaries, signed/unsigned overflow,
long inputs and unchanged Ghidra 12.1.4 CPU32
`(0x1,A1,D1w*0x1)` syntax. CI must also pass the real isolated
CPU32 two-hop indexed test and full Ghidra 12.1.4 PUBLIC/Java25 build
on the exact tested SHA. No assumption about active SIMCR MM or runtime
execution follows from a decoded candidate.
