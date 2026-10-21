# CPU32 auto-increment/decrement address register side effects

After a decoded Motorola `(A0)+` source or `-(A7)` destination, the
associated A-register no longer has its earlier value. The old CFG bridge
could keep a constant for A0 after e.g. `MOVE.L (A0)+,D0`, then attribute a
later `MOVE.W #value,(A0)` to a false MMIO address.

The read-only CFG translator now marks exact supported `(An)+` and
`-(An)` operands as implicit A-register mutations. The `HardwareDataflow`
solver processes the current instruction's known address first (where a
postincrement access uses its old base), then removes the changed A-register
from the map of known constants. For predecrement forms without an explicit
effective-address model, the memory write remains unresolved and the
register is also marked unknown.

This deliberately does NOT assume the byte/word/long update amount, register
stack semantics, exception return context, or that the instruction executed.
A later constant-defining instruction can establish a new known register
value. The no-guess policy is necessary for safe conditional MC68332 MMIO
candidate interpretation.

This increment has synthetic tests for both operand shapes, source operand
side effects and subsequent hardware stores, and a full Ghidra 12.1.4
extension build in CI. Other implicit register changes (LINK, UNLK, DBcc,
MOVEM and unknown P-code register outputs) require a more comprehensive
def-use/invalidation pass. No Program database mutation is performed.
