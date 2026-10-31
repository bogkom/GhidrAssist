# GA-05 — filter CSBAR source evidence before Review / Apply

This package is stacked on PR #72, preserving its immutable source
commit and artifact. It does not change the underlying Ghidra Apply
transaction or automatically select new hardware memory regions.

The former Review candidate generator accepted any literal CSBAR
source from the current scan, including a matching MC68332 register
name in the **MM0 address range** and contradictory literal values
from different source instructions.

The new filter requires the exact MM1 hypothetical MC68332 address:
CSBARBT at 0xFFFA48; CSBAR0..CSBAR10 at 0xFFFA4C + 4*n.
All observed source writes for a particular register must agree on
one complete literal. Unknown writes or disagreements suppress the
entire register from chip-window Review proposals. Repeated identical
candidate literals yield one proposal with bounded provenance.

The resulting Chip Select range is still only a **conditional
candidate** for an operator to inspect. It never proves that the
MM1 address window is active, the code executed, the CS pin asserted
or a physical external peripheral is connected. Existing Ghidra
preflight/review/confirmation and Undo remain mandatory.

A pure Java self-test covers wrong-MM aliases, branch conflicts,
missing values and CSBAR10/CSBOOT, followed by full Ghidra 12.1.4
build and separately authorized local acceptance.


## CS_WINDOW review default (safety hardening)

The preflight previously classified an absent speculative CS window
as READY and **selected it by default**. This could allow a routine
"Apply selected" action to create a candidate memory region the
operator had not specifically checked. The new preflight returns
MANUAL_REVIEW with selectedByDefault=false for any missing CS window.
The row remains explicitly selectable by the human and is still
revalidated under the undoable Ghidra transaction. Existing mapped
CS windows remain ALREADY_PRESENT, also unselected. No actual
hardware decode is asserted.
