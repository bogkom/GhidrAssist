# GA-02/03/18 — computed JSR references are not byte-proven unique targets

## Problem

In `AutomationCallPaths.index`, any Ghidra reference whose type satisfied
`ReferenceType.isCall()` and whose destination was an exact Function entry
previously became a traversable `ghidra_call_reference` edge. That included
**computed** CPU32 calls such as `JSR (A1)`: a user-defined or inferred
reference to one candidate function could therefore suppress
`unresolved_calls`, make `complete=true`, and mark a candidate target
as reachable even though the register's runtime contents were unproven.

Static Ghidra XREFs remain useful source facts, but the existence of one
XREF does not prove that a computed target has a unique value.

## Narrow fail-closed policy

**Direct (non-computed)** CALL references retain the original traversal
behavior. For a `FlowType.isCall() && FlowType.isComputed()` instruction,
the index **does not promote Ghidra CALL references to direct edges**.
Only the existing strict, byte-verified CPU32 source patterns handled by
`AutomationCallPaths.adjacentConstantRegisterCall` and
`boundedConstantRegisterSource` can create a proven *candidate* edge:

- `MOVEA.L #exactFunctionEntry,An; JSR (An)`;
- that same byte-proven source with up to three strictly allowlisted NOP
  or MOVEQ instructions which cannot modify `An`.

All remaining computed calls, even those carrying explicit
`RefType.COMPUTED_CALL` XREFs to a defined function, are counted as
unresolved and force `complete=false` for that query. This is a
conservative static reachability classification, **not** a proof that a
byte-verified candidate actually executes or that the MCU address is
physically mapped to that function.

## Real Ghidra 12.1.4 PUBLIC regression

The existing isolated `indirect-adjacent` CPU32 fixture now inserts a
`SourceType.USER_DEFINED` `RefType.COMPUTED_CALL` reference from a
real decoded `JSR (A1)` to a known function containing a possible
SIMCR write. The reference is **intentionally not justified by the bytes**
or by the value of `A1`. The Automation API must report:

- `unresolved_calls=1`, `complete=false` for that caller;
- `total_paths=0` and no artificial reachability of the referenced
  function;
- the separate, legitimate adjacent `MOVEA #entry,A0; JSR (A0)`
  still resolves exactly and does not acquire unresolved calls;
- the read-only hardware report remains source-only, unchanged by
  Analyze, without any Review/Apply promotion.

The fixture runs inside the real isolated synthetic Ghidra release
12.1.4 PUBLIC under Java 25. Its assertions and artifact SHA-256 are
checked by the existing GitHub Actions workflow. The linked repository
also runs its complete extension build and other regression suites
on the **same PR HEAD SHA**. No Wyse/Precision, local user projects or
ECU411 firmware are touched.

This does not extend indirect dataflow analysis to branch-dependent,
loaded-memory or nonadjacent register sources; these remain UNKNOWN.

## 2026-11-05 — forged CALL XREF on a non-CALL instruction

The earlier PR #175 correctly excluded user-defined CALL references
from **computed** `JSR (An)` reachability. Auditing the same index
showed a second related failure: the loop accepted a Ghidra CALL-type
reference on *any instruction* whose decoded flow was not computed
CALL. A manually attached `COMPUTED_CALL` XREF on an ordinary CPU32
`NOP` could therefore invent a reachable MMIO-writing Function,
despite no CALL instruction at that source PC.

The reference branch now requires **both** `FlowType.isCall()==true`
and `FlowType.isComputed()==false` before admitting an exact
Ghidra reference as a direct CALL edge. All other reference types
retain existing handling, and strict byte-proven adjacent/safe-chain
computed JSR evidence remains unchanged.

The real isolated Ghidra 12.1.4 PUBLIC/Java25
`indirect-adjacent` fixture injects a USER_DEFINED
`RefType.COMPUTED_CALL` from a genuine decoded `NOP` at 0x6E0
to an existing 0x700 MMIO-writing Function. Deterministic
`AutomationCallPaths.query(entry=0x6E0)` must report
`total_paths=0`, `unresolved_calls=0`, `complete=true`,
and exclude 0x700 from reachable entries. A true byte-proven
`JSR (A0)` remains resolved and an unproven `JSR (A1)`
remains incomplete. The harness reports a mandatory separate
evidence flag and uses an isolated synthetic Program.

This is source-only static provenance; a Ghidra reference can be
user-edited and is never proof of MCU runtime execution, physical
CS mapping, or latched SIMCR MM. No Review/Apply permission changes.
