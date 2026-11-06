# GA-02/03/11 — bounded SIMCR/MM MAY evidence for byte-proven CPU32 indirect JSR

Status: **CI CANDIDATE**, 2026-11-06. Source baseline after integrated
[PR #187](https://github.com/bogkom/GhidrAssist/pull/187),
`8fcf2abeddf11b9982061bed8f957d466df45033`.

## Problem

The existing bounded indirect JSR source verifier can establish, from
synthetic byte-verified CPU32 `MOVEA.L #imm,An` and `JSR (An)`,
a **possible exact target** without making a direct CALL edge.
PR #187 added transitive MAY memory STORE/VBR effects, but any STORE
might be unrelated to MC68332 SIMCR/MM. Its generic memory conclusion
cannot be interpreted as proof of an MM bit source.

## Change

`HardwareIndirectMmMay` joins **only already verified and displayed**
`HardwareIndirectCallEvidence.Site` witnesses with the existing
`HardwareInterproceduralMmEffects.FunctionNode` graph of possible
SIMCR/MM **low-byte overlap** sources. It reuses the existing
bounded/interprocedural solver: 4 direct-call levels, 100 scheduled nodes
per computed target and an aggregate budget of 16384 distinct scheduled
targets. Display is capped at 16 byte-witnessed computed-JSR rows.

The independent Markdown classification is:

- `STATIC_MAY_MM_LOW_BYTE`: at least one source STORE that may overlap
  MC68332 SIMCR/MM low byte in the target's inspected subtree.
- `UNKNOWN`: no such observed source but unknown alias/STORE width,
  unknown CALLOTHER/computed CALL, missing child, recursion, or hit budget.
- `NOT_OBSERVED_IN_BOUNDED_SOURCE`: no observed candidate and no
  uncertainty within the bounded, inspected source graph. **Not**
  a proof of hardware MM absence or an executed firmware path.

Both `MM0` and `MM1` are possible alternatives until hardware state
is known; neither is asserted latched. The independent source report
lists caller PC, JSR PC, witness target, unknown width/alias, unknown
CALL/flow, cycle/limit, examined functions and source provenance.

## Fail-closed boundaries

- Requires **explicit MC68332** selection. Generic CPU32 reports
  no device-specific SIMCR/MM classification.
- Does NOT add or update direct CALL graph edges, RESET visitation,
  VBR relocation, ISR activation or Ghidra analysis revision.
- Does NOT grant Review/Apply/Undo or infer that source STORE executed.
- If more than 16 witnesses are supplied, the deterministic display
  reports omitted rows as UNKNOWN. Input duplicate/invalid IDs reject;
  source graph caps/unknowns are inherited intact.

## Regression

Java21 pure-source `HardwareIndirectMmMaySelfTest` checks a local and
transitive possible SIMCR/MM STORE, negative bounded subtree,
unknown address/width, missing targets, unknown control flow,
cycles, depth cut, a 17th omitted site, deterministic row ordering,
immutable results, invalid caps, and **no false RESET reachability**.
Real isolated synthetic Ghidra 12.1.4 PUBLIC
`indirect-adjacent` and `indirect-bounded` fixtures compare
actual CPU32 decoded MOVEA/JSR bytes with a real SIMCR leaf at
`0x700`; unknown computed XREFs are not promoted. Existing
real Ghidra / Java25 full extension build is required at exact PR SHA.

No original ECU411 firmware, local user Program, Wyse/Precision,
legacy Supervisor, stopped timers, AI model or unauthorized write used.
