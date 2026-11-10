# GA-02/03 — conservative adjacent CPU32 indirect JSR source provenance

## Scope

The Automation API call-path service already validates a strictly adjacent
CPU32 instruction pair from the original instruction bytes:

```
MOVEA.L #<exact function entry>,An
JSR     (An)
```

The Ghidra 12.1.4 PUBLIC hardware report previously treated all computed
CALLs as UNKNOWN, and so did not display this *narrow, independently
verified source* at all. Reimplementing another MOVEA/JSR decoder would
risk diverging from the already-tested Automation API.

The existing `AutomationCallPaths.adjacentConstantRegisterCall` verifier
is now publicly reusable by the hardware report. It returns a target
**only** for the exact 6-byte MOVEA.L immediate followed immediately by
the 2-byte `JSR (An)` to the same address register on
`68000:BE:32:CPU32`, and only when Ghidra has already defined an
**exact target Function entry**. The hardware caller additionally
requires both instructions within one caller Function body and all
evidence addresses within the 24-bit MC68332 source range.

## Read-only evidence and safety

A new bounded `HardwareIndirectCallEvidence` section contains the
caller entry, MOVEA instruction, computed JSR PC, candidate exact target
and explicit `adjacent_movea_immediate` provenance. It limits display
to 96 sources and counts omitted candidates. Every nonmatching computed
CALL remains UNKNOWN. Results are sorted, unique by CALL PC, and are
never promoted to a direct CALL graph edge, transitive RESET proof,
GA-12 checkpoint, MCU MM-latch claim, or Review/Apply operation.
The source predicate itself does not imply an executed instruction.

A Java 21 deterministic regression checks bounded source rows,
deterministic ordering, duplicate/bad input, unknown and cap evidence.
A separate **real synthetic Ghidra 12.1.4 PUBLIC/Java25** fixture
tests actual bytecode for:

- an adjacent `MOVEA.L #0x700,A0; JSR (A0)` pointing to a
  defined function containing a candidate SIMCR source STORE;
- an uninitialized `JSR (A1)`;
- `MOVEA.L #0x700,A1; JSR (A0)` (register mismatch);
- `MOVEA.L #0x720,A0; JSR (A0)` (no exact target Function).

The fixture also checks computed-call decoding, no promotion into
Apply-eligible CFG sources, unchanged Program modification number,
repeat determinism and the explicit MC68332 profile gate. The GitHub
Actions workflow pins Ghidra release SHA-256, Java25, extension
packaging and tested harness hashes.

No original ECU411 firmware, user Ghidra project/profile or stopped
Wyse/Precision/Supervisor infrastructure is touched.

## Remaining gaps

Computed CALLs beyond the exact adjacent immediate form, including
branch-dependent addresses, memory-loaded vectors, address-register
arithmetic and nonadjacent provenance, remain UNKNOWN. This patch does
not enable any implicit cross-function dataflow or prove that the
24-bit CPU32 logical address corresponds to a physical chip-select.

## 2026-11-05 — additional bounded source paths (GA-02/03)

The Automation API had already implemented a more general **strictly
straight-line** CPU32 fall-back for `JSR (An)`: walk back no more than
four decoded instruction boundaries to a `MOVEA.L #<exact entry>,An`,
allowing only zero to three interposed `NOP` and/or `MOVEQ #imm,Dn`
instructions (both leave An intact). The hardware report previously
showed only the adjacent pair. It now reuses the same original byte
checker, with an **additional Function-body containment requirement for
every instruction** in the traced source chain. It never speculates
through branches, memory loads, ADDQ/CLR, arbitrary register writes,
or missing exact target Functions.

The report preserves three distinct source labels:
`adjacent_movea_immediate`, `bounded_movea_nop_chain` and
`bounded_movea_safe_chain`. Strictly bounded, sorted and unique
display rows include MOVEA PC, JSR PC, target and provenance.
Unresolved, over-budget and uninspected calls remain UNKNOWN.
These are **possible static source paths**, not guaranteed or executed
dispatch, and remain outside direct CALL graph, RESET reachability,
MC68332 active MM latch and all Review/Apply/Undo decisions.

A dedicated real synthetic Ghidra 12.1.4 PUBLIC/Java25 fixture
decodes bytecode for both allowed chains and negative controls
(unsupported CLR.L, mismatched A1/A0, absent exact Function).
It checks all per-source evidence, unchanged Program revision,
repeat determinism, generic CPU32 gate and non-promotion to Apply.
Java21 independently verifies allowed label integrity and output
bounds. Existing adjacent source and Automation API call-path
regressions must remain green on the exact PR SHA.


## 2026-11-10 — target-rooted source chains for indirect SIMCR/MM MAY

The read-only computed-JSR SIMCR/MM report now carries its underlying
bounded `HardwareInterproceduralMmEffects` source witnesses, instead
of exposing only `STATIC_MAY_MM_LOW_BYTE` or `UNKNOWN` booleans.
Each row separately labels shortest deterministic `MM_SOURCE`,
`STORE_ALIAS`, **observed** `UNKNOWN_FLOW`/`MISSING_TARGET` and
**uninspected** `DEPTH_CUTOFF`/`NODE_CUTOFF`/`BATCH_CUTOFF`
function-entry chains. When the original unknown witness denotes only
a cutoff, the observed-unknown field remains `NONE` and the cutoff
is shown independently. Cycles remain a separate uncertain flag and
never fabricate a callee chain.

A source chain begins at the **byte-verified computed JSR target**, not
the caller's JSR PC. The report refuses a chain rooted at another target,
duplicate computed-call PC or oversized manually created result. This is
only static function-level source connectivity, NOT a verified execution,
feasible CFG route, indirect graph edge, RESET/ISR reachability, latched
SIMCR MM, selected VBR or Review/Apply permission. Omitted/exhausted
sources stay UNKNOWN, and no disk cache replays those source chains.

The same revision-scoped joint JSR/MOVEC co-location inventory now rejects
an impossible cross-kind collision at one decoded instruction PC, even
when each type's inventory is individually duplicate-free or the queried
page does not display that source pair. Exact-page counts, omission flags
and native revision fences are otherwise unchanged. Synthetic Java21
regressions exercise positive MM, uncertain aliases/flow, missing target,
cycles, limited depth with a positive skipped leaf, reversed inventory,
foreign-root chains, same-PC JSR/MOVEC collision and later-page refusal.
Real Ghidra 12.1.4 PUBLIC Java25 extension/headless CI must pass before
integration. GA-01/02/03/11/18 remain PARTIAL.

## 2026-11-10 — public RESET/JSR/MOVEC pair and page consistency

The existing selected-MC68332 same-Function source correlation has a
bounded `SourceInventory`, canonical per-PC decoded JSR and MOVEC
observations and revision-fenced on-demand pages. The public `Pair`
and `Result` records are also constructible by other Java callers,
so their own constructors now enforce the same conservative evidence
**shape** before any Markdown can be published:

- Even bounded 24-bit function, indirect target, JSR and MOVEC PC
  identities; PC must be at/after the indicated Function entry.
  Candidate VBR source base must stay within the selected MCU24
  candidate envelope; one decoded PC cannot be both kinds of instruction.
- Exact complete page windows, inventory-product bound, stable
  cursor/has-more/truncation semantics and deterministic ordered
  distinct displayed pairs. There is no implicit skipped row in a
  supposedly complete page.
- Same JSR PC must retain one target and MM MAY verdict; same MOVEC PC
  retains one candidate VBR base. Both instruction inventories remain
  disjoint within the page. Repeated Function rows cannot disagree
  on observed RESET relation or graph incompleteness.
- Unknown RESET roots cannot be forged into known reachability. No
  partial proof authorizes new CALL edges, ISR firing, MM latch,
  actual VBR relocation or Review/Apply.

These checks are in addition to (not a replacement for) the original
source-inventory full-set identity checks and the same-Program revision
epoch fence. Java21 source-only adversarial tests assert accepted
canonical/fully stitched pages and rejected conflicting user-created
records; complete Java25 extension compilation and real isolated
Ghidra 12.1.4 PUBLIC synthetic CI remain required before integration.
GA-01/02/03/11/12/18 remain PARTIAL.
