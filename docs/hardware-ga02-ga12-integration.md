# GA-02/03 + GA-12 — joint integration checkpoint (review branch only)

This branch intentionally joins two historically separate **unmerged** stacks:

- GA-02/03: **#122 → #123 → #126 → #128**, exact source commit
  `3da49bfc1ee642441ff65d759f98c21f363ee899` (SIMCR byte overlap, 24-bit wrap, per-CALL-site may-write,
  strictly proven leaf and acyclic branch-return register constants).
- GA-12: **#124 → #125 → #127 → #129**, exact source commit
  `4b2d536db06ef283f98e66ed1efd4ce8f611e4ff` (program/JAR-bound
  completed CFG stages, per-function cache, opt-in durable checkpoints,
  bounded interrupted fixed-point worklists and restart).

**Do not merge either stack or this branch into master without owner review.**
This integration commit has both original heads in its Git parent ancestry;
it does not rewrite historical commits or their Actions evidence.

## Reconciled model

The combined `HardwareDataflow` retains GA-02/03's MC68332 24-bit
effective-address wrap, SIMCR MM-low-byte overlapping write detection,
indirect/indexed pointer provenance, conservative unknown STORE and
`CALL_BARRIER` semantics **and** GA-12's bounded `analyzeSlice`,
typed incomplete `Progress`, result restoration and finished checkpointing.

`GhidraHardwareFlowService` still accepts only verified direct callee
output constants: all paths of a fully decoded, bounded acyclic leaf must
agree on each returned A/D register; no unproven CALL, peripheral state
or VBR value can cross the barrier. Its normal full report now uses
GA-12's completed function cache and optional per-function disk restore.
Incomplete functions never publish as RAG, Review or Apply evidence.

`HardwareFunctionStageCache.signature` was bumped from
`GA12-FUNCTION-CFG-FIXPOINT-1` to **`-2`**. SHA-256 now includes,
in deterministic register-name order, every
`Step.verifiedCallReturns` register/value pair. The per-function durable
key already incorporates this translated Step digest and exact analyzer
JAR byte SHA-256, so both prior completed function files and partial
pending worklists are rejected when the callee summary changes.
No rewriting of user settings, original firmware, Ghidra projects, or
OAuth is required; all durable checkpoints remain explicitly opt-in and
must use a trusted private isolated directory.

## Acceptance before integration

1. Java 21 source regression:
   `HardwareCallCheckpointIntegrationSelfTest` proves positive CALL return
   constants, changed/unproved output hash misses for **both process-local
   and durable** fixed-point caches, and pending-worklist rejection.
   Callee result map insertion order cannot influence SHA; cold and sliced
   fixed points agree; MC68332 SIMCR overlap remains intact.
2. Real synthetic Ghidra 12.1.4 PUBLIC:
   `branch-cache` checks that a branch-convergent callee yields only
   static SIMCR source evidence, its completed GA-12 report is reusable,
   and explicit invalidation recomputes it without editing the project.
3. Full extension build and existing real synthetic Ghidra regressions,
   with all outcomes attached to the **exact final joint commit SHA**.
4. Source-level CI PASS is not a Wyse GUI PASS or formal Supervisor PASS.

Remaining roadmap GA-02/03 and GA-12 statuses are **PARTIAL**. This
does not establish actual RESET execution, write-once MM latch acceptance,
physical chip selects, or interrupt activation.

## Review order and next integration dependencies

Review existing independent #118–#121 for overlaps (especially RESET
vector and revision-safe rename). Review/integrate #122 and #124 as
foundations, then the corresponding dependent work in causal order.
The joint branch is a testable convergence checkpoint, NOT authority to
auto-merge every individual PR or bypass protected branch rules.

New work after integration: stronger interprocedural path/alias evidence,
bounded VBR/ISR dependency correlation, durable provenance of authorized
changes, and CI/API-first regression coverage; no paused local Supervisor
worker will be restarted.
