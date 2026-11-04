# GA-12 — fail-closed literal identity in completed CFG checkpoints (v3)

## Parent and scope

Stacked on [PR #136](https://github.com/bogkom/GhidrAssist/pull/136)
(`856791d93de71402e286bcc459508ccc6162cca5`), which in turn
depends on the reviewed GA-02/03 × GA-11 integration [#135](https://github.com/bogkom/GhidrAssist/pull/135).
Do not merge the large parent stack to `master` without owner approval.

## Cache correctness finding

`HardwareFunctionStageCache.signature()` previously wrote the same
four bytes (`-1`) for **absent `Step.literalWord`** and the legitimate
signed 32-bit literal **`Integer.valueOf(-1)`**. With all other
translated CFG fields equal, the v2 SHA-256 was identical even though
a 16-bit STORE's evidence differs:

- absent literal, no known source register: `writtenWord = UNKNOWN`;
- literal `-1`: `writtenWord = 0xFFFF`.

Because the full-input signature is used for both RAM completed-function
cache and opt-in GA-12 durable per-function checkpoints (including
interrupted-worklist keys), this collision could incorrectly reuse
a fixed point for a different translated source input.

## Correction

- A tagged representation now first hashes `literal-present: 0/1`,
  then the full signed integer only if present. Absence cannot collide
  with any valid signed `int` literal.
- Signature namespace changes from
  `GA12-FUNCTION-CFG-FIXPOINT-2` to
  **`GA12-FUNCTION-CFG-FIXPOINT-3`**. Previously persisted v2 function
  stages/progress do not match v3 input keys; a cold recomputation is
  required rather than silently inheriting old evidence.
- Java 21 deterministic regressions compare the distinct output
  snapshots and SHA values and test **both directions** of mismatched
  cache lookup, in memory and in the exact stable on-disk function slot.

These are source-level proof/isolation properties, **not** evidence of
firmware execution or MM write-once latch state. They do not create
Review/Apply/Undo rights, change MCU profiles or touch the original
ECU411/production Ghidra project, OAuth or the paused Wyse/Precision
Supervisors.

## Verification

Run all GitHub Actions relevant to this stacked PR, including the full
Ghidra 12.1.4 PUBLIC / Java 25 extension build, Java 21
`HardwareFunctionStageCacheSelfTest` and
`HardwareDurableFunctionStagesSelfTest`, and existing real synthetic
Ghidra GA-12/GA-02 checkpoints. Associate PASS/FAIL only with the
**exact final PR head SHA**; a created PR is not a CI PASS.
