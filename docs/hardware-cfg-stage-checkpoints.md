# GA-12 — completed CFG checkpoint and cooperative Cancel Analyze

Dependency: PR #60 exact commit `a0dd587b8f60d47afdbf1a9725b6e0039dc87456`. This draft keeps the same
revision-based full-report invalidation and adds **one completed phase
checkpoint**. Its scope is intentionally narrower than cross-session
resumption.

The read-only CFG/P-code pass is now completed before the Listing/reference
inventory. Once the CFG pass finishes successfully and the program revision
is unchanged, its result is held in a process-local weak-key cache. If a
user cancels the later inventory, pressing Analyze again can reuse the
already completed CFG evidence, **only** when the exact open Program,
language, original import SHA metadata, Ghidra modification/Undo/Redo
counter and manually selected CPU profile remain identical.

Click **Cancel Analyze** to invoke a cancellable TaskMonitorAdapter. The
worker checks cancellation within existing CFG/inventory loops. A cancelled
scan does not publish partial markdown to RAG, does not activate
Review/Apply or export, and never implies firmware execution. The UI
explicitly says cancellation was requested and whether a completed
checkpoint may be eligible for reuse; its presence is conditional.

A changed program, Undo/Redo or profile selection invalidates checkpoint
reuse. The cached value does not hold a strong reference to a Ghidra
Program. Oversize reports over 1,000,000 characters are not cached.

The checkpoint is **not written to disk**, cannot resume a half-computed
function, and cannot survive Ghidra restart. Full per-function incremental
resume will need a separate stable input/section hash and cancellation
boundaries. No Ghidra DB edits, file data or OAuth secrets are created.

CI: deterministic stage-schema/negative-reuse tests and full 12.1.4
extension build. Local acceptance: isolated project COPY, cancel during
inventory after complete CFG, repeat on unchanged revision, edit/Undo
to confirm recompute, verify no stale RAG or Review/Apply access.
Do not mark GUI validation PASS until actual host test.

## GA-12 durable checkpoint store — opt-in foundation

The new pure-Java HardwareDurableStageStore can persist bounded, **completed**
stage bytes in an explicitly supplied, existing, isolated directory. Files
use SHA-256 checksums, exact project identity, original executable hash,
analyzer fingerprint, manually selected MCU and, critically, a SHA-256 of the
**entire current analyzed input**. Checkpoint replacement uses atomic rename
and rejects symlink targets. Corrupt, oversized, stale or mismatched files are
cache misses. These files never reach public CI artifacts except synthetic
test fixtures. No original user firmware, OAuth credentials or configuration
are copied.

**Opt-in resume of one completed CFG stage:** HardwareFlowStageCache can
now read and write a bounded, typed, complete GhidraHardwareFlowService.Report
to this directory. Enable it only in an isolated working-copy environment by
setting the JVM system property (with an already-created private directory):

    -Dghidrassist.ga12.durable.dir=/path/to/isolated/private/checkpoints

The default is **OFF**; no disk directory is automatically created. The
fingerprint binds the Ghidra DomainFile file ID and project locator (not
only the name), imported source SHA-256, selected MCU/language, complete
initialized memory contents, function bodies, instructions, P-code, references
and the exact installed extension JAR SHA-256. If any input cannot be
measured, if any check changes, or if stored evidence is corrupt, the
checkpoint is ignored and the CFG stage recomputes. Stage writes are atomic.
No Ghidra project is modified by loading or saving the external checkpoint.

Only complete, non-limited CFG reports are persisted, never partial/failed
work. A resumed stage remains read-only and all existing Review/Apply/Undo
authorization applies; it is not proof of executed MCU instructions.
The model does **not** yet resume mid-function or halfway through CFG.
This snapshot is derived analysis data that may contain sensitive addresses
or annotations; keep it private and NEVER upload it to GitHub.

Native synthetic Ghidra 12.1.4 CI runs independent JVM processes for
cold write, reopen/reuse, and analysis-byte-edit invalidation. Distinguish
its exact-SHA PASS from source-only persistence tests and from any manual
Wyse/Precision acceptance.

## GA-12 — completed per-function CFG fixed-point checkpoints

The new `HardwareFunctionStageCache` stores **only completed**, nontruncated
results from `HardwareDataflow.analyze` in a weak-key, bounded, process-local
map. If a later function is cancelled, a same-process retry of the whole
CFG stage can replay those independently completed fixed points. A function
whose CFG budget was reached, or whose result was interrupted, is NEVER
reused as completed.

Each entry is bound to the exact Ghidra Program object, modification counter,
language, original imported SHA, explicit MCU selection, function entry,
iteration budget and a SHA-256 of every translated instruction/CFG successor,
implicit A/D register side effect and peripheral target address set. A
function whose input differs is recomputed, and a stale generation cannot
republish a result after explicit `HardwareFlowStageCache.clear`. Weak
owner keys avoid pinning closed Ghidra Projects. Cache retains the first
192 completed functions per Program and declines later entries rather than
evicting earlier entries that a cancellation retry would need first. Each
function also has step/snapshot caps and
4,096 total saved MMIO-word/register-cell entries per function. An additional
weak object-identity guard prevents cache reuse even if two distinct Ghidra
Program objects compare equal via `equals()`.

The intermediate checkpoints do **not** publish incomplete report, RAG
evidence or Review/Apply. They avoid only repeated *intraprocedural fixed
point computations*: functions still undergo Listing/P-code decoding and
the final full-report aggregation. Unlike the existing opt-in whole-stage
durable checkpoint, these smaller function checkpoints do not persist over
Ghidra restart; implementing that requires a separate authenticated typed
function-result format and persistence limits. No runtime MCU execution
or hardware MM latch is inferred.

## GA-12 — opt-in durable completed-function continuation

The *same existing* private `ghidrassist.ga12.durable.dir` system property
also permits saving **individually finished** (not interrupted) function
fixed points during the full CFG scan. This covers the case where Ghidra
is closed or analysis cancelled **before the overall report finishes**.
After restart, if the project, full Ghidra Listing/initialized memory,
references, extension JAR and MCU profile match exactly, a resumed scan
may restore each completed function and continue with the next function.

Each per-function key additionally covers its function entry, iteration
budget and SHA-256 of the entire translated CFG/Step inputs, including
successors and side effects. At most the first 64 eligible functions have
external slots per pass; filenames are stable per project+function, so
revision changes overwrite the old unusable slot instead of creating a
different file per revision. Incomplete, truncated and oversized fixed
points are not written. Loading is read-only and does not automatically
publish an unfinished RAG/Review/Apply report.

Full-report disk resume from PR #124 still takes precedence if an exact
finished report exists. Explicit `HardwareFlowStageCache.clear` disables
disk readback for that in-process retry and cancels earlier generation
work. A changed Ghidra Program input always recomputes.

SHA-256 here detects accidental corruption; it is not an authenticity
signature against someone who can write the private checkpoint directory.
Never point it at untrusted/shared locations. No partial *within-function*
iteration checkpoints, and no firmware execution proof, are implemented.
