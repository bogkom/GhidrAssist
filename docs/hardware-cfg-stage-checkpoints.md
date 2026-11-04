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
