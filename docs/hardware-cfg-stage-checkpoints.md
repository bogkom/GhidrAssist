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
