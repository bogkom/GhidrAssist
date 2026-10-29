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

## 2026-10-29 — explicit invalidation of in-flight stage writers

Previously an in-flight CFG scan could finish after an explicit UI cache
clear and repopulate a revision-matching stage (even though it had already
been discarded). New weak-key, process-local **epoch tokens** bind each
calculation to its initial cache generation. `clear(program)` always
increments the epoch — including before the first successful checkpoint —
and removes the completed entry.

Cache hits are rechecked against a fresh Ghidra revision and cooperative
cancellation before returning. A late producer must verify its original
epoch **before inserting** and **before returning**; otherwise it cancels
without publishing the stale result, including oversized results not stored
in the cache. The UI's explicit stale-evidence discard also clears the
completed CFG checkpoint, but normal Cancel Analyze continues to preserve
a genuinely completed stage for safe same-revision reuse as before.

This does not guarantee scheduling or prove that the firmware executed.
The result still needs full on-host revision checks, and none of the
checkpoints persist across process restarts. Deterministic concurrency
regressions run without Ghidra; actual UI cancellation and Ghidra
Undo/Redo acceptance remain required.
