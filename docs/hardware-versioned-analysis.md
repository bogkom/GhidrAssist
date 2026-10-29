# GA-12 — Revision-safe analysis and short-lived result reuse (partial)

This independent branch builds on `bd0a0a60eaa610e19581bd67fd16d29c637bfb8e` (PR #53).
Its scope is **in-memory revision validation**, not a persistent checkpoint.

Ghidra 12.1.4 `DomainObject.getModificationNumber()` increments after
changes, Undo or Redo. The analysis revision token records the exact
in-memory Program identity, modification number, Ghidra language, original
executable SHA-256 metadata (if provided) and explicitly selected MCU
profile. The latter SHA is metadata for the original imported binary;
it must not be misrepresented as a hash of modified project data. The
versioned evidence cache additionally keys entries to the analyzer
schema revision and invalidates stale entries on access.

**Behavior:** a completed unchanged revision can reuse its current UI
results when Analyze is pressed again. A program edit, Undo, Redo,
language/source metadata change or changed MCU selection prevents stale
report publication, reuse, Ghidra navigation, CSV/Markdown export,
Review / Apply and injection of stale hardware evidence into AI/RAG.
If a change occurs during an async scan, its result is discarded. Query
context revalidates the cache after excerpt construction.

This does **not** implement pause/resume of partly scanned CFGs, storage
of checkpoints across Ghidra sessions or a live firmware-content hash.
Those depend on a future bounded stage protocol and explicit cancellation
/ resume handling. No project data are modified by this change.

Verification: deterministic pure-Java adversarial revision tests and a
full Ghidra 12.1.4 extension build. Real acceptance requires a disposable
Ghidra project COPY and actual Analyze, Undo, Redo, navigation, exports
and RAG evidence checks, followed by explicit Supervisor approval. None
of those runtime tests are implied by green CI.
