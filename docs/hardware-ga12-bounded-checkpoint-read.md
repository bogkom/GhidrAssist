# GA-12 — bounded, no-follow durable checkpoint reads

The opt-in durable checkpoint store persists completed or partial CFG stages
in an isolated user-selected directory. It is a cache, not a trusted source
of executable evidence or an authorization mechanism. Its digest detects
accidental corruption but does not independently authenticate a writer.

Prior to this change, a successful size check was followed by
`Files.readAllBytes(path)`. A concurrently replaced or growing file could
become much larger than its pre-read length, allocating unbounded memory
before digest and schema validation.

Now, `load` reads a single `BasicFileAttributes` snapshot without following
a symbolic link, opens the final file component with `NOFOLLOW_LINKS`,
and decodes **at most `MAX_FILE_BYTES + 1` bytes** from the stream.
Any oversized, truncated, foreign-key, corrupt or schema-incompatible
content is an ordinary cache miss. This closes the time-of-check/time-of-use
**size-bound** gap and final-component symlink-follow risk; the directory
itself is still required to be an existing non-symlink location, and this
does not assert protection against a hostile process that can replace
ancestor directories concurrently.

The deterministic Java21 regression exercises a valid roundtrip through
small stream chunks, a synthetic unending source (exact byte budget),
a sparse oversized checkpoint, missing inputs and the existing symlink
destination guard. Independent full Ghidra 12.1.4 PUBLIC/Java25 extension
and isolated synthetic Ghidra workflows must PASS on the exact PR SHA.

This is not cross-project trust, a verified hardware profile, active
SIMCR/MM or VBR/ISR proof, and does not touch original ECU411 firmware,
user Ghidra projects or stopped Wyse/Precision/legacy Supervisor tests.


## Offline source-pair checkpoint comparison (GA-12/18, pending acceptance)

The `ghidrassist-agent source-pairs-compare --input OLD.json --compare-input NEW.json --offset 0 --source-limit 32` command compares two separately SHA-256-verified, bounded, static source-pair inventories without contacting the Ghidra RPC server. It requires the same firmware import SHA-256, the same explicitly selected MCU profile, and modern coverage metadata on both inputs. A changed import/profile or a legacy checkpoint is refused rather than interpreted as a source delta.

The read-only result reports added, removed and changed source-pair records keyed by function/indirect-JSR/MOVEC source PCs, including before/after evidence, exact total and paginated changes, source coverage before/after, generation/revision identifiers and a separate incompleteness indicator. No changes means only that the retained pair rows match: unpaired MMIO/MOVEC sources, omitted evidence, path feasibility and actual hardware state may still differ. Comparing checkpoints does **not** rebind them to a live Program, restore a CALL graph, authorize Resume/Review/Apply, or implement firmware comparison GA-14.

Acceptance requires deterministic positive/negative Python tests (including forged digest, mismatched firmware, missing coverage and invalid pagination), Java 21 source gates, full Java 25 Ghidra 12.1.4 PUBLIC build and genuine isolated synthetic Ghidra CI at the final exact SHA. This section documents the proposed scope, not a formal GA-12/18 completion claim.

## Historical-to-live source delta (GA-12/18, pending acceptance)

`ghidrassist-agent --session SESSION source-pairs-compare-live --input HISTORICAL.json --offset 0 --source-limit 32 --page-size 32` compares a verified historical checkpoint against a **freshly collected** complete source-pair inventory from the currently active, explicitly selected Ghidra program. Unlike `source-pairs-resume-check`, it permits different analysis generations/revisions and reports ADDED, REMOVED and CHANGED evidence plus coverage deltas. It still requires the same import SHA-256 and MCU profile; a changed firmware is **refused**, not silently treated as GA-14 comparison.

The client validates the historical digest/coverage and page bounds before contacting the live authenticated JSON-RPC session. It collects every current page and a terminal generation fence, rejects changed generation, incomplete pagination and mismatched firmware/profile, then compares the two verified inventories. The temporary live checkpoint is created in a private OS temporary directory and removed before returning; the historical file is never overwritten. The response has `offline:false`, `live_read_only:true`, `resume_authorized:false`, `apply_authorized:false`. The operation does not run Analyze, edit a Program, restore a CALL graph or authorize Review/Apply/Undo. A row delta is **static observed evidence**, not proof of runtime execution, latched SIMCR/MM, active VBR/ISR or physical Chip Select mapping.

Deterministic tests cover changed source rows across generations, removal of temporary state, stale generation/terminal cursor refusal, mismatched import and invalid historical digest/page parameters. Formal acceptance still requires exact-SHA Python regression, Java21 source checks, full Java25 Ghidra 12.1.4 PUBLIC extension build, real isolated synthetic Ghidra CodeBrowser JSON-RPC invocation and review. GA-12/18 remain PARTIAL.
