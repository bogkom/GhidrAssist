# GhidrAssist — 18-track hardware-analysis development ledger

Status: **IN PROGRESS**. Scope source: user-approved 2026-10-28 requirements (A–H, additional features 13.1–13.7, PDF/RAG, testing and Codex Supervisor integration).

## Immutable engineering rules

- Ghidra target: **12.1.4 PUBLIC**, baseline for this work: `fix/hardware-analyze-focused-report-20261028`, commit `412448166ec5d9cc3750ee10d1ec215804ae5802` (draft PR #52), which itself builds on `codex/agentic-policy-and-evidence-fixes`. Do not substitute old `master` as a new-feature baseline without reconciling these changes.
- Preserve independent draft PRs #48–#50 and their local unpushed work. Reconcile overlap and obtain verification before closing or merging.
- **Static reachability ≠ execution**. Instruction-address order ≠ runtime order. MM may be write-once. Unknown call side effects and aliases must invalidate unjustified value claims.
- MCU-dependent information is conditional on a **manually selected, documented device**, never silently inherited by generic CPU32.
- Analyze is compact. Detail/uncertainty belongs in dedicated views; complete register catalog and explicit, undoable changes belong in Review / Apply.
- Public repository and Actions must never contain ECU411 firmware or its Ghidra project. On-host test copies only. Test artifacts contain non-sensitive summaries/hashes.
- GitHub Actions first; Supervisor plans pinned to immutable full 40-character commits and verified build artifacts. On 2026-10-29 the owner granted **standing, revocable authorization** for standard isolated tests across all 18 tracks (GA-01..GA-18). Plans satisfying the host-bound, machine-checked authorization policy can be approved and run automatically; out-of-scope plans still require separate explicit authorization. The authoritative private queue remains `bogkom/codex-supervisor/test-plans/queue/`. Codex may freely modify **its dedicated Ghidra test project** but not implementation sources, other user projects, firmware originals, system settings or secrets.

## Scope mapping — exactly 18 tracked workstreams

The originating document has 18 *sections*, not 18 independent feature checkboxes. To avoid dropping any feature, the 18 implementation tracks below explicitly cover A–H, 13.1–13.7, RAG, verification, and autonomous test delivery. Section numbers 1–4 and 14,17,18 supply requirements and constraints across the tracks.

| ID | Source | Deliverable | Audited baseline 2026-10-28 | Acceptance / evidence |
|---|---|---|---|---|
| GA-01 | A | Reset vector / entry evidence and reachable initialization flow | PARTIAL: function-local CFG/call references; reset-root graph missing | Validate vector bytes / entry, distinguish reachable/candidate/unknown |
| GA-02 | B | Path-conditional SIMCR/MM (write-once), TRAMBAR, CSBAR/CSOR/CSPAR and VBR epochs | PARTIAL: snapshot/unknown-call invalidation; reset-relative epochs missing | Branch/alias/call uncertainty preserved, addresses and source paths |
| GA-03 | C | Indirect MMIO via A/D registers, indexed modes, P-code LOAD/STORE, aliases | PARTIAL: substantial CFG/P-code work merged through #35 | Synthetic alias joins, call barriers, no invented constants |
| GA-04 | D | Per-select CSBOOT, CS0..CS10 table in Analyze | PARTIAL: decoder/windows exist; Markdown currently uses per-window bullets | 12 separate rows, start/end/size, missing values UNKNOWN, model scope |
| GA-05 | E | Safe CPU32-unknown vs model-specific Review/Apply | PARTIAL: MC68332 full catalog; unknown-mode review constrained | No model-inherited unsafe maps; collision/transaction/Undo tests |
| GA-06 | F | Extendible sourced MC683xx profiles and conflict matching | PARTIAL: MC68332 and document hints, no complete import pipeline | Explicit model/version/page/bitfields/reset source; SVD/RDL feasibility |
| GA-07 | G | Compact 3-part Analyze: initiation, register history, CS map | PARTIAL: PR #52 focused site filtering; three-part report missing | UI/Markdown/RAG agreement, concise report, evidence links |
| GA-08 | H | Function, pointer and variable naming proposals | PARTIAL: function naming/Undo (#22/#28); pointers/locals missing | Collision-safe preview, manual labels preserved, transactional Undo |
| GA-09 | 13.1 | MMIO accesses explorer with navigation | MISSING as dedicated view | Filterable function/instruction/value/access/confidence with Go To |
| GA-10 | 13.2 | Verified bitfield decode with provenance | PARTIAL: MC68332 metadata; comprehensive decoder missing | Unknown fields UNKNOWN; model- and edition-specific source |
| GA-11 | 13.3 | Interrupt / exception analysis including VBR and ISR paths | PARTIAL: VBR sightings, no full ISR graph | Static candidates not treated as active IRQs |
| GA-12 | 13.4 | Resumable, version-aware incremental analysis | MISSING dedicated analyzer checkpoint protocol | Program identity, input hash, invalidation and resume regressions |
| GA-13 | 13.5 | Human/analysis/AI origin of changes | MISSING verified per-symbol provenance | Check actual Ghidra 12.1.4 SourceType API; retain rationale and Undo |
| GA-14 | 13.6 | Firmware configuration comparison | DEFERRED by source priorities | Assess Ghidra Version Tracking first; later CS/VBR/peripheral diff |
| GA-15 | 13.7 | Agentic planning, indirect calls, context, pagination, stale cache | PARTIAL: draft PR #49/#50 overlap and existing Agentic work | Don't duplicate existing tools; budget/policy evidence regression |
| GA-16 | 15 | Physical PDF page/printed label, register tables, sourced RAG | PARTIAL: native PDF/RAG and labels; tables uncertain | No auto-promotion of ambiguous PDF rows; page/edition evidence |
| GA-17 | 16 | CI, synthetic tests, isolated ECU411 project acceptance and rollback | PARTIAL: pure-Java Actions and private firmware tests exist | Compile 12.1.4, record artifacts/hashes, reversible actual-Ghidra test |
| GA-18 | 17 + new decision | GitHub-controlled multi-stage local Supervisor tests | PR #53 real isolated Ghidra 12.1.4 headless test **FINISHED/PASS**, report published privately; standing auto-test policy proposed in private Supervisor PR #9 | Immutable JSON + signed-off standing policy, host artifact SHA, quota/ownership guards, genuine ACK and private reports; no Codex programming |

## Dependency order and milestones

1. **Foundations/compatibility**: GA-17/GA-18, reconcile PR #48–#52 without disrupting installed #52; map existing Java APIs and tests.
2. **Reliable memory evidence**: GA-04 (initial deterministic table), GA-02/GA-03 (path state), GA-10 (bitfields), GA-05/GA-06 (device-scoped definitions). No false dynamic maps.
3. **Reset-rooted analysis**: GA-01, GA-11 and their prerequisites; then GA-07 combines initialization/history/map without dumping all registers.
4. **Investigation and safe edits**: GA-09, GA-08, GA-13; independent transactional and GUI regressions.
5. **Documentation and agent workflows**: GA-16, GA-15, GA-12; retain report provenance and avoid model token use for deterministic checks.
6. **Later comparison**: GA-14 after a stable report schema and Ghidra Version Tracking evaluation.

Each milestone: focused Java tests -> exact 12.1.4 extension build on GitHub Actions -> immutable candidate commit -> queue plan in private Supervisor repo -> **automatic approval only if the user's standing GA-01..GA-18 policy is active and the plan is eligible** (otherwise explicit per-plan approval) -> verified isolated-Ghidra regression -> review and merge. A plan proposal is not a PASS. Do not merge on planned rather than observed test results. The user will evaluate overall GUI/usability and feature quality **after all 18 tracks**, not approve each routine PR UI checkpoint; this does not waive automated/real-Ghidra tests or irreversible-change safety.

## First implementation batch

GA-04: add a pure, deterministic Markdown representation of the twelve MC68332 chip selects using the existing `ChipSelectModel.Window` decoder; unknown CSBAR/CSOR/CSPAR stays UNKNOWN. Integrate only as a **conditionally decoded** table in existing Hardware Analyze evidence, without claiming actual execution sequence, external wiring or firmware-derived active bus cycles. Keep all Review/Apply entries untouched.

For upcoming steps prepare independent Supervisor plans, each pinned to the corresponding **post-commit** GhidrAssist SHA. Do not queue speculative hashes or untested mutable refs.

## Explicitly deferred, not lost

Full MCU/peripheral emulation, physical CS electrical simulation, generic automatic hardware identification, and broad multi-firmware comparison remain out of the initial delivery, as required by original section 14.

## Standing local-test authorization (owner decision, 2026-10-29)

The user granted a **single standing authorization** for standard GhidrAssist GA-01–GA-18 tests, including GUI/headless execution and arbitrary edits to **Codex's own dedicated test project** (Review/Apply, names/types, Undo, disposable memory/test data). This does **not** authorize source-code implementation by Codex, changes to other Ghidra projects or original firmware, system-admin operations, OAuth/secrets access, network downloads by Codex, or publishing private content.

Supervisor may automatically approve only pinned private GitHub queue plans with an explicit GA-01..GA-18 authorization envelope and verified successful Ghidra 12.1.4 artifact. The host checks the archive and extension SHA-256 before dispatch; native Goal, quota, daemon ownership, nonces, ACKs, output hashes and failure gates stay enforced. An individual plan requiring powers outside this envelope still needs a separate user decision. This authorization is **revocable** and must be activated on the user's Wyse by a one-time, explicit `policy-enable --apply`; merely publishing this document does not start Codex or systemd timers. The optional `auto-timer` also remains disabled until explicitly enabled on the host. Never treat a JSON declaration or model instruction as a substitute for actual filesystem sandboxing.

GhidrAssist PR #53 was verified by GitHub Actions, real Ghidra 12.1.4 headless and Supervisor (1/1 verified test, terminal `finished`, private issue #8). The user manually confirmed its CS table displays. Full modal/Apply behavior remains outside that test's scope and belongs to subsequent acceptance tests; no manual per-PR UI approval will be solicited. Preserve original pinned PR #53 commit unchanged for reproducibility.
