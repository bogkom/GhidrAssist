# GhidrAssist — 18-track hardware-analysis development ledger

Status: **IN PROGRESS**. Scope source: user-approved 2026-10-28 requirements (A–H, additional features 13.1–13.7, PDF/RAG, testing and Codex Supervisor integration).

## Immutable engineering rules

- Ghidra target: **12.1.4 PUBLIC**, baseline for this work: `fix/hardware-analyze-focused-report-20261028`, commit `412448166ec5d9cc3750ee10d1ec215804ae5802` (draft PR #52), which itself builds on `codex/agentic-policy-and-evidence-fixes`. Do not substitute old `master` as a new-feature baseline without reconciling these changes.
- Preserve independent draft PRs #48–#50 and their local unpushed work. Reconcile overlap and obtain verification before closing or merging.
- **Static reachability ≠ execution**. Instruction-address order ≠ runtime order. MM may be write-once. Unknown call side effects and aliases must invalidate unjustified value claims.
- MCU-dependent information is conditional on a **manually selected, documented device**, never silently inherited by generic CPU32.
- Analyze is compact. Detail/uncertainty belongs in dedicated views; complete register catalog and explicit, undoable changes belong in Review / Apply.
- Public repository and Actions must never contain ECU411 firmware or its Ghidra project. On-host test copies only. Test artifacts contain non-sensitive summaries/hashes.
- GitHub Actions first; Supervisor plans pinned to immutable full 40-character commits; local tests run **only after operator approval**, via private `bogkom/codex-supervisor/test-plans/queue/`.

## Scope mapping — exactly 18 tracked workstreams

The originating document has 18 *sections*, not 18 independent feature checkboxes. To avoid dropping any feature, the 18 implementation tracks below explicitly cover A–H, 13.1–13.7, RAG, verification, and autonomous test delivery. Section numbers 1–4 and 14,17,18 supply requirements and constraints across the tracks.

| ID | Source | Deliverable | Audited baseline 2026-10-28 | Acceptance / evidence |
|---|---|---|---|---|
| GA-01 | A | Reset vector / entry evidence and reachable initialization flow | PARTIAL in stacked PR #54: image-zero vector decoding and bounded direct-call candidate paths, no interprocedural state transfer or proven execution | Validate vector bytes / entry on isolated ECU411, distinguish static candidate/unknown and complete indirect paths later |
| GA-02 | B | Path-conditional SIMCR/MM (write-once), TRAMBAR, CSBAR/CSOR/CSPAR and VBR epochs | PARTIAL: snapshot/unknown-call invalidation; reset-relative epochs missing | Branch/alias/call uncertainty preserved, addresses and source paths |
| GA-03 | C | Indirect MMIO via A/D registers, indexed modes, P-code LOAD/STORE, aliases | PARTIAL: substantial CFG/P-code work merged through #35 | Synthetic alias joins, call barriers, no invented constants |
| GA-04 | D | Per-select CSBOOT, CS0..CS10 table in Analyze | PARTIAL: decoder/windows exist; Markdown currently uses per-window bullets | 12 separate rows, start/end/size, missing values UNKNOWN, model scope |
| GA-05 | E | Safe CPU32-unknown vs model-specific Review/Apply | PARTIAL: MC68332 full catalog; unknown-mode review constrained | No model-inherited unsafe maps; collision/transaction/Undo tests |
| GA-06 | F | Extendible sourced MC683xx profiles and conflict matching | PARTIAL: MC68332 and document hints, no complete import pipeline | Explicit model/version/page/bitfields/reset source; SVD/RDL feasibility |
| GA-07 | G | Compact 3-part Analyze: initiation, register history, CS map | PARTIAL: PR #52 focused site filtering; three-part report missing | UI/Markdown/RAG agreement, concise report, evidence links |
| GA-08 | H | Function, pointer and variable naming proposals | PARTIAL: function naming/Undo (#22/#28); pointers/locals missing | Collision-safe preview, manual labels preserved, transactional Undo |
| GA-09 | 13.1 | MMIO accesses explorer with navigation | MISSING as dedicated view | Filterable function/instruction/value/access/confidence with Go To |
| GA-10 | 13.2 | Verified bitfield decode with provenance | PARTIAL: MC68332 metadata; comprehensive decoder missing | Unknown fields UNKNOWN; model- and edition-specific source |
| GA-11 | 13.3 | Interrupt / exception analysis including VBR and ISR paths | PARTIAL: PR #54 VBR evidence; new PR candidate image-zero exception table, static handler labels only; runtime VBR/IRQ graph unresolved | Static candidates not treated as active IRQs |
| GA-12 | 13.4 | Resumable, version-aware incremental analysis | MISSING dedicated analyzer checkpoint protocol | Program identity, input hash, invalidation and resume regressions |
| GA-13 | 13.5 | Human/analysis/AI origin of changes | MISSING verified per-symbol provenance | Check actual Ghidra 12.1.4 SourceType API; retain rationale and Undo |
| GA-14 | 13.6 | Firmware configuration comparison | DEFERRED by source priorities | Assess Ghidra Version Tracking first; later CS/VBR/peripheral diff |
| GA-15 | 13.7 | Agentic planning, indirect calls, context, pagination, stale cache | PARTIAL: draft PR #49/#50 overlap and existing Agentic work | Don't duplicate existing tools; budget/policy evidence regression |
| GA-16 | 15 | Physical PDF page/printed label, register tables, sourced RAG | PARTIAL: native PDF/RAG and labels; tables uncertain | No auto-promotion of ambiguous PDF rows; page/edition evidence |
| GA-17 | 16 | CI, synthetic tests, isolated ECU411 project acceptance and rollback | PARTIAL: pure-Java Actions and private firmware tests exist | Compile 12.1.4, record artifacts/hashes, reversible actual-Ghidra test |
| GA-18 | 17 + new decision | GitHub-controlled multi-stage local Supervisor tests | SUPERVISOR IMPLEMENTED; no GhidrAssist queued plans yet | Pinned JSON, explicit approve, quota safeguards, verified private reports |

## Dependency order and milestones

1. **Foundations/compatibility**: GA-17/GA-18, reconcile PR #48–#52 without disrupting installed #52; map existing Java APIs and tests.
2. **Reliable memory evidence**: GA-04 (initial deterministic table), GA-02/GA-03 (path state), GA-10 (bitfields), GA-05/GA-06 (device-scoped definitions). No false dynamic maps.
3. **Reset-rooted analysis**: GA-01, GA-11 and their prerequisites; then GA-07 combines initialization/history/map without dumping all registers.
4. **Investigation and safe edits**: GA-09, GA-08, GA-13; independent transactional and GUI regressions.
5. **Documentation and agent workflows**: GA-16, GA-15, GA-12; retain report provenance and avoid model token use for deterministic checks.
6. **Later comparison**: GA-14 after a stable report schema and Ghidra Version Tracking evaluation.

Each milestone: focused Java tests -> exact 12.1.4 extension build on GitHub Actions -> immutable candidate commit -> queue plan in private Supervisor repo -> explicit one-time local approval -> verified isolated-Ghidra regression -> review and merge. A plan proposal is not a PASS. Do not merge on planned rather than observed test results.

## First implementation batch

GA-04: add a pure, deterministic Markdown representation of the twelve MC68332 chip selects using the existing `ChipSelectModel.Window` decoder; unknown CSBAR/CSOR/CSPAR stays UNKNOWN. Integrate only as a **conditionally decoded** table in existing Hardware Analyze evidence, without claiming actual execution sequence, external wiring or firmware-derived active bus cycles. Keep all Review/Apply entries untouched.

For upcoming steps prepare independent Supervisor plans, each pinned to the corresponding **post-commit** GhidrAssist SHA. Do not queue speculative hashes or untested mutable refs.

## Explicitly deferred, not lost

Full MCU/peripheral emulation, physical CS electrical simulation, generic automatic hardware identification, and broad multi-firmware comparison remain out of the initial delivery, as required by original section 14.

## Second implementation batch (stacked after PR #53)

GA-01 RESET candidate evidence, without pretending to emulate reset:

- Read eight bytes at image zero only for the 68000 big-endian language family; parse unsigned initial SP and reset PC. If bytes, memory, format or function entry are unavailable, report UNKNOWN rather than inventing a boot route. Image-zero is explicitly a *hypothesis* about the firmware origin.
- Connect the PC's containing function to the already collected direct static-call graph and show bounded paths to **independently observed** MMIO/VBR evidence. Respect cycles, missing targets, computed flow and display budgets.
- Keep local MMIO dataflow results local. **No** interprocedural propagation, MM first-write-after-reset assertion, verified runtime ordering or reset vector remapping claims.
- Test vector endianness and invalid data, branch-like diamond paths, unresolved indirect calls, recursion and truncation in pure Java GitHub Actions; require full Ghidra 12.1.4 build and isolated on-host integration before merging.

This is a first GA-01 component, not completion of GA-01 or GA-02. Later steps must model reset-relative path-dependent register epochs and validate against real MC68332 documentation and firmware test copies.


## 2026-10-29 — GA-11 candidate interrupt vector inventory

- Branch: `feature/hardware-interrupt-vector-candidates-20261029` built on immutable PR #54 RESET head `9b8b871a10a506925963161dc86a8e14bc3d5a66`.
- Read-only, bounded big-endian image-zero exception-vector scan of entries 2..255,
  with per-entry memory/function lookup and explicit unreadable, odd, erased,
  null, unmapped and recognized-function classes.
- The report **does not establish VBR at runtime**, actual exceptions, IRQ
  enablement, device-specific interrupt assignments or executed ISRs.
- CI: standalone negative Java tests and complete Ghidra 12.1.4 extension build.
  A green workflow is not a substitute for isolated actual-Ghidra acceptance.
- No changes to PR #54 pinned artifact, Review/Apply, source firmware, OAuth or
  original Ghidra projects. New Supervisor test plan only after immutable CI ZIP.


## 2026-10-29 — GA-11 interior vector pointer discrimination

- Independent GA-11 follow-up `fix/ga11-vector-function-entry-evidence-20261029`
  based on immutable PR #57 SHA `99a4deb4868563ca5a12528d92e3b0540c5da5ce`.
- A vector landing in a recognized Ghidra function *body* is reported
  separately from a vector pointing exactly to that function's entry
  point; neither proves dynamic ISR execution or active VBR.
- Invalid/missing entry metadata and candidate slot arithmetic overflow
  must not be promoted to a valid handler. Synthetic negative tests,
  Ghidra 12.1.4 full extension CI and actual host acceptance remain gates.
