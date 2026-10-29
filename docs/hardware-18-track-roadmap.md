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
| GA-01 | A | Reset vector / entry evidence and reachable initialization flow | PARTIAL INTEGRATED: image-zero RESET candidate, bounded direct-call graph and statically recognized function set; no dynamic path proof | Validate vector bytes / entry, distinguish reachable/candidate/unknown |
| GA-02 | B | Path-conditional SIMCR/MM (write-once), TRAMBAR, CSBAR/CSOR/CSPAR and VBR epochs | PARTIAL INTEGRATED: per-function SIMCR/MM, TRAMBAR, CSBAR/CSOR alternative words and unknown writes; no first-executed write or latched MM proof | Branch/alias/call uncertainty preserved, addresses and source paths |
| GA-03 | C | Indirect MMIO via A/D registers, indexed modes, P-code LOAD/STORE, aliases | PARTIAL INTEGRATED: conditional CSBOOT–CS10 table and source-local CS register alternatives; no physical bus map | Synthetic alias joins, call barriers, no invented constants |
| GA-04 | D | Per-select CSBOOT, CS0..CS10 table in Analyze | PARTIAL: decoder/windows exist; Markdown currently uses per-window bullets | 12 separate rows, start/end/size, missing values UNKNOWN, model scope |
| GA-05 | E | Safe CPU32-unknown vs model-specific Review/Apply | PARTIAL: MC68332 full catalog; unknown-mode review constrained | No model-inherited unsafe maps; collision/transaction/Undo tests |
| GA-06 | F | Extendible sourced MC683xx profiles and conflict matching | PARTIAL INTEGRATED: profile citation audit, strict preview-only external manifest and optional local PDF checksum; no verified MCU import | Explicit model/version/page/bitfields/reset source; SVD/RDL feasibility |
| GA-07 | G | Compact 3-part Analyze: initiation, register history, CS map | PARTIAL INTEGRATED: three-part Overview, full evidence tab and complete export/RAG evidence | UI/Markdown/RAG agreement, concise report, evidence links |
| GA-08 | H | Function, pointer and variable naming proposals | PARTIAL INTEGRATED: function naming review and source-only A-register role hints; no local-variable rename | Collision-safe preview, manual labels preserved, transactional Undo |
| GA-09 | 13.1 | MMIO accesses explorer with navigation | PARTIAL INTEGRATED: searchable read-only MMIO explorer with Go To Listing; host GUI verification pending | Filterable function/instruction/value/access/confidence with Go To |
| GA-10 | 13.2 | Verified bitfield decode with provenance | PARTIAL INTEGRATED: sourced SIMCR bitfield values from literal full-word writes only; other bits UNKNOWN | Unknown fields UNKNOWN; model- and edition-specific source |
| GA-11 | 13.3 | Interrupt / exception analysis including VBR and ISR paths | PARTIAL INTEGRATED: reset-based vector candidate inventory; actual VBR/ISR execution UNKNOWN | Static candidates not treated as active IRQs |
| GA-12 | 13.4 | Resumable, version-aware incremental analysis | PARTIAL INTEGRATED: revision-aware invalidation, cancelable Analyze and in-memory complete CFG-stage checkpoint | Program identity, input hash, invalidation and resume regressions |
| GA-13 | 13.5 | Human/analysis/AI origin of changes | PARTIAL INTEGRATED: read-only SourceType audit and local CSV; human/AI authorship UNKNOWN | Check actual Ghidra 12.1.4 SourceType API; retain rationale and Undo |
| GA-14 | 13.6 | Firmware configuration comparison | DEFERRED by source priorities | Assess Ghidra Version Tracking first; later CS/VBR/peripheral diff |
| GA-15 | 13.7 | Agentic planning, indirect calls, context, pagination, stale cache | PARTIAL: draft PR #49/#50 overlap and existing Agentic work | Don't duplicate existing tools; budget/policy evidence regression |
| GA-16 | 15 | Physical PDF page/printed label, register tables, sourced RAG | PARTIAL INTEGRATED: physical PDF-page and candidate printed folio sequence status; actual PDF source page remains authoritative | No auto-promotion of ambiguous PDF rows; page/edition evidence |
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


## 2026-10-29 — GA-12 revision-aware read-only evidence (partial)

- New independent draft: `feature/hardware-versioned-analysis-cache-20261029`
  based on immutable PR #53 head `bd0a0a60eaa610e19581bd67fd16d29c637bfb8e`.
- Ghidra 12.1.4 `DomainObject.getModificationNumber()` changes on program
  edits, Undo and Redo; exact active Program object, language, original-import
  SHA-256 metadata, MCU profile selection and analyzer schema are part of
  the current scan's version check. Original SHA is *not* a live byte hash.
- Discard results if the source changes during asynchronous Analyze;
  do not publish stale RAG evidence. Invalidate cached hardware context on
  program edit/Undo/Redo, and refuse stale export/navigation/Review/Apply.
- When Analyze is repeated on an identical completed in-memory revision,
  reuse existing results without re-running the scan. This is a limited
  incremental optimization, **not** disk-backed resume or partially resumed
  CFG analysis. Those remain GA-12 TODO.
- CI: strict revision pure-Java regression plus complete 12.1.4 extension
  build; separate approved Supervisor real-Ghidra test required before merge.


## 2026-10-29 — GA-12 completed CFG stage resume and cancellation

- Draft branch `feature/hardware-resumable-cfg-stage-20261029`
  builds on immutable PR #60 head `a0dd587b8f60d47afdbf1a9725b6e0039dc87456`.
- A completed conservative CFG/P-code stage is cached first, keyed by exact
  Ghidra Program weak identity, analyzer schema, revision/Undo counter,
  language, original-import SHA-256 metadata and selected MCU profile.
- A later cancelled read-only inventory scan leaves the **completed** CFG
  stage available for same-revision retry. No half-processed function is
  interpreted as completed. A changed program/profile never reuses it.
- Analyze now supplies a real cancellable Ghidra TaskMonitorAdapter and
  Cancel Analyze button. Cancel never publishes partial RAG/Markdown/Apply
  evidence. Computed/reused checkpoint is labeled in completed report.
- This is **process-local completed-stage reuse**, not persistent disk
  checkpoints, interrupted-function continuation or cross-session resume.
- Gate: exact Ghidra 12.1.4 extension build and standalone negative stage
  tests, then local isolated Ghidra cancellation+Undo tests before merge.


## 2026-10-29 — integrated release candidate PR #67

- Branch `integration/hardware-tracks-20261029` is built on immutable
  PR #64 (and PR #60) and reconciles sibling PR #54–#66 functionality.
  It is a **draft integration candidate**, not a merge to `master`.
- Dedicated read-only RESET graph produces a set of recognized candidate
  direct-call functions, with recursion, unknown target and traversal caps
  preserved. The same immutable evidence is used for GA-01/02/03
  per-function write alternatives.
- Separate candidate word values for SIMCR/MM, TRAMBAR, CSBAR/CSOR/CSPAR
  are not interpreted as temporal register epochs. Chip Select state
  across functions or branch alternatives remains UNKNOWN.
- Compiles the full extension for Ghidra 12.1.4 and runs standalone
  adversarial tests. A green CI run is **not** local firmware acceptance.
  Prepare an *integration-specific*, artifact/SHA-pinned Supervisor plan
  after successful final-head CI; retain all old plans without automatic
  approval. Do not merge before real host integration verification.


## 2026-10-29 — GA-02/03 CFG-derived MMIO store evidence (#68)

- Independent dependent draft `feature/hardware-cfg-mmio-evidence-20261029`
  based on exact integration PR #67 SHA `85352509cd2de2e2dcc452eaf93c9ad49bedd0be`.
- A new source-only CFG/P-code report classifies resolved direct vs indirect
  register stores, full 16-bit literals, byte/long/unknown writes, and
  unknown-destination pointer aliases. It is separate from the direct
  Listing/XREF history to avoid double-counting as real execution.
- SIMCR write sites retain a saturated predecessor candidate range
  (0/1/2+) from within the modeled **same-function** CFG.
  Unknown calls, alias stores or control-flow limits force UNKNOWN,
  regardless of source-PC ordering or MM literal value. MC68332 MM bit
  is never declared a latched hardware configuration.
- New deterministic adversarial regressions and a full Ghidra 12.1.4 build
  required. No Review/Apply or Ghidra project modifications introduced.


## 2026-10-29 — GA-01/02/03 bounded within-function path possibilities

- Stacked draft `feature/hardware-cfg-store-path-relations-20261029`
  is based on exact PR #68 head `5b343d6da75f59785e1d3107dc42789a77be2565`.
- Read-only CFG pairwise path-existence between source sites for SIMCR,
  TRAMBAR, CSBAR/CSOR/CSPAR, bounded to 12 candidate writes per
  function and 1500 graph nodes per reachability query. The possible
  relations are A→B, B→A, both directions via cycles, no *modeled*
  connecting path, or UNKNOWN when budget is exceeded.
- Explicitly does **not** claim actual execution, feasible branch
  conditions or a unique chronological order after RESET.
- Generic CPU32 now suppresses concrete MC68332 register labels
  in the new CFG provenance table (addresses stay visible as hypotheses).
- Dedicated synthetic regression, full Ghidra 12.1.4 extension build
  and explicit host integration acceptance remain mandatory.


## 2026-10-29 — GA-01/02/03 read-only source-evidence CSV (stacked)

- `feature/hardware-initialization-evidence-csv-20261029` based on
  immutable PR #69 head `839767b3b688d3875a5f7a5481935269b95f1291`.
- Ghidra Hardware Analysis adds `Evidence CSV...`: separate,
  stable-schema, source-only STORE and CFG_PATH receipts, each
  `NEVER_AUTO_APPLY`. No accidental re-use as naming proposals.
- Export requires the identical current program revision and selected
  profile; profiles/edits invalidate old evidence. CSV injection guarded;
  file capped at 5000 records with omitted-row marker.
- Standalone schema regression + full Ghidra 12.1.4 build required.
  Real GUI and Undo/Redo acceptance remain pending Supervisor approval.


## 2026-10-29 — GA-01/02/03 unified source-site reconciliation (PR #72 candidate)

- Stacked branch `feature/hardware-unified-startup-evidence-20261029`
  based on immutable PR #71 head `bd206954ad9ca73f81804f836dd764e7729d3a6c`.
- Full-report startup alternatives now use a union of existing
  Listing/XREF candidates and CFG/P-code resolved direct/indirect stores,
  deduplicated by function+instruction PC+register-address.
- Each site carries independent LISTING/CFG origins; contradictory
  register identity, width, or literal degrades to UNKNOWN. Unknown
  destination aliases are counted as potential ANY-MMIO effects
  without inventing a specific register target. Byte/long/unknown
  writes never become confirmed 16-bit words.
- Generic CPU32 register labels in the new merged report stay
  UNVERIFIED_MCU_REGISTER. Source groups are still **static candidates
  only**, not execution events, proven reset epochs or physical CS maps.
- Deterministic synthetic conflicts/alias/duplicate tests and complete
  Ghidra 12.1.4 extension CI required before a pinned host plan; no
  changes to original program, RAG documents or user secrets.


## 2026-10-29 — GA-07 unified evidence summary without double-counting

- Three-part Overview remains compact, but section 2 now separately
  records unique function/PC/address source sites from both Listing/XREF
  and CFG/P-code, raw observations, deduplicated matches, conflicting
  candidate values and unknown-pointer aliases.
- Existing Listing count is deliberately not relabeled as runtime
  writes, and compiled CFG-only stores are not silently folded into
  historical Listing counts. No false execution or memory-map claims.
- Added pure Java summary/regression and full Ghidra build gate.

- Robustness follow-up: width=0 unmodeled P-code STORE now means
  UNKNOWN-width alias, rather than throwing an exception during a
  real Ghidra CFG pass. Synthetic regression covers this case.


## 2026-10-29 — GA-02/03 no lexical last-write-wins CS map

- The earlier per-function MM0/MM1 conditional CS table used a lexical
  address-ordered `Map.put` that could accidentally select the last
  source site even across branch alternatives.
- A standalone pure-Java source-consensus gate now includes a register
  only when **all observed candidate writes** have the same known
  full-word literal. Any different literal, partial-width or unknown
  write excludes the register and counts the conflict/unknown.
- The table remains a *conditional source sketch*, never a physical
  Chip Select configuration. Regression tests cover repeated agreeing
  literals, conflicting SIMCR values, unknown CSOR writes and
  reference-only sites. Full Ghidra 12.1.4 build gate remains.


## 2026-10-29 — GA-05 guarded CSBAR Review/Apply proposals

- Dependent branch `feature/hardware-csbar-review-gate-20261029`
  starts from immutable PR #72 head `f18904bd28fa7ff746b0ae7b5083671203f895e8`.
- Previously the Review/Apply CSBAR window source accepted every
  individual literal in the inventory, including MM0-addressed sites
  and contradictory assignments in alternative branches/functions.
- A conservative read-only gate now recognizes only exact MC68332 MM1
  source addresses for CSBARBT and CSBAR0..CSBAR10, requires a known
  full-word literal, and excludes a register entirely if any matched
  MM1 source disagrees or has an unknown write. Repeated agreeing
  sources result in one candidate, never a runtime event.
- The existing explicit user Review, Ghidra preflight, transaction and
  Undo semantics remain untouched. No automatic Apply is enabled,
  no reset-state or external CS activation is asserted.
- CI: pure Java negative safety tests and full Ghidra 12.1.4 build;
  local isolated GUI acceptance remains required before merge.


- GA-05 safety follow-up: absent `CS_WINDOW_*` proposals now
  receive `MANUAL_REVIEW` and `selectedByDefault=false`, not
  `READY` and automatically selected. Explicit operator selection
  and final confirmation are still necessary; existing preflight
  and Undo support are retained.


## 2026-10-29 — GA-05 Review proposals now consume unified CFG+Listing safety

- Stacked draft from PR #73 (immutable SHA `7b008b63c54c326023179b341e3d8d822736d868`).
- Read-only `HardwareCsbarUnifiedReview` consumes deduplicated Ghidra
  Listing + CFG/P-code candidate stores, rather than the historical
  Listing-only collection. Conflicting words, byte/long/unknown-width
  writes or unknown call/path hazards poison the affected register.
- An unresolved P-code pointer alias to an UNKNOWN destination may
  address any CSBAR; **all CSBAR memory-window proposals are suppressed**
  until a clean scan without such aliases. Generic CPU32 emits none.
  This may reject safe possibilities but never fabricates hardware state.
- The filtered immutable result is captured with the completed, versioned
  Analyze snapshot and is the only source used by Review/Apply.
  The source-gate status is visible in the Review dialog. Existing manual
  CS_WINDOW default and Ghidra Undo remain unchanged.
- Full Ghidra 12.1.4 build and synthetic safety checks required;
  real isolated host GUI acceptance remains pending.
