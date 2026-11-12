Warning: truncated output (original token count: 74304)
Total output lines: 4986

## GA-12/18 — 2026-11-12: integrated read-only live rebind of source-pair checkpoints

PR [#319](https://github.com/bogkom/GhidrAssist/pull/319) was squash-merged
at `f6e738bf7cad617ddf4b4e8bc562f93b884a484c` from exact candidate
`bb6a6c4bdb60f3d37ec5f7e98c33f85407b5d800`. Its `source-pairs-resume-check`
preflight authenticates a saved static JSR/MOVEC source-pair inventory,
re-reads every row through the current isolated CodeBrowser RPC, checks the
coverage counters and immutable generation through a terminal page, and
rejects mismatched or non-read-only evidence. It grants no execution, AI
resume, Apply or tool authority. Exact-head GitHub Actions passed **10/10**,
including the Java 25 Ghidra 12.1.4 PUBLIC build and real CodeBrowser
JSON-RPC/CLI acceptance; the source-pair Python regression passed **21/21**.
This is live evidence rebind only; GA-12/18 remain PARTIAL and cross-function
analysis provenance is still an independent requirement.

## GA-02/03/18 — 2026-11-12: public one-hop CALL source coordinate gate PASS

PR [#320](https://github.com/bogkom/GhidrAssist/pull/320) was squash-merged
as `64a6d303b1719fdee368bf228918c3121510f805` from exact tested candidate
`282f7a60a85e75fb1b9b45469767ffd615712254`. The candidate passed **56/56
exact-head GitHub Actions**; the merge commit passed **16/16** Actions. Public one-hop CALL
context, callee CFG, candidate and summary records reject odd/out-of-range
MC68332 source coordinates, malformed CFG PCs and contradictory candidate
or counter shapes. The live service omits invalid/out-of-scope CALL sites as
explicit incomplete coverage instead of aborting Analyze and validates
decoded callee successors before construction. Java 21 one-hop/two-hop
regressions, the Java 25 Ghidra 12.1.4 PUBLIC build, and genuine isolated
synthetic Ghidra workflows passed on the exact candidate. This prevents
forged typed source claims; it does not prove CALL execution, path
feasibility, MM latch, active ISR/VBR or physical bus mapping.
GA-02/03/18 remain PARTIAL.

## GA-02/03/18 — candidate 2026-11-12: fail-closed typed two-hop CALL evidence

The public two-hop `Bridge`, `Candidate` and `Summary` records now reject
odd or out-of-range MC68332 PCs, invalid nested-CALL/STORE coordinates,
malformed CFG successors, impossible MMIO addresses and contradictory row
omission counters at construction. Adversarial Java 21 regressions exercise
those boundaries while retaining valid two-hop source candidates. This
protects the typed boundary only; it does not prove CALL execution, branch
feasibility, MM latch, active ISR/VBR or physical bus mapping. Exact-head
Java 21 regressions, full Java 25 Ghidra 12.1.4 PUBLIC build and real
synthetic Ghidra Actions remain required before integration. GA-02/03/18
remain PARTIAL.

## GA-01/11/18 — 2026-11-12: public RESET Vector eligibility fail-closed (pending exact-SHA CI)

The public sourceResetPcEligible gate now independently validates unsigned
32-bit source vector words, non-null/non-erased aligned RESET PC and the
selected-MC68332 24-bit scope, even for caller-created Vector(valid=true).
A caller-supplied valid flag cannot promote a forged malformed PC to a
recognized RESET candidate. Generic CPU32 continues to accept legitimate
wide aligned source PCs. Adversarial Java21 regressions cover forged PC/SP
values and the generic-versus-selected-device distinction. Full Java25
Ghidra 12.1.4 PUBLIC build and real isolated synthetic headless CI on the
exact PR SHA remain required. This is source eligibility, not proof of
executed RESET, MM latch, active ISR/VBR or physical mapping.
GA-01/11/18 remain PARTIAL; GA-14 deferred.

## GA-01/02/11/18 — 2026-11-12: RESET publication identity binding (pending exact-SHA CI)

The read-only RESET Summary Markdown publisher now rejects source-report
coordinates outside aligned CPU32 bounds, recognized graphs attributed to a
different vector/function entry, and evidence chains that do not start at the
published root. Missing roots remain explicitly UNKNOWN rather than acquiring
a guessed CALL graph. Five adversarial source regressions cover forged
publication coordinates and a positive exact-root witness. This guards
report attribution, not source authentication or executed RESET; static
CALL reachability does not prove executed MMIO, MM latch or active VBR/ISR.
Java21 source tests, complete Java25/Ghidra 12.1.4 PUBLIC extension build,
and genuine isolated synthetic Ghidra CI must PASS at the exact head SHA
before integration. GA-01/02/11/18 remain PARTIAL; GA-14 deferred.

## GA-01/02/11/18 — 2026-11-11: RESET public summary root coherence (pending CI)

The read-only RESET static source Summary constructor now rejects recognized
roots with no inspected function, missing-root reports without UNKNOWN,
witness paths longer than the inspected-function count, and multiple
incompatible source roots in one published inventory. Source graph traversal
and Review/Apply remain unchanged. Java21 adversarial source regressions,
full Java25 Ghidra 12.1.4 PUBLIC build and genuine synthetic headless CI
must pass at the exact PR SHA before integration. This is source-report
consistency, not proof of executed RESET, latched MM, active ISR/VBR or
physical bus mapping. GA-01/02/11/18 remain PARTIAL.

## GA-07/13/18 — 2026-11-11: imported CSV formula provenance

The read-only evidence CSV merger now rejects unescaped spreadsheet formula
prefixes in every decoded imported source cell, including Unicode Cf,
whitespace and leading TAB. CSV quoting is not a formula defense. The
existing serializer's apostrophe-prefixed cells remain accepted. Java21
adversarial regression fixtures are added; full Ghidra 12.1.4 PUBLIC/Java25
and real synthetic CI on exact SHA are mandatory before merge. This is not
Apply authorization or evidence of MCU execution.

## GA-07/13/18 — 2026-11-11: fail-closed source CSV record provenance

The read-only evidence CSV merger now rejects syntactically valid
14-column imported rows that impersonate MERGED_SITE, unbound-alias or
omitted-merged views, unknown record types, repeated/early omission markers,
and source STORE rows after CFG_PATH. Only canonical STORE*, CFG_PATH*,
optional terminal OMITTED_ROWS source ordering is accepted. The merged
report still cannot authorize Review/Apply, and this check is a schema
provenance gate, not a proof of hardware execution or source truth.
Java21 adversarial regressions and full Ghidra 12.1.4 PUBLIC/Java25
CI are required on the exact commit. GA-07/13/18 remain PARTIAL.

## GA-07/13 — 2026-11-11: total CSV row budget includes omission markers (pending CI)

The unified read-only hardware evidence CSV now reserves room for
OMITTED_MERGED_SITES whenever merged detail and unknown-alias summary
would exceed the 5000-row total cap. A source CSV already occupying all
5000 rows fails closed if new merged evidence cannot be represented with
an omission marker. The standalone serializer likewise reserves a row
for OMITTED_ROWS, preventing a 5001st record. Deterministic boundary
regressions check both paths. This is bounded export metadata only;
no hardware execution, physical map or Review/Apply is inferred.
GA-07/13 remain PARTIAL pending exact-SHA Java21, full Java25 Ghidra
12.1.4 PUBLIC build and real synthetic CI verification.

## GA-07/13 — 2026-11-11: bounded decoded upstream CSV cells (pending exact-SHA CI)

The unified read-only hardware evidence CSV parser now bounds each decoded
quoted cell to 513 UTF-16 units (512 serialized source units plus at most
one spreadsheet-formula escape apostrophe), including doubled quotes.
Previously a syntactically valid 14-column forged source row could carry
an arbitrarily large quoted cell even though the serializer clipped
individual source fields. Deterministic negative regressions cover both
plain and quote-escaped oversized cells while preserving existing source
row and 5000-row checks. This is an interchange-boundary refusal only:
no firmware execution, physical MMIO mapping or Review/Apply authority
is inferred. GA-07/13 remain PARTIAL until all roadmap acceptance criteria
are satisfied. Full Ghidra 12.1.4 PUBLIC/Java25 build and source-only
Java21 CI are required on the final PR SHA; no local Wyse/Precision tests.

## GA-02/03/18 — 2026-11-10: canonical signed MOVEQ post-return source constants

Previously, verified input-independent CPU32 CALL return registers only
accepted 6-byte MOVE.L/MOVEA.L immediate definitions. The strict
straight-line `RTS` and path-complete acyclic conditional-branch leaf
solvers now additionally accept 2-byte `MOVEQ #signed8,Dn` (D0–D7),
with exact 8-to-32-bit sign extension and no A-register shortcut. The
real Ghidra decoder admits valid four-byte `MOVEQ;RTS` functions while
rejecting wrong instruction lengths, RTE, non-canonical immediate data,
unmodeled register effects, nested calls and branch disagreement.
Java21 source tests and genuine isolated Ghidra 12.1.4 PUBLIC/Java25
headless `leaf-return` + `moveq-return` modes test source-only
candidate word `0xFF80` without claiming executed CALLs, MM latch,
physical mapping or Review/Apply. All GA-02/03/18 remain PARTIAL;
GA-14 deferred.

## GA-02/03/18 — 2026-11-10: source-only two-hop conditional-branch CFG coherence

The selected MC68332 outer CALL → intermediate single JSR/BSR → direct
leaf MMIO source pipeline now refuses fake bridge control flow even
when all supplied steps form a closed acyclic graph. Conditional Bcc
must have two distinct successors, unconditional BRA exactly one,
linear A/D instructions and NOP exactly one, RTS none and only
a real JSR/BSR can introduce the inner CALL barrier. Decoded source
coordinates are aligned MCU24, recursive/out-of-range cases are
rejected as incomplete rather than returning guessed evidence or
crashing the Ghidra report. Source regressions include forged CFGs,
missing fallthrough, hidden P-code register effects and a positive
convergent branch producing consistent source candidate words.
Independent Java21, Java25 Ghidra 12.1.4 PUBLIC extension build and
real isolated synthetic headless CI remain exact-SHA gates. This does
not prove branch feasibility, code execution, latched SIMCR/MM or
Review/Apply eligibility. GA-02/03/18 PARTIAL; GA-14 deferred.

## GA-06/18 — 2026-11-10: untrusted external profile Preview/Comparison constructor safety

The tab-delimited external MCU manifest parser is read-only and the
selected MC68332 device still requires explicit selection. Its public
Source/Module/Register/Field/Preview records now independently enforce the
same structured document, 4 KiB module aperture, aligned register ownership,
non-overlapping names/ranges/masks, row bounds and exact ambiguous-page
counts as parsing, so a direct Java record cannot falsely claim it passed
structural verification. The read-only cross-manifest Report bounds
source-difference evidence, detects duplicate/kind-mismatched findings and
reconciles retained plus omitted rows. It does **not** prove PDF bytes,
claimed SHA, physical bus map, real MCU identity or silicon differences.
Java21 adversarial source-only checks, Java25 full Ghidra 12.1.4 PUBLIC
build and synthetic CI on exact SHA required. GA-06/18 PARTIAL; GA-14
deferred. No importer, automatic Apply, host/Supervisor/firmware actions.

## GA-06/10/16/18 — 2026-11-10: exact publisher field-source report coherence

Read-only MC68332 source reports for (1) 15 SIMCR/SYNCR physical-page
**name tokens**, (2) 15 independently reviewed diagram bit positions
and (3) ten SYPCR/PICR/PITR excerpt citations now validate their
**public** Row/Report constructors. Selected-device metadata and
canonical reviewed identities/order are fixed; positive rows require
their exact in-range folio/mask/state and counters; SYPCR/PICR/PITR
positive excerpts must hash to their own bounded text rather than
accepting an arbitrary well-formed digest. Generic CPU32 never acquires
MC68332 publisher identity. Java21 adversarial regressions, independently
SHA-256-pinned 265-page publisher PDF extraction, full Ghidra 12.1.4
PUBLIC/Java25 build and synthetic headless CI are required at exact SHA.
Source text is untrusted without the separate publisher-byte job,
and this report consistency never proves instruction execution, MM,
VBR/ISR, physical bus mapping or Review/Apply authorization.
GA-06/10/16/18 PARTIAL; GA-14 deferred.

## GA-01/02/03/11/12/18 — 2026-11-10: typed RESET/indirect-JSR/MOVEC report coherence

The read-only selected-MC68332 same-function indirect JSR / SIMCR-MM
MAY / MOVEC-to-VBR publication now fail-closes its **public Pair and Result
constructors**, not only the source inventory builder. All displayed
function, JSR PC, computed target and MOVEC PC identifiers must be even,
bounded MCU24 source coordinates, and a JSR cannot share its decoded PC
with MOVEC. Public Result pages require exact inventory-product counts,
complete bounded offset/limit windows, exact cursor/has-more and omission
accounting, canonical nonduplicate source order, consistent same-PC
target/MM and MOVEC/base witnesses, disjoint JSR/MOVEC instruction sets,
and one RESET relation/incompleteness claim per function. Canonical pages
created by the actual static source solver are unchanged. Source-only
adversarial Java21 regressions, full Java25 Ghidra 12.1.4 PUBLIC build
and genuine isolated synthetic headless CI are required at exact commit.
This prevents forged/contradictory **public report claims**, but is not
source authentication, RESET instruction execution, latched SIMCR MM,
an active VBR/ISR or physical bus mapping. GA-01/02/03/11/12/18 PARTIAL;
GA-14 deferred.

## GA-08/12/13/18 — 2026-11-10: durable pointer datatype and first-use receipt v2

The previously live-checked Function-DB pointer DataType path/length and
first-use offset now persist inside the same native undoable rename
transaction as `GA13-POINTER-VARIABLE-2`. Cross-JVM read-only audit checks
both against the current Ghidra Program and labels mismatches
`TYPE_IDENTITY_CHANGED`. Existing `GA13-POINTER-VARIABLE-1` receipts
remain canonically readable but `LEGACY_TYPE_UNVERIFIED`, never silently
promoted to typed current approval. Audit CSV appends reviewed/current type
and first-use columns. This is a consistency/Undo safeguard, not
authentication or unattended Apply permission. Java21 source regressions,
full Java25 extension build and genuine isolated Ghidra 12.1.4 PUBLIC
headless tests are exact-SHA integration gates. GA-08/12/13/18 PARTIAL,
GA-14 deferred.

## GA-08/12/13/18 — 2026-11-10: exact live scoped-pointer datatype/first-use Review identity

The existing Ghidra Function-DB scoped pointer parameter/local Review now
captures the exact Ghidra datatype path/size and function-relative first-use
offset in addition to function entry, variable kind/ordinal/storage/name,
pointer flag and ABI auto/forced status. A changed pointee type or first-use
scope cannot be re-used as an old Apply proposal even if both remain pointers
at the same stack/register location. Historical 8-field source-only
observations remain inspectable but are explicitly **not** complete live
Apply identities; batch Apply rejects them before the native transaction.
The native all-or-nothing Apply rechecks typed provenance after each rename.
A real Ghidra 12.1.4 synthetic fixture rejects a forged type-only proposal
in a two-variable batch without a partial edit or receipt, then verifies
fresh Apply/Undo/Redo. The GA13-POINTER-VARIABLE-1 durable receipt schema
remains backward-compatible; it does *not* persist pointee datatype identity,
which remains an explicit separate cross-JVM audit improvement. Deterministic
Java21 source tests and complete Java25 extension/integration CI on exact
SHA remain mandatory. GA-08/12/13/18 PARTIAL; GA-14 deferred.

## GA-08/12/13/18 — 2026-11-10: typed scoped-pointer receipt and redo audit

The **existing** real Ghidra Function-DB pointer parameter/local Review→Apply→Undo
implementation (`HardwareScopedVariableService`) remains the only supported
mutation path. Its public GA-13 receipt audit now independently recomputes
each CURRENT_APPROVED_NAME state using exact saved option-key/function
identity, storage, import-source SHA-256 syntax, observed pointer data type,
USER_DEFINED SourceType and absence of ABI auto/forced parameter semantics.
Mixed, duplicate, reordered and direct caller-forged state inventories fail
closed; a generic CPU32 revision cannot certify MC68332 CSV. The native Apply
transaction re-resolves the pointer variable after setName and rolls back
the *entire* batch if the name, storage, type, SourceType or ABI status differs.
Receipt schema remains GA13-POINTER-VARIABLE-1 and native Undo/Redo preserves
its transactional association. Real isolated synthetic Ghidra exercises
Approve/Apply→Undo→Redo, plus deterministic Java21 negative source-policy
checks and complete Java25/Ghidra 12.1.4 PUBLIC CI. This does not infer
HighVariable identity from A-register activity, authenticate a person or
executable bytes, or authorize unattended pointer naming. GA-08/12/13/18
PARTIAL; GA-14 deferred.

## GA-08/12/13/18 — 2026-11-10: public persisted rename receipt state revalidation

Read-only saved function-rename audit snapshots now recompute every public
approval state from the actual saved GA-13 receipt, live function name,
current SourceType and full executable import identity. Callers cannot
construct forged `CURRENT_APPROVED_NAME` rows after a Program edit, source
change or `USER_DEFINED` classification loss. Public inventories require
strict function address order and no duplicates or missing rows. Generic
CPU32 revisions may not certify the selected MC68332 rename report in the
CSV fence; old unknown-source receipts remain inspectable as
`SOURCE_UNVERIFIED`. These are consistency checks, not an append-only Undo
log, author authentication or a new Apply permission. Deterministic Java21
regressions, full Java25/Ghidra 12.1.4 PUBLIC integration and real isolated
synthetic Ghidra Actions remain exact-HEAD gates. GA-08/12/13/18 PARTIAL;
GA-14 deferred.

## GA-08/12/13/18 — 2026-11-10: conflicting static write-site witnesses

The function naming proposal engine refuses to mark a role as REVIEW_REQUIRED
when the same static instruction PC in one function is claimed to write two
different hardware registers in a single source snapshot. This complements
existing function-name disagreement and Ghidra revision/transaction preflight:
no contradictory proposal can enter the explicit function-name Apply path.
The A-register role explorer likewise downgrades conflicting PC/register,
module/target or function-name observations to PATH_UNCERTAIN, with no
persistent variable/pointer rename (read-only evidence only). Exact duplicate
site witnesses remain deduplicated and a bounded 120,000-site limit prevents
unbounded grouping. Java21 synthetic adversarial self-tests, full Java25
Ghidra 12.1.4 PUBLIC extension build and isolated true synthetic Ghidra CI
are mandatory exact-SHA gates. Static PCs do not prove instruction execution
or runtime register lifetime. GA-08/12/13/18 PARTIAL; GA-14 deferred.

## GA-12/13/15/18 — 2026-11-10: historical Agentic row-source completeness

Historical Agentic checkpoints can no longer claim `complete=true` after
rehashing if a retained finding lacks a nonblank fact, source observation
or tool of origin. Live CLI capture independently downgrades successful-but-
uncited findings to INCOMPLETE; old archives with complete=false remain
read-only inspectable. Java same-Program Review drafts and cross-JVM
historical Review import enforce matching source attribution for every
retained row. These are integrity and Review-readiness checks, not source
authentication or resumable LLM sessions; Program fingerprint and new
Review/Apply authorization gates remain separate. Java/Python regressions,
full Ghidra 12.1.4 PUBLIC Java25 build and isolated synthetic CI are exact-
SHA merge requirements. GA-12/13/15/18 PARTIAL; GA-14 deferred.

## GA-12/13/15/18 — 2026-11-10: checkpoint source and export loss accounting

In-memory completed-function GA-12 checkpoint reuse now requires a nonblank,
non-`UNKNOWN` import identity and rejects forged control/format characters
in bounded source/language metadata. Weak source identity yields a cache miss,
not a successful fixed-point resume; an existing valid checkpoint is not
invalidated by such a failed query. The stronger on-disk full-input SHA-256
and Program binding remain independent authorization gates. GA-13 read-only
provenance CSV now emits explicit `TRUNCATED_SOURCE_ROWS` receipt whenever
any retained row lost source cell bytes, separately from `OMITTED_ROWS` after
the row count cap. Neither receipt grants Apply/Undo authority. Java21
negative regressions, full Java25/Ghidra 12.1.4 PUBLIC compile and genuine
isolated synthetic GitHub Actions are exact-SHA merge requirements.
GA-12/13/15/18 remain PARTIAL; GA-14 deferred.

## GA-06/15/16/18 — 2026-11-10: strict indexed PDF selected-result identity

The RAG PDF selected search result and reconstructed physical page must
both carry a full canonical index-time SHA-256, valid bounded path, and
bounded library identity without concealed control/format characters.
Equal-but-missing legacy metadata or a matching short placeholder digest
cannot allow a stale indexed source to be opened as a trustworthy match.
Cross-folio publisher citation groups use the same guard. This does not
substitute for independent current-file PDF-byte verification or manually
verified MC68332 edition/folio provenance. Java21 RAG regressions, Java25
full Ghidra 12.1.4 PUBLIC build and isolated synthetic CI are exact-SHA
gates; GA-06/15/16/18 remain PARTIAL, GA-14 deferred.
The GA-18 full extension build workflow now includes `src/main/java/ghidrassist/core/RAG*.java` and `src/test/java/ghidrassist/core/RAG*.java` in both push/PR filters; these RAG source changes previously triggered only narrower source tests and thus missed the mandatory full Ghidra compile. This is a CI coverage correction, not a host-runner/Supervisor restart.\n\n

## GA-06/10/15/16/18 — 2026-11-10: RAG source and Agentic completeness accounting

Reviewed MC68332UM field-excerpt public reports now bind every positive
candidate's SHA-256 to its actual bounded text, require the exact canonical
15-field list and count matching/omitted rows instead of trusting caller
supplied completeness counters. A generic CPU32 report may not inherit
MC68332 publisher field citations. Separately, the Agentic retained-findings
cache cannot certify a finished investigation as *complete* if any accepted
finding lacked its own evidence text or tool origin, even when that finding
was later pruned from the ranked cache. Clear begins a new evidence generation.
These are deterministic **source-claim consistency** gates; digest equality
is not independent PDF file authentication, and a sourced finding is not
proof of firmware execution. Java21 source tests, full Java25/Ghidra 12.1.4
PUBLIC build and isolated genuine synthetic CI are exact-SHA merge gates.
GA-06/10/15/16/18 remain PARTIAL; GA-14 deferred.

## GA-06/17/18 — 2026-11-10: bounded fail-closed source-profile structural audit

The standalone GA-06 profile metadata audit now rejects oversized raw
catalogs, names/modules with invalid identities, unaligned word/long
register sites and forged public citation coverage totals. All structural
findings, not only width/range collisions, make collisionFree() false;
missing PDF-page labels remain independently counted UNKNOWN and are
never reinterpreted as authenticated manual evidence. Deterministic
Java21 tests, full Java25/Ghidra 12.1.4 PUBLIC extension build and
real isolated synthetic CI are exact-SHA merge gates. No physical bus
mapping, MCU auto-identification, executed MMIO or production Apply is
inferred. GA-06/17/18 remain PARTIAL; GA-14 deferred.

## GA-06/10/16/18 — 2026-11-10: PDF folio and bitfield source-c…62304 tokens truncated…ed into
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

- GA-05/13 review hardening: the revision token now guards local
  provenance CSV export before/after file dialogs, and guards Apply
  again **after** the final modal user confirmation. Same-Program
  identity alone is insufficient after Ghidra Edit/Undo/Redo.


## 2026-10-29 — GA-12 bounded CFG evidence capture, conservative Review

- Stacked on PR #74 exact head `68b665aa142f198745a08c0d7293dbedd7f43574`.
- Read-only CFG MMIO and A-register pointer-role source collectors
  now retain at most 12,000 and 8,000 records respectively, with
  explicit exact counts of discarded source sites.
- If the CFG walk or its source collector is incomplete, the unified
  CSBAR Review gate deliberately exposes **no speculative external
  CS-window proposals**; a truncated collector is not proof that
  an unobserved pointer store cannot alias a CS register.
- Extremely large CFG functions (over 50,000 nodes) and duplicate
  same-PC P-code STORE sites are marked as unresolved for pairwise
  path comparison rather than crashing Analyze.
- Source-limited A-register role hints are downgraded to PATH_UNCERTAIN,
  and reports label all omitted candidate counts. No half-processed
  CFG stage is cached as successful, no Ghidra DB edits are performed.
- Synthetic budget+fail-closed tests, full Ghidra 12.1.4 compile
  and real isolated host acceptance are required.


## 2026-10-29 — GA-02 bounded function-local possible first SIMCR sources

- Stacked draft `feature/hardware-simcr-local-first-paths-20261029`
  is based on immutable PR #75 head `52fbb1ce1f79ff189ff0a28a07d54e8bd6a037ed`.
- For explicitly selected MC68332, each recognized function
  containing a P-code candidate SIMCR write is analyzed using bounded
  Ghidra CFG successors. The result lists *possible first source-PCs
  within that function*, including different literal words in
  alternative branches, unknown values, unknown pointer/call effects,
  CFG cycles, missing edges and work-budget truncation.
- The model **cannot prove a first write since MCU RESET**, runtime
  path feasibility, chip-select configuration or write-once MM latch.
  Generic CPU32 remains outside this MCU-specific display.
- Dedicated pure Java branch/loop/alias/unknown tests and complete
  Ghidra 12.1.4 extension CI; actual on-host Ghidra acceptance
  remains a separate Supervisor gate.

## 2026-10-29 — authoritative GA-18 operational update

- Standing owner authorization covering all standard GhidrAssist
  GA-01..GA-18 tests is **granted, deployed and active on Wyse**.
  Confirmed `codex-supervisor-auto` systemd timer launched the PR #54
  dedicated Codex **test-only** turn at 09:24:15 Europe/Warsaw.
- Private verified real-host Supervisor results exist for
  **PR #53** ([issue #8](https://github.com/bogkom/codex-supervisor/issues/8)),
  **PR #54** ([issue #14](https://github.com/bogkom/codex-supervisor/issues/14),
  PASSED 09:32:49 Warsaw), and **PR #55**
  ([issue #16](https://github.com/bogkom/codex-supervisor/issues/16),
  PASSED 09:51:09 Warsaw). Each result is pinned to its own exact
  historical commit and GitHub Actions artifact.
- Supervisor standing-policy PR #9 remains unmerged to private `main`,
  but its approved functionality was already installed and exercised
  on Wyse using an audited pinned stack based on Supervisor PR #13.
  **Do not call operational activation unconfirmed solely because
  these source PRs remain open.** The auto-reload subfeature has
  not separately been proven by the manual thread reload.
- Later stacked integration PRs #67–#76 still need their **own**
  exact-commit real-Ghidra tests and positive Supervisor reports.
  In particular, a PR #55 success does not verify later source
  combinations or permission for unreviewed production merges.

## GA-06/10 — candidate 2026-11-05: strict physical PDF page claim audit

The read-only profile coverage counter previously accepted any `PDF page`
substring, including invalid, reversed and non-contiguous numbers.
`HardwareProfileAudit.physicalPage` now uses the existing shared
`ManualPdfPageClaim.hasSingleConsistentClaim` to reject misleading
labels. This validates **claim syntax only**, not PDF bytes, editions,
register facts or physical hardware. Needs Java21 and full Ghidra
12.1.4 PUBLIC/Java25 PASS on exact PR SHA. No user firmware or projects.

## GA-08/13 — candidate 2026-11-05: bounded function naming CSV export

The read-only legacy function-role naming CSV now retains at most 5,000
candidate rows and emits an explicit seven-column omitted-row sentinel
(`OMITTED_ROWS`, `INCOMPLETE_EXPORT_NEVER_AUTO_APPLY`). Untrusted cells
remain formula-safe and bounded. No Review/Apply permission or actual
function name is changed; full Ghidra 12.1.4 PUBLIC/Java25 and Java21
regressions require a fresh PASS on the exact candidate SHA.

## GA-08/13 — kandydat 2026-11-05: sprzeczne nazwy funkcji

`HardwareFunctionNamingReview` wykrywa teraz obserwacje jednego adresu
funkcji z różnymi bieżącymi nazwami, a nie wybiera ostatniej nazwy
z kolejności źródeł. Taki przypadek ma `EVIDENCE_TOO_WEAK`, pustą
propozycję i znacznik `CONFLICTING_SOURCE_NAMES`. Nie modyfikuje
Review/Apply/Undo ani Program. Wymagany odrębny CI PASS Java21 i
pełnej Ghidry 12.1.4 PUBLIC / Java25 na dokładnym SHA.

## GA-02/03/11 — candidate 2026-11-05: separate transitive effect frontier

The generic `HardwareCallEffects` memory STORE/MOVEC inventory now bounds
**scheduled** function PCs (not just examined functions), with an explicit
`TRUNCATED/UNKNOWN` marker after a distinct-call budget overflow. This is
separate from the previously integrated GA-02/03 SIMCR callsite budget.
Deterministic Java21 fixtures cover 12,000 distinct and duplicate edges,
unknown targets, budget validation, and preserve existing shortest-path /
cycle semantics. Full Ghidra 12.1.4 PUBLIC/Java25 CI required on exact PR
SHA. Read-only source evidence, not runtime vector/RESET activation.

## GA-01/11 — candidate 2026-11-05: vector target memo / bounds

Repeated vector slots sharing an exact function handler now reuse its
read-only transitive CALL effect summary within one report. Each numbered
vector remains separately counted and correlated with RESET; no persisted
cache or execution claim is introduced. Fail closed on more than 254
vector candidates, overlarge graph/RESET subsets, null targets and
invalid RESET addresses. Requires Java21, full Ghidra 12.1.4 PUBLIC /
Java25 and synthetic headless CI on the exact new SHA.

## GA-12 — kandydat 2026-11-05: ograniczony strumieniowy odczyt checkpointu

Trwały magazyn etapów używa teraz `BasicFileAttributes` bez śledzenia
linków i otwarcia docelowego pliku przez `NOFOLLOW_LINKS`. Po sprawdzeniu
rozmiaru dodatkowy niezależny limit `MAX_FILE_BYTES+1` zapobiega
nieograniczonemu `readAllBytes`, gdy plik urośnie lub zostanie podmieniony
między stat a odczytem. Przekroczony limit to cache miss, nie dowód
przeciw analizie. Java21 regresja obejmuje nieskończony strumień,
podzielone odczyty, plik o rozmiarze ponad limit i stare testy symlinków.
Wymagany pełny build Ghidry 12.1.4 PUBLIC / Java25 na SHA PR.

## GA-13 — kandydat 2026-11-05: bezpieczne komórki CSV dowodów CFG

`HardwareConfigurationEvidenceCsv` dotychczas rozpoznawał formuły
arkusza tylko przy pierwszym znaku `=+-@` i bez limitu długości pola.
Kodowanie pojedynczych komórek ma teraz limit 512 znaków UTF-16,
znacznik `SOURCE_TRUNCATED`, ochronę par zastępczych oraz sprawdzanie
formuł ukrytych po Unicode Cf i białych znakach. Format 14 kolumn,
limity wierszy, ostrożność CPU32 i zakaz Apply pozostają bez zmian.
Wymagany pełny CI Java21 i Ghidra 12.1.4 PUBLIC/Java25 na SHA PR.

## GA-02/03 + GA-17/18 — kandydat 2026-11-05: priorytet CALL i kontrola krawędzi

W analizatorze `HardwareInterproceduralMmEffects` wspólny budżet
16 384 adresów był konsumowany przez wszystkie wywołania w kolejności
adresów, zanim dotarto do funkcji wybranych do raportu. Dwufazowa,
deterministyczna ocena priorytetyzuje `interestingCallers` także przy
limicie wyświetlanych wierszy, pozostawiając `LIMITED/UNKNOWN` dla
nieprzebadanych, pozostałych wywołań. Źródłowy graf ograniczono do
200 000 krawędzi CALL (oprócz wcześniejszego limitu węzłów).
Regresja Java21 obejmuje 16 384 zamkniętych obcych celów, wybrany
kandydat MM za nimi, permutację kolejności i 200 001 krawędzi.
Wymagane testy GitHub Actions / Ghidra 12.1.4 PUBLIC / Java25 na
dokładnym SHA. Nie jest to dowód wykonania ani aktywnego MM.

## GA-17/18 — kandydat 2026-11-05: kontrolowany bootstrap Gradle w Actions

Po próbach PR #159 stwierdzono niezależne błędy sieciowego pobierania
Gradle 9.7.1 (timeout 10 s / HTTP 504), **przed testami produktu**.
Pilotaż obejmuje trzy workflow: pełny build rozszerzenia, GA-18 pakiet A
i siedem testów bezpieczeństwa syntetycznej Ghidry. W izolowanym
`RUNNER_TEMP`, po weryfikacji SHA oryginalnego ZIP Ghidry 12.1.4
PUBLIC, helper sprawdza stały adres dystrybucji Gradle i zmienia
**wyłącznie tymczasowy** timeout na 120 s, dwa ponowienia i backoff.
Nie zmienia wersji Gradle ani binariów. Osobna regresja shellowa
sprawdza pin, idempotencję, odrzucenie symlinków i obcych ścieżek.
Pełny CI na dokładnym SHA jest wymagany; nie wznawiamy Supervisora.

## GA-17/18 + GA-02/03 — kandydat 2026-11-05: SHA Gradle i kolejne testy

Po przetestowanym i scalonym pilotażu #163, kontrolowany bootstrap
Gradle w Actions obejmuje cztery dodatkowe regresje rzeczywistej
syntetycznej Ghidry (CALL-argument, branch-convergent return, leaf
return, two-hop CALL). Dodatkowo wymaga sprawdzonego oficjalnego
`distributionSha256Sum` dla Gradle 9.7.1 -bin, odrzucając niezgodne
lub zdublowane sumy. Stała wersja Gradle, niezmienione archiwum Ghidry,
izolacja `RUNNER_TEMP` i wyłączony Supervisor. Wymagany dokładny
PASS GitHub Actions na SHA nowego PR.

## GA-02/03 — kandydat 2026-11-05: nieznana szerokość zapisu przez CALL

Jedno- i dwupoziomowy analizator kontekstowy odrzucał zapisy z
ustalonym adresem, ale **nieznaną szerokością** (0/64 bitów),
jeżeli adres początkowy nie należał bezpośrednio do indeksu MMIO.
Przy zapisie zaczynającym się tuż przed SIMCR taki wynik nie
wyklucza objęcia jego bajtu MM. Wyróżniamy teraz nieznany alias
STORE zamiast deklarować brak kandydatów; tylko szerokości 8/16/32
mogą otrzymać precyzyjny kandydat. Java21 obejmuje kontrolę
zapisu sąsiedniego 8/32-bit, dwóch poziomów CALL i brak
niesłusznego awansu nieznanej wartości do zatwierdzenia.
Wymagane dokładne SHA CI Ghidry 12.1.4 PUBLIC / Java25 oraz
rzeczywiste syntetyczne przypadki Ghidry. Brak dowodu wykonania.

## GA-01/02/03 + GA-17 — kandydat 2026-11-05: limit krawędzi lokalnego SIMCR

Graf możliwych pierwszych źródeł zapisu SIMCR miał limit liczby
węzłów (50 000), ale nie sumy następców CFG. Rozbudowany zbiór
zdublowanych krawędzi mógł niepotrzebnie obciążać analizę mimo
małego budżetu odwiedzin. `HardwareSimcrLocalFirst.inspect`
odrzuca teraz ponad 200 000 krawędzi przed DFS, bez raportu
sugerującego kompletną analizę. Java21 regresje obejmują
dokładny próg, przekroczenie progu w jednym i dwóch węzłach,
prawdziwy cykl oraz niezmienność dotychczasowych wyników.
Wymagane CI Ghidra 12.1.4 PUBLIC / Java25 na SHA PR;
wynik pozostaje statyczny i nie dowodzi pierwszego wykonania.

## GA-02/03/12 + GA-17 — kandydat 2026-11-05: limit krawędzi solvera CFG

Rdzeniowy `HardwareDataflow.analyzeSlice`, wykorzystywany przez
analizę pośrednich STORE, przekazywanie rejestrów w CALL oraz wznowienie
checkpointów, limitował iteracje, ale nie sumę wszystkich referencji
następców CFG. Zbyt wiele zdublowanych krawędzi mogło obciążyć
każdą iterację mimo małego budżetu. Silnik odrzuca teraz ponad
200 000 krawędzi zanim rozpocznie analizę zimną lub wznowioną.
Regresje Java21 obejmują próg, 200 001 krawędzi, łączny
próg z dwóch węzłów, odmowę wznowienia niezgodnego grafu
i niezmienność wcześniej zamkniętych dowodów.
Wymagany pełny PASS Ghidry 12.1.4 PUBLIC / Java25 na SHA PR.
Wynik jest statycznym MAY/UNKNOWN, bez uruchamiania firmware.

## GA-02/03 + GA-17/18 — candidate 2026-11-05: indexed MMIO po dwóch CALL

Istniejący test headless potwierdzał dwa CALL i zapis `(A1)`,
lecz nie indeks `(A1,D1.W)` dekodowany przez rzeczywistą Ghidrę.
Osobny syntetyczny tryb `two-hop-indexed` weryfikuje 24-bitowe
adresowanie i indeks D1.W=-1, dwa niezależne konteksty A0/D0/D1,
brak sztucznej wartości D1 w trzecim kontekście, niezmienność
projektu i zakaz awansu do Apply. Java21 testuje też
niezgodne wartości indeksu na zbieżnych ścieżkach. Wymagany
pełny build Ghidra 12.1.4 PUBLIC / Java25 i rzeczywisty
syntetyczny headless PASS na dokładnym SHA PR.

### 2026-11-05 — GA-02/03/18 CPU32 indeks: luka rzeczywistej składni

Nowa syntetyczna Ghidra ujawniła konkretny brak dekodera:
rzeczywisty operand `(0x1,A1,D1w*0x1)` nie pasował do
`D1.W*1`. Zmieniono wyłącznie ścisłą gramatykę indeksu,
akceptując oba warianty i skalowanie `0x1/2/4/8`.
Dodano osobny test Java21 parsera i rzeczywisty test indeksu
przekazywanego przez dwa CALL; konflikt D1 lub brak D1
pozostaje nieznanym aliasem, a nie potwierdzonym zapisem.
Wymagany pełny CI na dokładnym SHA i checkpoint.

### 2026-11-05 — GA-02/03/18 MOVEQ: rozpoznanie natychmiastowej stałej

Rzeczywista syntetyczna Ghidra 12.1.4 pokazała
`moveq -0x1,D1` bez prefiksu `#`; poprzedni dekoder
odrzucał wartość D1 jeszcze przed zewnętrznym JSR.
`HardwareRegisterOperand.isImmediateToken` uznaje
ściśle numeryczny argument bez `#` wyłącznie dla `MOVEQ`,
a kod Ghidry wymaga ponadto rzeczywistego `Scalar`.
Dodano niezależny test Java21 i ponowiono rzeczywisty
dwupoziomowy test indeksowanego MMIO. Inne instrukcje
oraz nieznane indeksy pozostają konserwatywne.

### GA-02/03 + GA-17/18 — 2026-11-05: granica szerokości indeksu MCU24

`HardwareIndexedAddress` dopuszczał przesunięcia >32 bity,
które maskowanie do 24-bitowej przestrzeni MCU mogło zamienić
w pozornie prawidłowy adres MMIO. Gramatyka odrzuca teraz
za długi operand (>128 znaków UTF-16) i przesunięcia spoza
przedziału `-0x80000000..0xFFFFFFFF`. Kontrola działa
również w publicznym konstruktorze indeksowanego
`HardwareDataflow.Step`, aby syntetyczny graf nie ominął
parsera. Regresje Java21 obejmują obie granice i odrzucanie
przepełnień, zachowując składnię Ghidry 12.1.4 PUBLIC.
Wymagane pełne CI oraz rzeczywista syntetyczna Ghidra na SHA PR;
to dowody źródłowe, nie fizyczna mapa magistrali ani aktywny MM.

### GA-02/03 + GA-17/18 — 2026-11-05: indeks skalowany i zawijanie MCU24

Po PR #168 i #169 rozszerzamy rzeczywistą syntetyczną
Ghidrę o osobny tryb `two-hop-indexed-wrap`. Dwa
wywołania przekazują A0=0, D0 i dodatnie wartości D1.L
z ujemnym dolnym słowem: indeks `D1.W` po sign extension
i skalowaniu *2 zawija 24-bitowy adres do SIMCR
`0xFFFA00` albo `0xFFFA68`. Trzeciemu wywołaniu
brakuje D1 — wynik musi pozostać UNKNOWN. Java21
porównuje również indeks `D1.L`, który nie może dać
sztucznego trafienia do SIMCR. Test łączy rzeczywisty
Listing CPU32, dwa JSR, deterministyczny raport
MAY-only, niezmienioną rewizję Program i profil MC68332.
Pełny build Ghidra 12.1.4 PUBLIC/Java25 oraz wynik
GitHub Actions na dokładnym SHA są obowiązkowe.

## GA-02/03 + GA-17/18 — kandydat 2026-11-05: źródłowy cel pośredniego JSR

Po integracji #168–#171 istniejący mechanizm Automation API weryfikuje
ściśle sąsiadujące instrukcje CPU32 `MOVEA.L #entry,An; JSR (An)`
według rzeczywistych bajtów i zdefiniowanego, dokładnego wejścia
funkcji. Główny raport sprzętowy dotychczas nie pokazywał tego
wąskiego dowodu. Nowa sekcja `HardwareIndirectCallEvidence` ponownie
wykorzystuje **tę samą** weryfikację, rejestruje źródłowe
`adjacent_movea_immediate` oraz jawne nieznane i pominięte cele.
Nie dołącza dowodu do grafu RESET, nie promuje go do trwałego
checkpointu ani Review/Apply.

Osobny rzeczywisty syntetyczny test Ghidry 12.1.4 PUBLIC/Java25
weryfikuje dokładny JSR (A0), nierozpoznany JSR (A1),
niezgodny rejestr MOVEA/JSR i nieistniejący dokładny Function
target. Java21 testuje deterministyczną prezentację, limit 96
kandydatów i brak wnioskowania z nieznanych celów.
Wymagane SHA-pinned pełne CI na dokładnym HEAD PR. Nie oznacza
wykonanego wywołania, zapisu SIMCR, aktywnego MM ani fizycznej
mapy CS. GA-02/03 pozostają CZĘŚCIOWO.

## GA-06/10/16 — kandydat 2026-11-05: SYNCR z MC68332UM D-6/D-7

Po scaleniu #172, w oparciu o **oficjalny plik PDF NXP**
`https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf`,
© Motorola 1995, Appendix D.2.3, drukowane D-6 i D-7
(fizyczne strony PDF **220 i 221**), dodajemy źródłowe
pola rejestru SYNCR: W, X, Y[5:0], EDIV, RSTEN, STSIM, STEXT.
Pola statusowe SLIMP/SLOCK oraz zarezerwowane bity 6/5
pozostają **UNINTERPRETED** przy analizie stałej zapisu.
Nie zgadujemy wartości po RESET, bieżącego stanu zegara,
ani uprawnień do automatycznej edycji.

Wymagane regresje Java21: dokładne maski, 7 cytowań
drukowana/fizyczna strona, wyłączenie statusów,
brak automatycznego dziedziczenia przez ogólny CPU32
i odrzucenie częściowych zapisów. Pełna kompilacja
Ghidry 12.1.4 PUBLIC / Java25 oraz rzeczywista
syntetyczna Ghidra mają przejść na dokładnym SHA PR.
Weryfikacja strony PDF nie zastępuje podpisu,
autentyczności wydania i lokalnego SHA pliku.

## GA-02/03 + GA-17/18 — kandydat 2026-11-05: pośredni CALL z NOP/MOVEQ

Po #172 osobny raport źródłowy rozpoznawał tylko sąsiadujące
`MOVEA.L #entry,An; JSR (An)`. Automation API obsługiwało już
dodatkowo do trzech bezpiecznych instrukcji `NOP/MOVEQ`
między nimi, ale dowodu nie pokazywano w analizie sprzętowej.
Nowy wspólny interfejs źródłowy podaje adres MOVEA,
potwierdzony cel i precyzyjny wariant pochodzenia.
Główny raport wymaga ponadto przynależności **wszystkich**
instrukcji do tej samej funkcji i pozostaje MAY-only.
Nieznane, niezgodne lub nieobsługiwane pośrednie CALL to UNKNOWN,
bez dodawania krawędzi RESET i bez automatycznego Apply.

Wymagany rzeczywisty izolowany test Ghidry 12.1.4 PUBLIC/Java25
z syntetycznym CPU32, test Java21, pełny build rozszerzenia
i PASS na dokładnym SHA. Historia #172 pozostaje zachowana;
GA-02/03 nie stają się z tego powodu ukończone.

## GA-02/03/18 — kandydat 2026-11-05: obcy XREF nie domyka pośredniego JSR

`AutomationCallPaths.index` ufał dowolnemu Ghidra
`ReferenceType.isCall()` do istniejącej funkcji jako
rozstrzygniętej krawędzi, także dla `JSR (An)`.
Tym samym ręcznie dodany odsyłacz `COMPUTED_CALL`
mógł tłumić `unresolved_calls` i raportować
`complete=true` bez dowodu wartości rejestru.
Poprawka ogranicza awans takich krawędzi do istniejącego
ścisłego dekodera CPU32 `MOVEA.L #entry,An` i dopuszczonych,
krótkich łańcuchów `NOP/MOVEQ`; pozostałe wywołania
obliczane są UNKNOWN, niezależnie od przypisanego XREF.
Nie ogranicza odsyłaczy dla bezpośrednich CALL.

Regresja w rzeczywistej syntetycznej Ghidrze 12.1.4
PUBLIC wstawia ręczny `COMPUTED_CALL` z `JSR (A1)`
do funkcji MMIO. Oczekuje `unresolved_calls=1`,
`complete=false`, braku pozornych ścieżek oraz
zachowania prawidłowego byte-proven `JSR (A0)`.
Wymagane pełne CI i dokładny SHA PR; statyczne krawędzie
nie stanowią dowodu przebiegu firmware ani aktywnego MM.

## GA-02/03/18 — kandydat 2026-11-05: fałszywe CALL-XREF na zwykłym NOP

Po scaleniach #174 i #175 wykryto pokrewną lukę:
`AutomationCallPaths.index` uznawał referencję typu CALL nawet
z instrukcji, która według Ghidry **nie jest CALL**.
Ręcznie dodany `COMPUTED_CALL` przy prawdziwym CPU32 `NOP`
mógł stworzyć fałszywie osiągalną funkcję zapisującą MMIO.

Nowy warunek wymaga prawdziwego `FlowType.isCall` oraz
braku `isComputed` przed wykorzystaniem referencji.
Oddzielny rzeczywisty test syntetycznej Ghidry 12.1.4
PUBLIC/Java25 dodaje do `NOP` testowy USER_DEFINED XREF
prowadzący do funkcji MMIO i wymaga **0 ścieżek**,
braku 0x700 w osiągalnych, `complete=true`.
Poprawny JSR (A0) nadal ma precyzyjny byte-proven target,
a nieznany JSR (A1) pozostaje INCOMPLETE. Wymagane
pełne GitHub Actions na dokładnym SHA, bez lokalnych
testów Wyse/Precision, zmian Apply ani twierdzeń o runtime.
