Warning: truncated output (original token count: 74013)
Total output lines: 4967

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

## GA-02/03/18 — candidate 2026-11-12: validate public one-hop CALL source coordinates

The public one-hop CALL context, callee CFG, candidate and summary records
will independently reject odd or out-of-range MC68332 source coordinates,
malformed CFG PCs and contradictory candidate/counter shapes. Deterministic
Java 21 adversarial regressions and the complete Java 25 Ghidra 12.1.4 PUBLIC
build plus genuine isolated synthetic Ghidra CI must pass on the exact HEAD
before integration. This prevents forged typed source claims; it does not
prove CALL execution, path feasibility, MM latch, active ISR/VBR or physical
bus mapping. GA-02/03/18 remain PARTIAL.

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

## GA-06/10/16/18 — 2026-11-10: PDF folio and bitfield source-claim integrity

A coherent metadata-trust package rejects revision dates disguised as
printed PDF folios, checks public pagination classification against both
physical and printed page observations, and requires public decoded bitfield
reports to match static register word, width, mask inventory, untyped
remainder and one syntactically consistent physical PDF-page claim per
field. These are validation of *claims*, not authentication of a manual
edition/hash or observation of CPU execution, latched SIMCR MM or active
interrupts. Java21 regressions, full Java25 Ghidra 12.1.4 PUBLIC build and
real isolated synthetic Ghidra CI remain exact-HEAD gates. GA-06/10/16/18
are PARTIAL; GA-14 remains deferred.

## GA-01/02/03/11/18 — 2026-11-10: RESET/CALL public report source consistency

Generic CPU32 transitive CALL effect summaries now reject impossible zero-visit STORE/VBR findings, contradictory recursive/truncated flags, and typed witness chains whose observed prefixes exceed the inspected-node budget. Missing roots and skipped frontiers retain correct zero-visit and not-inspected semantics. RESET static flow reports validate visited node counts, typed evidence depth and chain endpoint syntax, source membership in the inspected function set, and duplicate evidence identities. Deterministic Java21 adversarial self-tests, full Java25/Ghidra 12.1.4 PUBLIC compilation and genuine isolated synthetic headless CI are merge requirements at exact SHA. Static candidates remain distinct from actual instruction execution, active ISR/VBR, latched MM, and physical mapping. GA-01/02/03/11/18 PARTIAL; GA-14 deferred.

## GA-01/02/03/11/18 — 2026-11-10: CPU32 source graph U32 address envelope

Both read-only transitive CALL source engines and RESET root/evidence\nvalidation enforce the unsigned
32-bit identity envelope before accepting function nodes, edges,
CALL-site instruction PCs, selected callers, explicit roots or typed
witness chains. The inclusive 0xFFFFFFFF boundary remains representable;
0x100000000 is rejected rather than printed as a plausible CPU32 source.
Device-specific MC68332 24-bit address interpretation remains independent.
Java21 adversarial boundary regression, full Java25/Ghidra 12.1.4 PUBLIC
build and isolated real synthetic Ghidra CI are required at exact SHA.
Static source membership is not execution, latched MM, active VBR/ISR or
physical mapping. GA-01/02/03/11/18 remain PARTIAL; GA-14 deferred.

## GA-02/03/15/18 — 2026-11-10: CALL-site SIMCR/MM source report integrity

The public transitive MM CALL-site source report now rejects fabricated
cross-target witness paths, impossible observed-chain versus inspected
function counts, zero-visit resolved evidence, malformed row inventory
and an unresolved computed CALL promoted into a known callee. Missing
roots and omitted frontier targets stay conservative UNKNOWN. Java21
regression, full Java25 Ghidra 12.1.4 PUBLIC extension compilation and
synthetic headless CI are exact-SHA gates. Read-only source evidence is
not actual execution, RESET sequencing, active ISR/VBR or latched MM.
GA-02/03/15/18 remain PARTIAL; GA-14 deferred.

## GA-02/03/11/18 — 2026-11-10: bounded MC68332 source witness visit coherence

Selected-MC68332 vector-handler SIMCR/MM source reporting now rejects
publicly constructed MAY/alias/inspected-unknown/cycle witnesses whose
function-chain prefixes cannot fit the claimed number of visited source
functions. Missing roots and pre-inspection batch cutoffs remain valid
zero-visit UNKNOWN results; explicitly skipped depth/node/batch targets
are never counted as visited. Deterministic Java21 adversarial tests,
Java25 full Ghidra 12.1.4 PUBLIC extension build and genuine synthetic
headless CI are exact-SHA merge gates. Static MAY is not executed MMIO,
latched SIMCR MM, an active VBR/ISR or proof of physical bus behavior.
GA-02/03/11/18 remain PARTIAL; GA-14 deferred.

## GA-01/02/03/11/18 — 2026-11-10: shared vector-handler provenance integrity

Both generic CPU32 STORE/MOVEC and selected-MC68332 SIMCR/MM source
correlation now reject inconsistent report rows for different vector
slots resolving to the same exact handler function. Canonical typed
source paths accept only 32-bit CPU32 function identifiers (eight hex
digits); this is NOT evidence of MCU24 physical addressing or active IRQ.
Deterministic Java21 contradictory-record and address-width tests, Java25
full Ghidra 12.1.4 PUBLIC build and genuine isolated synthetic headless CI
are exact-commit merge gates. Existing source-per-handler caching,
displayed-only counts, read-only behavior and RESET/MM evidence separation
are preserved. GA-01/02/03/11/18 remain PARTIAL; GA-14 deferred.

## GA-01/02/03/11/18 — 2026-11-10: fail-closed generic vector/RESET source reports

The generic 32-bit CPU32 vector/RESET report now validates bounded
source-only row identity, ordered vector slots, exact/interior population,
RESET shared/outside counters, and canonical rooted STORE/MOVEC/unknown/
frontier function witnesses before publishing Markdown. Null, malformed,
injected or contradictory user-constructed report cells fail closed.
Displayed-only STORE and MOVEC counts explicitly do not describe
undisplayed handlers. Legacy seven-field source constructors remain
compatible. The selected MC68332-only SIMCR/MM report is separate;
CPU32 32-bit candidate pointers do not inherit MCU24 hardware mapping.

Java21 deterministic adverse source regression, Java25 full Ghidra
12.1.4 PUBLIC extension compilation and isolated genuine synthetic
headless vector CI are exact-SHA integration gates. This does not prove
ISR firing, active VBR, RESET execution, SIMCR first write or bus mapping,
and it changes no Apply/Undo, original firmware, production project
or paused Wyse/Precision/Supervisor tests. See
[vector/RESET correlation](hardware-vector-reset-correlation.md).
GA-01/02/03/11/18 remain PARTIAL; GA-14 deferred.

## GA-01/02/03/11/18 — 2026-11-10: selected-MC68332 vector handler -> SIMCR/MM MAY roots

MC68332 exact-entry image-zero and candidate relocated MOVEC/VBR
vector handlers now have a separate **device-specific transitive
SIMCR/MM low-byte MAY** report. The former generic `memory STORE`
source correlation was insufficient to distinguish actual potential
SIMCR byte overlap from unrelated memory writes. The existing bounded
MM source solver now accepts exact function-entry roots directly
(`inspectRoots`) so no fake vector-to-handler CALL-site PC, runtime
ISR dispatch, or direct RESET graph edge is constructed. Repeated
vector slots share one root summary within this single Program analysis.

The added device-gated report names typed shortest source-function
chains for potential MM STORE, unknown alias/width, inspected missing
target/unknown flow, and independently skipped depth/node/batch
frontiers. It preserves the separate RESET reachability confidence
horizon, counts the full bounded exact/interior vector inventory,
inspects only capped displayed exact entries (32 image-zero/12 per
relocated source table), and rejects 32-bit CPU32 pointer reinterpretation
as a selected MC68332 24-bit vector target.

Generic CPU32 receives no device-specific MM status. Neither table
is established as active VBR; a potential MM STORE is not an executed
write or latched MM value. No ISR firing, physical bus/CS mapping,
Review/Apply/Undo authorization, original ECU411 source, or production
Ghidra project is modified. Java21 deterministic source regressions,
Java25 complete Ghidra 12.1.4 PUBLIC build and isolated genuine
synthetic headless image-zero/relocated gates are required on final
PR SHA. See [vector/RESET correlation](hardware-vector-reset-correlation.md).
GA-01/02/03/11/18 remain PARTIAL; GA-14 deferred.

## GA-01/02/03/11/18 — 2026-11-10: known CALL targets are not missing depth frontiers

The read-only bounded transitive SIMCR/MM and RESET direct-CALL analyzers
now distinguish an already-scheduled CALL target at the maximum traversal
depth from an actually uninspected target. A recognized recursive
backedge or convergent diamond edge may end at the depth boundary
without asserting a **false** `DEPTH_CUTOFF` or a falsely truncated
RESET graph. Cycle/unknown-control flags remain conservative; genuinely
unscheduled deeper functions still yield an explicit omitted frontier,
and a decoded direct CALL into a missing function remains observed
UNKNOWN rather than a silently closed negative. Generic STORE/MOVEC
solver parity is regression-tested.

The selected-MC68332 MOVEC/VBR table planner also rejects unbounded,
null, odd, negative and over-24-bit RESET source function identities
before assigning priority to source-image table candidates. No generic
CPU32-to-device 24-bit aliasing is inferred. These changes affect
source-evidence precision and validation only; no executable CALL or
RESET path, active MM latch, runtime VBR/IRQ, physical map, new
Review/Apply authority, user program mutation or Supervisor host
test is inferred. Java21 deterministic regressions and Java25 full
Ghidra 12.1.4 PUBLIC isolated synthetic CI are exact-SHA merge gates.
See [interprocedural MM sources](hardware-interprocedural-mm-source-witnesses.md)
and [relocated VBR sources](hardware-relocated-vbr-source-candidates.md).
GA-01/02/03/11/18 remain PARTIAL; GA-14 deferred.

## GA-01/02/03/11/18 — 2026-11-10: shortest typed vector-handler STORE and MOVEC CALL witnesses

The bounded read-only `HardwareCallEffects` BFS now retains **typed
shortest function-entry source chains** for generic P-code `MEMORY_STORE`
and CPU32 `MOVEC_VBR`, separately from actually observed
`UNKNOWN_FLOW`/`MISSING_TARGET` and a not-yet-visited
`DEPTH_CUTOFF`/`NODE_CUTOFF`. The original summary flags and public
`summarize` API are preserved. Vector/RESET correlation presents these
paths per exact-entry ISR candidate, with unchanged numeric counts,
an explicit unknown flag and per-report memoization. Interior vector
pointers never borrow complete-function evidence; display caps only
limit detailed per-handler source analysis, not input counts.

A **recognized source function** is not an executed handler; observed
direct-CALL graph reachability is not runtime feasibility. Missing
function definitions, unresolved indirect calls, recursion and bounded
depth/node frontiers remain uncertain. No latched SIMCR MM, active VBR,
actual interrupt, physical CS map or Ghidra write permission follows.
No durable source evidence is reused across Ghidra revisions.
Deterministic Java21 and full Java25 Ghidra 12.1.4 PUBLIC isolated
synthetic headless CI are exact-SHA merge gates. See
[vector/RESET source correlation](hardware-vector-reset-correlation.md).
GA-01/02/03/11/18 remain PARTIAL; GA-14 deferred.

## GA-12/15/18 — 2026-11-10: explicit Listing page anchor across UI navigation

Automation API v3 `listing.range` may use the active CodeBrowser cursor
only for its first read-only page. Previously a later page with a
matching Program revision but no address could silently reuse a
newly selected GUI cursor: CodeBrowser navigation does not increment
the Program modification number, so two adjacent pages could come
from different Listing ranges. The RPC server, underlying Listing
implementation and `ghidrassist-agent` CLI now require an explicit
first-page start address **and** the original Program revision for
every nonzero offset. First-page interactive navigation and explicit
same-start requests remain unchanged. `start`, `revision`,
`next_offset` and static-source warnings provide bounded pagination
coordinates but are not independently authenticated cross-request cursors.

Deterministic Python3 CLI negative tests reject absent/blank start and
absent revision before RPC; Java25 full Ghidra 12.1.4 PUBLIC extension
build and isolated synthetic headless integration are exact-SHA
integration gates. No executable CALL, MMIO/ISR execution, Review/
Apply/Undo authorization, Program writes, user profiles, OAuth, original
ECU411 firmware, or stopped Wyse/Precision/Supervisor tests are used.
See [Automation API v3](ga18-automation-api-v3.md).
GA-12/15/18 remain PARTIAL; GA-14 deferred.

## GA-01/02/03/11/18 — 2026-11-10: target-rooted computed JSR/MMIO chains and MOVEC identity gate

The byte-witnessed indirect CPU32 JSR -> SIMCR/MM MAY report now
publishes the shared solver's bounded, typed target-rooted function
witnesses for modeled MM sources, unknown STORE aliases, inspected
unknown-flow/missing-function sources, and separately uninspected
depth/node/batch frontiers. This closes a presentation/evidence gap
after the previous direct CALL-site dual-witness improvement: flags
alone masked the actual candidate origin and omission boundary.
The read-only report rejects a source witness rooted at a different
computed CALL target, repeated CALL PC, and unbounded result rows.
Cycles without a source witness remain explicitly uncertain.

The joint RESET/indirect-JSR/MOVEC same-function correlation now
also rejects the logically impossible reuse of a **single decoded
instruction PC** for both JSR and MOVEC, including at an on-demand
page beyond the first window and during immutable source-inventory
capture. This prevents internally inconsistent mixed source snapshots
from appearing as meaningful MM/VBR co-location.

No new direct CALL graph edges, actual RESET dispatch, executed STORE,
latched SIMCR MM, runtime VBR/ISR, physical CS map, Review/Apply/Undo
authorization or durable cross-JVM source publication is inferred.
Java21 deterministic positive/negative coverage for partial MM paths,
observed UNKNOWN vs skipped frontier, cross-target forgery, source
reordering and cross-kind PC identity; Java25 full Ghidra 12.1.4 PUBLIC
build and genuine isolated synthetic headless CI are merge gates.
See [indirect JSR source provenance](hardware-ga02-indirect-jsr-source-provenance.md)
and [CALL source witnesses](hardware-interprocedural-mm-source-witnesses.md).
GA-01/02/03/11/18 remain PARTIAL; GA-14 deferred.

## GA-08/13/18 — 2026-11-10: fail-closed executable digest in rename receipt audits

Both GA-08 pointer-variable and GA-13 function-rename **read-only**
Program Options audits now require two syntactically valid 64-hex
executable SHA-256 identifiers before classifying a saved approved
name as `CURRENT_APPROVED_NAME`. Identical malformed text, legacy
`UNKNOWN` (including lowercase) or nonhex 64-character values
remain readable as records but result in `SOURCE_UNVERIFIED`;
different valid digests remain `SOURCE_CHANGED` and different-case
valid hex values may match. This corrects a false-confidence
classification; SHA metadata alone is NOT independent proof of file
bytes, author identity, unchanged analysis, Review/Apply authorization
or MCU hardware execution. Existing versioned schemas and native
Undo/Redo transactions are unchanged.

Regression spans the shared revision digest check, saved-function
read-only audit and scoped-variable receipt audit, including forged
same-text identities and positive valid matching hex. Java21
deterministic tests, Java25 Ghidra 12.1.4 PUBLIC full extension build
and genuine isolated synthetic Ghidra CI are mandatory before merge.
See [change provenance](hardware-change-provenance.md).
GA-08/13/18 remain PARTIAL; GA-14 deferred.

## GA-02/03/18 — 2026-11-10: separate observed-UNKNOWN and bounded frontier paths

CALL-site transitive SIMCR/MM reporting now distinguishes the shortest
**observed** unknown-flow or missing-function chain from the independently
bounded **uninspected** frontier chain. A depth/node/batch cutoff seen
while inspecting an earlier BFS sibling no longer hides a later,
shorter observed UNKNOWN candidate in the primary witness. The original
cutoff-only unknown-chain API remains compatible. Both witnesses retain
canonical traversal order, typed causes and conservative UNKNOWN/LIMITED
flags; no new graph edges, executed CALL/RESET assertions, active MM
latch, VBR/ISR activity, physical hardware map, database mutations or
checkpoint publication are inferred.

Java21 determinism/negative tests cover depth plus observed flow, missing
target plus cutoff, node cap plus observed UNKNOWN, reversed input order,
cutoff-only compatibility and forged contradictory evidence. Java25 full
Ghidra 12.1.4 PUBLIC extension build and synthetic headless GitHub Actions
remain required before merge. See
[interprocedural MM source witnesses](hardware-interprocedural-mm-source-witnesses.md).
GA-02/03/18 remain PARTIAL.

## GA-06/10/16/18 — 2026-11-10: ten immutable publisher D-10/D-11 excerpt SHA-256 references

On top of the new ten SYPCR/PICR/PITR source fields, the exact
publisher-hosted MC68332UM SHA-256/265-page PDF CI verified **10/10
full nearby heading-and-meaning excerpts** on physical PDF pages
224/D-10 and 225/D-11, and logged the ten independent excerpt
SHA-256 fingerprints (Actions run 42816712499, source SHA
`02d14ace320a159daecb24ec8237a365bba49d62`). The manually
reviewed fingerprints are now frozen in
`HardwareSimProtectionTimerPublisherPins` and verified on every
official PDF CI run. No automatic acceptance of changed PDF/excerpts.
The exact register mask/width checks remain separately validated
against the original diagrams and the already pinned Table D-2
physical register list.

`ga_mc68332_field_citations` now reports both the source's
**index-time excerpt SHA** and the **frozen publisher excerpt SHA**
and distinguishes `MATCHES_PINNED_EXCERPT` from textual candidates.
This still does **not** independently authenticate caller-supplied
RAG text, live local PDF bytes, physical MMIO, SYPCR first write,
active watchdog, PIT timer or ISR. No paused Wyse/Precision/Supervisor
workloads, real ECU411 firmware, user Ghidra projects or OAuth
data are touched. GA-06/10/16/18 remain PARTIAL, GA-14 deferred.

## GA-06/10/16/18 — 2026-11-10: ten MC68332 protection/periodic timer bitfields

The next MC68332-only source review expands beyond the previously verified
15 SIMCR/SYNCR bitfields: SYPCR (six 8-bit fields), PICR (three-bit
periodic interrupt level plus eight-bit vector), and PITR (timer
prescaler plus eight-bit modulus). All **10 new masks and their
source heading/meaning pairs** are independently correlated with the
reviewed MC68332UM Motorola 1995 diagrams, printed D-10/D-11,
**physical PDF pages 224/225**, while original register identities,
offsets and widths remain linked to the already checked Table D-2 on
physical PDF page 218. The same immutable 265-page official NXP PDF SHA
is checked in separate GitHub Actions before extracting any field source.
Historic D-5/D-6/D-7 15-field source evidence stays scoped separately.

Only complete static register-width literal values may be decoded, under
the explicitly selected MC68332 profile: SYPCR has a first-write
after-reset caveat, but neither actual write acceptance nor watchdog
function is proved; PICR/PITR candidates never prove active interrupt,
vector/ISR, timer frequency or hardware execution. No reset register
value is inferred, especially for MODCLK-dependent fields. SWSR
watchdog servicing remains an unproven source-side sequence.

The existing `ga_mc68332_field_citations` RAG tool additionally
accepts SYPCR/PICR/PITR through an exact two-folio Lucene snapshot,
requiring the original publisher SHA **at index time**. The warning
`INDEXED_TEXT_NOT_CURRENT_FILE_AUTHENTICATION` remains mandatory:
indexed text is not independent proof of current local PDF bytes.
Focused Java21 source-only negative tests, official SHA-pinned PDF CI,
full Ghidra 12.1.4 PUBLIC Java25 integration, and synthetic headless/GUI
CI are required before any merge. See
[bitfield source evidence](hardware-bitfield-evidence.md).
GA-06/10/16/18 remain PARTIAL; GA-14 deferred.

## GA-06/10/16/18 — 2026-11-10: independent publisher field-description excerpts and RAG binding

Beyond the already implemented NXP-hosted MC68332UM (Motorola 1995)
publisher PDF SHA-256, exact 265 pages, physical folios and independent
15-bitfield diagram-mask comparison, a new **independent source-content
cross-check** now binds all 15 reviewed SIMCR/SYNCR fields to their
**full printed heading and nearby explanatory paragraph fragment** on
the physically correct description folio D-5/219, D-6/220 or D-7/221.
The drawing/mask page is tracked separately from the prose page; short
MM/W/X/Y tokens alone can never pass. Fifteen reviewed original publisher
excerpt SHA-256 fingerprints are frozen in source and checked afresh in
the official PDF CI after downloading and verifying actual immutable
publisher bytes. No PDF content is uploaded to the repo or CI artifacts.

An explicitly invoked `ga_mc68332_field_citations` native tool obtains
all required indexed PDF pages in ONE Lucene snapshot, enforcing identical
source SHA/path/library and per-page text consistency before rendering
a bounded, read-only field citation. Users specify the concrete device
MC68332; generic CPU32/filename alone never selects registers. Every
citation distinguishes the index-time SHA, extracted passage SHA and
frozen publisher reference, including whether individual excerpts match
the independently reviewed source. These are **indexed-text comparisons**
and not cryptographic proof of current local PDF, the manual edition,
execution, active SIMCR MM latch, VBR/ISR or bus mapping. The existing
pre-open local file hash check is independent and unchanged.

Deterministic Java21 adversarial tests cover wrong description page,
heading, excerpt text, mask, distant phrase, unrecognized field, invalid
profile, stale page, cross-folio source SHA/path/library mixing, edition
pin mismatch and unbounded source input. Full Ghidra 12.1.4 PUBLIC Java25
extension build and isolated synthetic GUI/headless regressions are gated
before integration. See [bitfield source evidence](hardware-bitfield-evidence.md).
GA-06/10/16/18 remain PARTIAL; GA-14 deferred.

## GA-06/10/16/18 — 2026-11-10: indexed PDF digest and current-file RAG provenance

Existing GA-10/16 CI already pins publisher-hosted MC68332UM (Motorola 1995)
SHA-256 and checks exact physical PDF folios, source tokens, independently
reviewed SIMCR/SYNCR bitfield diagrams and MCU-specific SIM register tables.
This package closes the separate **runtime RAG provenance gap** rather than
duplicating official-PDF tests.

Both ordinary text and PDF imports now require identical **pre- and
post-extraction SHA-256 and file length**, before atomic Lucene replacement;
even the unchanged-file skip performs a second consistency check. An
interrupted extraction or modified input is a failed import rather than
a new digest with stale text.

Search results now propagate each Lucene source document's **index-time**
SHA-256, physical PDF page and file path. Full-page retrieval joins chunks
only when their page, digest, path, document type, source library and distinct
chunk IDs agree, with a bounded total text cap and fail-closed response to
conflicting/ambiguous metadata. Native RAG search/page results and GUI search-result panels identify the
pinned public MC68332UM bytes using the same reviewed SHA-256 constant as
the bitfield source ledger; any older/missing digest remains UNKNOWN. The
selected project's library scope is checked against the page's actual
Lucene snapshot, avoiding separate mutable metadata reads. GUI full-page
inspection additionally binds the result's **original** SHA, source path,
library and physical page to the current index snapshot, refusing stale
search hits after a document is reindexed or moved between libraries.

Before external source-page viewing, the current local PDF is streamed
and SHA-256 compared to the indexed bytes, with PDF-header, regular-file,
symlink, size and during-read replacement checks. A changed or unpinned
local file cannot be presented as the indexed citation; it requires reindex.
This is **not** an OS-atomic guarantee against changes after the check, and
a checksum or familiar filename does not prove edition, folio content,
hardware register semantics or a real MCU. Arbitrary indexed text remains
untrusted; profile/device selection remains explicit. No Ghidra writes,
Review/Apply/Undo changes, private firmware, user configuration mutation,
stopped local host tests or publication of PDF bytes.

Java21 deterministic regression covers changed/rewrapped/legacy digest,
cross-page and cross-library chunk mixing, duplicate IDs and bounded
source-file checks; Java25 complete Ghidra 12.1.4 PUBLIC extension build
and synthetic headless CI remain required. See
[RAG source integrity](hardware-rag-source-provenance.md).
GA-06/10/16/18 remain PARTIAL; GA-14 deferred.

# GhidrAssist — 18-track hardware-analysis development ledger

## GA-01/02/03/11/12/18 — 2026-11-10: fail-closed source inventory after disk CFG restart

The GA-12 aggregate CFG report retains exact Program/Listing/JAR input
fingerprints and a typed V2 JSR/MOVEC/RESET inventory, but the V2 envelope
checksum does **not** authenticate a source author or independently replay
instruction identities, indirect MAY-MM provenance, bounded RESET reachability
or MOVEC/VBR candidates after a JVM restart. A completed report was
previously restored into `GhidraHardwareFlowService.Report` with the stored
source inventory still attached, enabling revision-bound GUI/Automation API
source pagination as though those rows were freshly re-derived.

Now disk `load` calls a strict **CFG-only restoration projection**:
the completed, fingerprint-matching report and original safety/omission/RESET
flags remain reusable, but the stored typed source inventory is dropped from
the **active** report. A prominent notice distinguishes retained historical
Markdown from independently verified current Listing source. Automation
`source-pairs` pages remain `SOURCE_INVENTORY_NOT_RETAINED` until an explicit
checkpoint clear and fresh Analyze. Fresh in-memory source pages still use
the existing revision+epoch gate. Read-only sourced checkpoints do not grant
Review/Apply/Undo authority or imply actual MCU execution, latched SIMCR MM,
active VBR/ISR or a physical map.

The typed disk V2 decoder remains backwards compatible (V1 and V2); added
RESET-root consistency guards refuse a nonempty reset set without a
recognized root or a recognized root with no functions, even with recomputed
outer SHA-256. Java21 adversarial tests check complete, omitted/uncertain,
historic V1 and malformed rewrapped V2. The real Ghidra 12.1.4 PUBLIC Java25
multi-JVM synthetic restart regression must also verify that a byte-valid,
**correctly rehashed but falsified** JSR MAY-MM claim can be reused ONLY as
an aggregate CFG checkpoint, never as live source-page evidence. A full
fresh Analyze re-derives sources with the existing independent GA-12
per-function register/MMIO/VBR source checks. No original ECU411 firmware,
production project, profiles/OAuth or stopped Wyse/Precision tests are used.
GA-01/02/03/11/12/18 remain PARTIAL; GA-14 deferred.

## GA-02/03/18 — 2026-11-10: deterministic bounded interprocedural MM source witness paths

The shared `HardwareCallEffects.FunctionNode` also canonically sorts
direct target adjacency for both the generic static CALL-effect analysis
and RESET-rooted candidate paths. Reversed Ghidra reference enumeration
can no longer select a different subset under the same bounded node
budget or change the shortest convergent RESET witness. Duplicate edges
remain representable; canonical numerical order is NOT execution order.
The Java21 RESET and static CALL-effect tests now cover reversed inputs,
convergent paths, deterministic truncated subsets and positive uncapped
controls.

The read-only transitive CALL-site SIMCR/MM report now carries independently
typed **shortest function-only source witness chains** for positive modeled
SIMCR MM candidates, unknown STORE aliases and unknown control-flow or
uninspected graph frontiers. Canonical BFS target order makes the witnesses
stable across Ghidra reference-enumeration order, including converging
diamonds and finite node/edge/batch limits. Each frontier is explicitly
typed as missing function, depth cutoff, node cutoff or shared batch cutoff:
an uninspected callee is **never** presented as an observed STORE.
An unresolved indirect CALL or a cycle-only uncertainty does not fabricate
a callee chain; the original UNKNOWN/LIMITED/CYCLE flags remain decisive.

The source chain begins at the *called function*, not a CALL instruction
site, and cannot establish a feasible/executed RESET path, interprocedural
register transfer, actual SIMCR MM latch, VBR/ISR activity, or physical bus
mapping. The witness paths are read-only, in-memory, bounded by the existing
10,000-node per-source and 16,384-node batch caps and 32-edge traversal
depth. No Ghidra program/review/undo/durable checkpoint semantics change.

Java21 adversarial regression extends the existing GA-02/03 CALL-effect
self-test; full Ghidra 12.1.4 PUBLIC Java25 extension compilation and
actual synthetic Ghidra headless CI remain required. See
[bounded source witnesses](hardware-interprocedural-mm-source-witnesses.md).
GA-02/03/18 remain PARTIAL.

## GA-02/03/11/12/18 — 2026-11-10: independent MMIO/VBR/unknown-site CFG joins for durable evidence

Completed GA-12 per-function disk checkpoints now undergo an additional
**independent, bounded hardware-lattice source replay** on both `save`
and `load`. Following the already integrated exact Program/JAR/Step
hashes and independent predecessor **A/D register** join proof, this
pass derives tracked whole-16-bit MMIO register constants, candidate
VBR and source-uncertainty state at each reachable CFG node **without
feeding in any MMIO/VBR values claimed by the disk record**.

For a modeled MMIO STORE, the replay derives direct or indirect 24-bit
source address and 16-bit literal/known register value from the
independently verified A/D state. Any byte/word/long store clears
overlapping full-register constants; an unknown pointer or unknown
width drops the entire tracked MMIO lattice and records UNKNOWN store
provenance. Only a known, aligned 16-bit complete store to an explicitly
tracked target re-establishes the full-word value. `CALL_BARRIER`
clears MMIO/VBR state and preserves UNKNOWN call provenance, even when
strictly verified return-register constants are separately available.
`VBR_CONSTANT` and `VBR_FROM_REGISTER` update only candidate static
VBR observations.

At a CFG merge or loop back edge, conflicting/missing MMIO words
and VBR candidates collapse to UNKNOWN, the bounded count of **possible
SIMCR MM low-byte source writes** is joined as a min/max range, and
UNKNOWN CALL/STORE flags are merged conservatively with logical OR.
Every completed typed STORE/MOVEC snapshot's **post-instruction**
MMIO map and VBR, and **pre-instruction** candidate range and
unknown-source flags, must agree with these independently reconstructed
values. This blocks a fabricated partial CSBAR/MMIO constant, selected
VBR branch or first-SIMCR-site epoch even if an attacker recomputes
the outer SHA-256 of a key-matching disk envelope.

The replay uses at most the existing fixed-point iteration count and
3,000-Step/200,000-edge bounded source graph, plus a 262,144-total
active MMIO-cell cap. Oversized or nonconvergent audits fail closed to
cold analysis rather than using a dubious completed checkpoint.
Existing typed source bounds, `Review/Apply/Undo` authorization and
stale-Program/revision gates are unchanged. Incomplete intra-function
worklists remain **not publishable** as analysis evidence.

Two Java21 CI workflows now include a deterministic synthetic
adversarial suite: equal vs conflicting peripheral words on a diamond,
identical vs conflicting MOVEC/VBR branches, independent leaf CALL
return registers with MMIO/VBR state invalidation, unknown indirect
STORE, byte-overlapping 16-bit register, competing SIMCR source-site
counts, and cyclic VBR back-edge. Hostile checkpoints are saved inside
**correctly rehashed** exact project/CFG/JAR envelopes: rejected
`save` must preserve the valid slot, and `load` must refuse the
resealed lie. Full Ghidra 12.1.4 PUBLIC Java25 extension build and
real isolated synthetic headless regression are also mandatory.

These are **static candidate source** consistency facts only, not
proof that calls, writes, VBR or interrupts execute, that SIMCR MM
latched or that a physical memory map exists. Checksum integrity
does not authenticate an author; the pass does not independently
re-derive arbitrary actual MCU bus configuration. No ECU411 original
firmware, production Ghidra project, user profile/OAuth, or stopped
Wyse/Precision/Supervisor worker is accessed. GA-02/03/11/12/18
remain PARTIAL; GA-14 remains deferred.

## GA-02/03/12/18 — 2026-11-10: independent A/D register-join reconstruction before durable CFG publication

GA-12 completed per-function fixed-point checkpoints now receive a
**separate, bounded, register-only, source-derived fixed-point audit** on
both disk `save` and `load`. Starting at the source function entry
with unknown A/D registers, the verifier iteratively propagates
translated `SET_POINTER`, `COPY_POINTER`, partial-byte/word/long
`ADJUST_POINTER`, `CLOBBER_POINTER`, `CALL_BARRIER` with strictly
verified post-RTS register constants, and implicit source P-code
side-effect clobbers. At every directed CFG merge or back edge, only
constants **agreed by all observed source predecessors** survive;
unknown, missing or conflicting values collapse to UNKNOWN.

The verifier reconstructs **every** nonempty pre-instruction A/D
register map independently of the typed disk payload, compares it
exactly with `knownPointersAtEntry`, and respects the already bounded
3,000-Step CFG, source-edge limit and the completed result's maximum
fixed-point iteration count. No progress/partial checkpoint is upgraded
to completed evidence. A locally forged, **correctly rehashed**
checkpoint that invents a convergent A0/D0 source, keeps A0 across a
clobbered path, claims a register constant before it is defined, or
retains A0 through a loop back edge is now a cache miss; a rejected
`save` does not overwrite the last valid source. A matching diamond,
correct input-independent verified leaf return, or compatible loop
remains eligible for restart.

Independent Java21 regression covers conflicting/agreeing branch
joins, CALL return and pre-RTS register state, an A0-clobber fork,
converging D0 .B/.W arithmetic, a cyclic kill-and-join, valid
checkpoint roundtrip, and resealed false MMIO `0x40CA` witnesses
with exact project/CFG/JAR envelope keys. It runs in two distinct
GA-02/03 + GA-12 and GA-12 durable checkpoint Actions lanes.
Full Java25 Ghidra 12.1.4 PUBLIC extension build and actual isolated
synthetic Ghidra headless regression are required before merge.

This check **does not repeat the MMIO/VBR state solver** and does
not independently authenticate a checkpoint writer, prove execution
of an MCU path, bus mapping, an active MM latch or a VBR/ISR. Generic
source CPU32 and explicitly selected MC68332 profiles remain
separately bound by existing keys. Contextual one-hop CALL inputs
without a keyed caller are not eligible for disk-source publication:
the register replay starts from unknown entry values, avoiding false
cross-caller reuse. The accepted scope uses no ECU411 original
firmware, production Ghidra projects, user profiles, OAuth or stopped
Wyse/Precision/Supervisor process. GA-02/03/12/18 remain PARTIAL;
GA-14 remains deferred.

## GA-02/03/12/18 — 2026-11-10: source-equivalent value witnesses in durable CALL/CFG checkpoints

Beyond the already integrated exact Program/JAR/Step hashes, rooted CFG
reachability, site identity and bounded 24-bit value domains, the GA-12
**completed per-function** disk `save` and `load` paths now cross-check
each typed read-only MMIO/VBR snapshot's derived **values** against the
same translated CPU32 source `Step` and recorded pre-instruction
registers. For a direct STORE, its effective address must equal the
source literal modulo the modeled 24-bit address space. For an indirect
STORE, address derivation must match the known base, displacement and
optional signed 16-bit/32-bit index and scale; a missing source register
must not reappear as a concrete target. A 16-bit written word must be
exactly the source immediate or known D/A register low word, including
verified post-CALL return registers. No known-source register means
**UNKNOWN**, not a zero or fabricated SIMCR value. `MOVEC/VBR`
immediate and register-source snapshots must match their source base.

The bounded peripheral after-STORE lattice is also checked: all
retained full-register keys must be among the explicitly tracked source
targets; an unmodeled-width or unknown-pointer STORE must clear them.
Byte/long/spanning stores invalidate overlapped 16-bit register values.
Only a known, aligned, complete 16-bit tracked STORE can establish a
new register constant, and it must agree with the recorded source
word. This is **source-data consistency**, NOT proof that an MMIO
write occurred, MM latched, physical 24-bit bus mapping exists, or a
particular CALL/ISR/RESET path was executed.

The check…44013 tokens truncated…z chroniony `master`,
z zachowaniem oryginalnej historii 13 PR-ów #118–#130.

- **Commit wdrożenia:** [`217a5dd43e48135cde930e6f14dcb9b879c12b23`](https://github.com/bogkom/GhidrAssist/commit/217a5dd43e48135cde930e6f14dcb9b879c12b23).
- **Dokładny HEAD kandydata:** `e182c0f2b1f49e13b1975727956d1dcc2347d32e`.
  **55/55 GitHub Actions SUCCESS**, w tym Java 21, kompilacja rozszerzenia
  Ghidra 12.1.4 PUBLIC / Java 25, rzeczywista syntetyczna Ghidra headless,
  Xvfb/CodeBrowser oraz Automation API na izolowanym projekcie.
- **Identyczne drzewa obu commitów:** `4279c8fbead2921d3d5814d635eef63f8908782b`.
  Zatem komplet zweryfikowanych plików jest dokładnie taki sam na
  scalonym SHA, bez odchyleń w konflikcie po stronie `master`.
  Na **dokładnym merge SHA** dodatkowo **22/22 push GitHub Actions SUCCESS**,
  w tym [pełna kompilacja Ghidry 12.1.4](https://github.com/bogkom/GhidrAssist/actions/runs/41834860451).
- [RESET / wektory / źródła ISR](https://github.com/bogkom/GhidrAssist/actions/runs/41833621753),
  [Review/Apply nazw + Undo / odrzucenie starej rewizji](https://github.com/bogkom/GhidrAssist/actions/runs/41833621858),
  [CALL → checkpoint i unieważnianie cache](https://github.com/bogkom/GhidrAssist/actions/runs/41833621715),
  [trzy JVM, częściowy fixed point CFG](https://github.com/bogkom/GhidrAssist/actions/runs/41833621809),
  [Automation API](https://github.com/bogkom/GhidrAssist/actions/runs/41833621839) i
  [rzeczywisty syntetyczny CodeBrowser pod Xvfb](https://github.com/bogkom/GhidrAssist/actions/runs/41833621737):
  **CI PASS** na HEAD kandydata — nie oznacza testu na oryginalnym firmware.
- GitHub oznaczył bezpośrednie PR-y #118, #119, #120, #121, #122,
  #124 jako `Merged`. Zależne PR-y #123, #125–#130 są **administracyjnie
  zamknięte**, ponieważ każdy ich HEAD jest już przodkiem `master`
  (GitHub compare: 0 commitów behind). Odrębne etykiety `Closed`
  w interfejsie nie oznaczają braku włączenia kodu.
  Ich oryginalne SHA, komentowane checkpointy i dowody CI pozostają.
- Starsze, historyczne PR-y spoza tego pakietu nie są automatycznie
  uznane za wykonane ani zamykane; Issue #106 nadal jest otwartą
  skrzynką problemów produktu, bez nowych komentarzy. Issue #98
  nadal wymaga odrębnego dowodu migracji starego profilu CodeBrowser.

**Statusy obszarów po integracji** (18 obszarów, nie 18 jednorazowych
testów; `BAZA_WDROŻONA` oznacza ograniczoną bazę, nie zakończenie):

| Obszar | Stan | Nowa potwierdzona baza w `master` | Kryteria nadal otwarte |
|---|---|---|---|
| **GA-01** RESET | CZĘŚCIOWO | Statyczna korelacja RESET z wektorami, ograniczony graf wywołań i warunki spójności | Niepełne skoki, analiza międzyfunkcyjna, brak śladu wykonania MCU |
| **GA-02** SIMCR/MM | CZĘŚCIOWO | Możliwe MMIO STORE, nakładanie bajtów SIMCR, 24-bitowe adresy, bounded CALL i stałe po RTS; **w nowym PR**: odrębne konteksty argumentów A/D dla jednego bezpośredniego CALL; **w zależnym PR**: bezpieczny, nieutrwalany łańcuch `CALL → bridge → CALL → MMIO` | Warunki pierwszego wykonanego zapisu / write-once, bardziej złożone wielopoziomowe ścieżki, brak dowodu aktywnego MM |
| **GA-03** pośrednie MMIO | CZĘŚCIOWO | CFG/P-code, indeksowanie, aliasy, bezpieczne unknown STORE, CALL-BARRIER i zgodność ścieżek; **w nowym PR**: potencjalne MMIO według argumentów ustalonych na konkretnym CALL PC (nie globalny Apply); **w zależnym PR**: jedno pośrednie CALL, rozbieżne gałęzie fail-closed i usunięcie A7 na obu granicach wywołania | Dalsze międzyfunkcyjne ścieżki, pośrednie CALL, niepełne dynamiczne aliasy |
| **GA-04** CSBOOT/CS | BAZA_WDROŻONA | Statyczna warunkowa tabela 12 okien z pochodzeniem źródłowym | Więcej konfliktów i wariantów CSPAR/CSOR; brak fizycznej mapy |
| **GA-05** Review/Apply/Undo | BAZA_WDROŻONA | Jawny preflight, bezpieczne zatwierdzanie, transakcje, Ghidra Undo, blokady niepewności | Rozszerzone scenariusze decyzji i uprawnień, bez automatycznego Apply |
| **GA-06** profile MCU | CZĘŚCIOWO | MC68332 wybierany jawnie, manifesty i sprawdzanie fizycznych stron PDF fail-closed | Zweryfikowane kolejne MCU i wydania dokumentacji z dowodami |
| **GA-07** analiza/raport/RAG | BAZA_WDROŻONA | Wersjonowany komplet źródeł, raport statyczny i eksport | Długie scenariusze i dalsza spójność wyników |
| **GA-08** nazwy | CZĘŚCIOWO | Propozycje funkcji, blokada nieaktualnej rewizji Apply, transakcja i Undo | Zmienne lokalne, argumenty i wskaźniki z Review/Undo |
| **GA-09** MMIO Explorer | BAZA_WDROŻONA | Read-only Listing i GUI CodeBrowser na syntetycznej Ghidrze w Actions | Dalsze przypadki GUI i rzeczywista migracja starego profilu (#98) |
| **GA-10** bitfieldy | CZĘŚCIOWO | Wybrane pola MC68332, konsekwentny dowód fizycznej strony i wydania | Pozostałe rejestry i ścisła walidacja pełnego korpusu |
| **GA-11** IRQ/VBR | CZĘŚCIOWO | Źródłowa korelacja wektor–RESET–funkcja i kandydaty ISR; **w PR**: ograniczony odczyt relokowanych tablic źródłowych wskazywanych przez MOVEC-to-VBR (zob. `docs/hardware-relocated-vbr-source-candidates.md`) | Dalsze pośrednie ISR, warunkowa relokacja i brak dowodu aktywnego IRQ |
| **GA-12** analiza przyrostowa | CZĘŚCIOWO | Ukończony CFG w RAM/dysku, per-function restart oraz bounded mid-function worklist przez JVM; SHA pełnego Program/JAR i CALL returns | Trwałość szerszych sesji i decyzji, więcej przerwań i wersjonowania |
| **GA-13** pochodzenie zmian | CZĘŚCIOWO | Rewizja zatwierdzonego Rename, SourceType, rollback/Undo | Trwała historia decyzji, autorów i powiązań zmian |
| **GA-14** firmware diff | ODŁOŻONE | Brak odrębnego porównania firmware | Schemat dowodów, Ghidra Version Tracking i izolowane porównanie |
| **GA-15** Agentic | CZĘŚCIOWO | Niepełne źródła pozostają oznaczone po pruningu findings-cache | Kontrola długich przebiegów, kontekstu i wznowień |
| **GA-16** PDF/RAG | CZĘŚCIOWO | Fail-closed fizyczne strony, wydanie i identyfikowalny dokument | Bardziej kompletne źródłowe korelacje rejestrów z PDF |
| **GA-17** testy/CI | CZĘŚCIOWO | 55/55 PR CI, 22/22 master push CI, realna syntetyczna Ghidra/Xvfb, JSON/JUnit/SHA | Dalsze scenariusze regresyjne, stary profil CodeBrowser #98 |
| **GA-18** automatyzacja | TOR_ZMIENIONY | Automation API v3 + agent CLI, kontrolowane GitHub Actions, CI-first integracja | Pełna autonomiczna orkiestracja i pomiar limitów wymagają osobnej decyzji |

**Niezmienne ograniczenia bezpieczeństwa:** statyczne P-code/Listing/CFG
nie dowodzą faktycznego wykonania RESET, zatrzaśnięcia MM, aktywnego
VBR/ISR ani rzeczywistej mapy magistrali. Generic CPU32 nie dostaje
automatycznie definicji MC68332; Profile/Review/Apply/Undo pozostają
kontrolowane. Dane oryginalnego ECU411, projekt Ghidry, profile i OAuth
nie były dotykane. Historyczne GUI/CUA/headless na Wyse/Precision oraz
worker, Goal i timery Supervisora **pozostają zatrzymane**.

**Następna praca**: konserwatywna analiza GA-02/03/11 przepływów
międzyfunkcyjnych i VBR/ISR; GA-06/10/16 zweryfikowane profile i
bitfieldy z wydaniem/stroną; GA-08/12/13 historia decyzji z Undo oraz
systematyczne pokrycie funkcjonalności przez GitHub Actions.
Nie traktować żadnego GA-01–GA-18 jako zamkniętego tylko dlatego, że
podstawowa funkcjonalność działa.

## Historyczny plan kompozycji — 2026-11-04 (przed scaleniem do `master`)

Kandydat `integration/ga01-ga18-reviewed-20261104` zachowuje oryginalną
historię i źródłowe dowody CI **wszystkich 13 zależnych/niezależnych
PR-ów #118–#130**, bez powielania ukończonych testów.
Punkt wyjścia: chroniony `master` `fda73ad65ff38c1c8030847a74e02a9d56d0afae`.

- Najpierw połączono statyczną analizę MCU `#122 → #123 → #126 → #128`
  z trwałym cache `#124 → #125 → #127 → #129` w PR #130.
  Wersja sygnatury funkcji `GA12-FUNCTION-CFG-FIXPOINT-2`
  obejmuje posortowane `verifiedCallReturns`; zmiana dowodu
  zwracanego rejestru unieważnia zarówno zapisane wyniki, jak i
  niedokończony stan CFG. Dokładny SHA PR #130:
  `21f250507e33c8452830e9438f8170ae954d2e12`;
  38/38 GitHub Actions SUCCESS.
- Następnie na osobnej gałęzi włączono PR **#118** z zależnościami
  RESET → wektory/ISR do wspólnego `GhidraHardwareFlowService`;
  `GhidraInterruptVectorService` dostaje rzeczywisty statyczny
  zbiór osiągalnych kandydatów, nie fałszywy ślad wykonania.
- Pakiety **#119** (zweryfikowane strony PDF, profile, bitfieldy)
  i **#120** (niekompletne źródła wyników Agentic) zachowują swój
  pierwotny zakres i historii SHA bez niepotrzebnych zmian.
- **#121** wymaga zarówno kontroli rewizji `HardwareAnalysisRevision`
  w `Review → Apply`, jak i regresji w tym samym testowym
  `Ga11VectorHeadlessMain`. Zachowano gałęzie `branch-cache`,
  `leaf-return`, `branch-leaf`, `function-stage-resume`
  oraz negatywną asercję `rename_stale_revision_blocked`.

**Brama do `master`:** najpierw otwarty PR integracyjny, następnie
kompilacja rozszerzenia dla Ghidry **12.1.4 PUBLIC / Java 25**,
regresje Java 21, rzeczywista syntetyczna Ghidra headless oraz
istniejące testy Xvfb/CodeBrowser/Automation API na dokładnym
commicie kompozycyjnym. GitHub Actions może wymagać ponowienia
**tylko infrastrukturalnie zablokowanego zadania** (np. Maven HTTP 429),
nigdy przenoszenia PASS z innego SHA. Dopiero po pozytywnych
wymaganych kontrolach i zgodnie z ochroną gałęzi możliwe jest
scalenie zatwierdzonego PR-a.

To nadal **częściowy zakres 18 obszarów**; zwłaszcza analiza RESET,
SIMCR/MM, CS, VBR/ISR i cache daje dowody statyczne, nie
potwierdza wykonania MCU ani fizycznej konfiguracji magistrali.
Issue #106 pozostaje skrzynką problemów produktu; Issue #98
zachowuje osobną lukę migracji starego profilu CodeBrowser.
Przerwane testy i workery Wyse/Precision/Codex Supervisora nie
są uruchamiane.

## Historyczna migawka PR-ów — 2026-11-04 (przed scaleniem #131)

**Stan przed scaleniem #131:** ówczesny `master` na
`fda73ad65ff38c1c8030847a74e02a9d56d0afae`.
Poniższe CI dotyczy **dokładnych commitów gałęzi PR**, nie `master`,
formalnej akceptacji Supervisora ani pełnego zamknięcia GA-01–GA-18.
Wszystkie obszary pozostają CZĘŚCIOWO lub ODŁOŻONE zgodnie z tabelą niżej.

| Pakiet | PR | CI PASS / wszystkie workflow na HEAD | Etap review |
|---|---|---:|---|
| RESET / wektory / ścieżki | #118 | 26/26 | osobny, nakłada się na `GhidraHardwareFlowService` |
| PDF / MCU / bitfieldy | #119 | 13/13 | niezależny |
| Agentic / kompletność źródeł | #120 | 2/2 | niezależny; pełna kompilacja w CI |
| Bezpieczne nazwy względem rewizji | #121 | 24/24 | wymaga dostosowania harnessu przy wspólnej integracji |
| SIMCR overlapping + modulo 24 bit | #122 | 24/24 | fundament GA-02/03 |
| Statyczne skutki CALL (unknown alias) | #123 | 24/24 | po #122 |
| Trwały ukończony etap CFG | #124 | 14/14 | fundament GA-12 |
| Ukończone funkcje w RAM | #125 | 26/26 | po #124 |
| Bezwarunkowe wartości po RTS | #126 | 27/27 | po #123 |
| Trwałe ukończone funkcje po restarcie | #127 | 29/29 | po #125 |
| Wszystkie ścieżki acyklicznego RTS | #128 | 28/28 | po #126 |
| Trwała niedokończona kolejka CFG | #129 | 28/28 | po #127 |

**Zależności:** GA-02/03: `#122 → #123 → #126 → #128`;
GA-12: `#124 → #125 → #127 → #129`. PR **#130** jest
odizolowanym punktem połączenia *obu historii Git*, z nowym SHA-256
`HardwareFunctionStageCache.signature` w schemacie `-2`, który
uwzględnia posortowane `verifiedCallReturns` i odrzuca stare
checkpointy po zmianie podsumowania funkcji wywoływanej.
Pełna integracja wymaga **własnego CI na finalnym SHA**.

**Ważne niekompatybilności do review:** #118 rozszerza wywołanie
`GhidraInterruptVectorService.analyze` i musi zostać zgodnie złączony
z interproceduralnym `GhidraHardwareFlowService`; #121 wymaga
`HardwareAnalysisRevision` przy Apply nazw i modyfikuje ten sam
syntetyczny harness `Ga11VectorHeadlessMain`. Nie wolno pomijać tych
zmian przez proste zastąpienie pliku.

**Tryb testowania:** tylko GitHub Actions na Ghidrze 12.1.4 PUBLIC
i Javie 21/25. Historyczne timery, GUI/CUA/headless na Wyse/Precision
i natywny Supervisor są zatrzymane decyzją właściciela. PR #98
zachowuje osobny brak testu migracji starego CodeBrowsera;
Issue #106 pozostaje otwartą skrzynką usterek (brak nowych zgłoszeń).
W chwili tej historycznej migawki `master` pozostawał niescalony;
wynik wdrożenia opisano w bieżącej sekcji wyżej.

## Stan historyczny — 2026-11-03, po integracji do `master`

**Punkt odniesienia:** `master` na commicie
[`2596a5a00e272720a091bc92209b00fb2edffefd`](https://github.com/bogkom/GhidrAssist/commit/2596a5a00e272720a091bc92209b00fb2edffefd).
To **aktualna ocena implementacji i dowodów**, nie zastąpienie historycznej
tabeli „Audited baseline 2026-10-28” ani zmiana statusu wcześniejszych testów.
Roadmapa ma 18 *obszarów*, a nie 18 jednorazowych testów.

**Słownik:** `BAZA_WDROŻONA` = główna, ograniczona funkcjonalność jest już
w `master` i ma regresje; **nie** oznacza pełnej realizacji wszystkich
kryteriów. `CZĘŚCIOWO` = istnieje kod i/lub testy, ale pozostają wymienione
wymagania. `ODŁOŻONE` = zakres celowo poza bieżącym priorytetem.
`TOR_ZMIENIONY` = historyczny workflow został zastąpiony, a nowa
operacyjna automatyzacja nie ma jeszcze pełnej akceptacji. **Żaden z
18 obszarów nie jest tu formalnie oznaczony jako zamknięty w całości.**

| Obszar | Aktualny stan | Potwierdzony zakres w `master` | Co pozostało / kryterium domknięcia |
|---|---|---|---|
| **GA-01** RESET i inicjalizacja | **CZĘŚCIOWO** | Wektor RESET, ograniczony graf wywołań i źródłowe hipotezy osiągalności | Bardziej kompletna analiza międzyfunkcyjna, niepewne skoki/wyjątki; nie nazywać osiągalności wykonaniem |
| **GA-02** SIMCR/MM i epoki rejestrów | **CZĘŚCIOWO** | Źródłowe STORE, możliwe lokalne pierwsze zapisy, warunkowe SIMCR/TRAMBAR/CS/VBR | Spójne stany ścieżek między funkcjami, nieznane efekty i ograniczenia MM write-once; bez twierdzeń o zatrzaśniętym MM |
| **GA-03** pośrednie MMIO / P-code | **CZĘŚCIOWO** | Bounded CFG/P-code, lokalne rejestry adresowe, aliasy i konserwatywne nieznane STORE | Pełniejsze indeksowanie/aliasy i bardziej zaawansowane przepływy międzyblokowe/międzyfunkcyjne; brak fizycznej mapy |
| **GA-04** CSBOOT i CS0–CS10 | **BAZA_WDROŻONA** | Warunkowa, 12-wierszowa tabela okien i bezpieczne dekodowanie CS | Weryfikacja nietrywialnych warunków CSOR/CSPAR, źródeł i konfliktów na dodatkowych przykładach; nie twierdzić, że okna są aktywne |
| **GA-05** Review/Apply/Undo | **BAZA_WDROŻONA** | Jawne zatwierdzenie, preflight, izolowane transakcje/Undo, blokady niepewnych CS | Dalsza akceptacja zaawansowanych scenariuszy na kopiach; polityka zapisu API w produkcji pozostaje wyłączona |
| **GA-06** profile MCU | **CZĘŚCIOWO** | Audyt źródeł MC68332, preview TSV, kontrola PDF SHA i porównanie *deklaracji* profili | Zweryfikowany import kolejnych MCU z wydaniem/manualem/bitfieldami; preview nie rejestruje urządzenia |
| **GA-07** Analyze/raport/RAG | **BAZA_WDROŻONA** | Trzyczęściowe Overview, Full Evidence i wersjonowany eksport | Sprawdzać spójność nowych analiz, skróty i kompletne dowody, bez podwójnego liczenia |
| **GA-08** propozycje nazw | **CZĘŚCIOWO** | Preview, bezkolizyjne zatwierdzane nazwy *funkcji* w jednej odwracalnej transakcji; źródłowe podpowiedzi A-register | Zmienne lokalne, argumenty i wskaźniki oraz ich niezależny Review/Undo; nie nadpisywać nazw ręcznych |
| **GA-09** MMIO Explorer | **BAZA_WDROŻONA** | Filtracja MMIO/Go To Listing, read-only z ochroną przed zmianą programu | Poszerzenie klasyfikacji i doświadczenia użytkownika na kolejnych wariantach danych |
| **GA-10** bitfieldy | **CZĘŚCIOWO** | Udokumentowane wybrane pola SIMCR z literalnych pełnych słów MC68332 | Pozostałe rejestry/pola, wydania i zerowe/nieznane reset values; bez dopisywania bitów bez źródeł |
| **GA-11** IRQ/VBR | **CZĘŚCIOWO** | Statyczny spis kandydatów wektorów i odróżnienie exact-entry od wnętrza funkcji | Analiza VBR/przemieszczenia tablic i zależności ISR; bez dowodzenia aktywnego IRQ |
| **GA-12** analiza przyrostowa | **CZĘŚCIOWO** | Identyfikacja rewizji Program, anulowanie, cache gotowego etapu CFG w bieżącym procesie | Trwałe checkpointy i wznowienie po restarcie, częściowe per-funkcja resume; kontrola unieważnienia |
| **GA-13** pochodzenie zmian | **CZĘŚCIOWO** | Aktualny Ghidra SourceType, preflight, lokalne CSV i ochrona eksportu | Rzeczywista trwała historia autorstwa zmiana→decyzja→Undo; SourceType nie identyfikuje człowieka/AI |
| **GA-14** porównywanie firmware | **ODŁOŻONE** | Brak porównywania dwóch firmware; istniejące porównanie *manifestów MCU* to GA-06 | Najpierw schemat raportu i Ghidra Version Tracking; potem bezpieczne różnice CS/VBR/peryferiów |
| **GA-15** Agentic | **CZĘŚCIOWO** | Istniejące Query/Agentic, ograniczanie kontekstu, polityki i wyniki źródłowe | Domknięcie długich przebiegów, cache/paginacji/przekazań oraz ocena regresji bez dublowania narzędzi |
| **GA-16** PDF/RAG | **CZĘŚCIOWO** | Strony fizyczne, niejednoznaczne folio, ostrożny odczyt kandydatów tabel, ograniczenia rozmiaru | Wiarygodne ekstrakcje tabel pól/offsetów z wersją źródła; odrębna walidacja strony drukowanej |
| **GA-17** testy / CI | **CZĘŚCIOWO** | 12.1.4 PUBLIC + Java, syntetyczne Ghidra/CodeBrowser/Xvfb, rollback i pakiety SHA | Niezależne testy zgodności starych przeniesionych profili, wybrane kopie ECU411 i dowody specyficzne dla nowych funkcji |
| **GA-18** Supervisor / automatyzacja | **TOR_ZMIENIONY** | Integracja opt-in Automation API v3, CLI, agent launcher; 10/10 wybranych testów Dell Precision, bez nowej pracy Supervisora | Zaprojektować API-first automatyczne wykonanie i raportowanie; historyczne GUI/headless Supervisora pozostają zatrzymane decyzją właściciela |

**Weryfikacja integracji:** PR
[#114](https://github.com/bogkom/GhidrAssist/pull/114),
[#115](https://github.com/bogkom/GhidrAssist/pull/115) i
[#116](https://github.com/bogkom/GhidrAssist/pull/116) są scalone;
końcowe `master` przeszło **11/11 workflow push SUCCESS**, w tym
[Ghidra 12.1.4 full build](https://github.com/bogkom/GhidrAssist/actions/runs/41694253605).
Wcześniejsze **10/10 wybranych hostowych testów Precision** dotyczyło
wyłącznie syntetycznego programu i określonego API — nie jest zaliczeniem
18 obszarów. Exact-head PR #114/#115/#116 miały odpowiednio
12/12, 13/13 i 14/14 CI SUCCESS; ich wyników nie należy przepisywać na
inne commity. `Issue #106` jest pustą otwartą skrzynką problemów,
a [Issue #98](https://github.com/bogkom/GhidrAssist/issues/98) zachowuje
osobną lukę testu migracji *starego profilu* użytkownika.

**Decyzja testowa 2026-10-31:** natywne GUI/CUA i headless timery
Codex Supervisora na Wyse zostały decyzją właściciela zatrzymane;
nie wolno zakładać ich ponownej aktywacji. Rozwój ma preferować
deterministyczne testy rzeczywistej Ghidry przez GitHub Actions/Xvfb
i nowe opt-in Automation API, z odrębnymi kategoriami dowodu
`CI`, `host-synthetic`, `manual-GUI`, `Supervisor-PASS`
i `INCONCLUSIVE/BLOCKED`.

**Priorytety dalszej realizacji:** (1) GA-01/02/03/11 — dokładniejsze,
ale nadal *statyczne* przepływy MCU; (2) GA-06/10/16 — weryfikowalna
wiedza o rejestrach; (3) GA-08/12/13 — bezpieczna edycja i trwałość;
(4) GA-14 — dopiero po zamknięciu schematów dowodów i akceptacji.
GA-17/18 to **metoda testowania wszystkich tych zadań**, a nie
osobna obietnica, że samo API automatycznie je zaimplementuje.

---

## Immutable engineering rules

- Ghidra target: **12.1.4 PUBLIC**, baseline for this work: `fix/hardware-analyze-focused-report-20261028`, commit `412448166ec5d9cc3750ee10d1ec215804ae5802` (draft PR #52), which itself builds on `codex/agentic-policy-and-evidence-fixes`. Do not substitute old `master` as a new-feature baseline without reconciling these changes.
- Preserve independent draft PRs #48–#50 and their local unpushed work. Reconcile overlap and obtain verification before closing or merging.
- **Static reachability ≠ execution**. Instruction-address order ≠ runtime order. MM may be write-once. Unknown call side effects and aliases must invalidate unjustified value claims.
- MCU-dependent information is conditional on a **manually selected, documented device**, never silently inherited by generic CPU32.
- Analyze is compact. Detail/uncertainty belongs in dedicated views; complete register catalog and explicit, undoable changes belong in Review / Apply.
- Public repository and Actions must never contain ECU411 firmware or its Ghidra project. On-host test copies only. Test artifacts contain non-sensitive summaries/hashes.
- GitHub Actions first; Supervisor plans pinned to immutable full 40-character commits. **Standing owner authorization for standard GA-01..18 local tests is already active on Wyse**, with revocable, fail-closed Supervisor policy; no new per-plan approval is necessary. Tests run only inside the approved dedicated test Goal/workspace, never a new Codex programming session.

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
| GA-18 | 17 + new decision | GitHub-controlled multi-stage local Supervisor tests | OPERATIONALLY ACTIVE on Wyse as of 2026-10-29; PR #9 GitHub integration still open; real tests PR #53/#54/#55 PASSED | Pinned JSON, active standing authorization, quota safeguards, verified private reports |

## Dependency order and milestones

1. **Foundations/compatibility**: GA-17/GA-18, reconcile PR #48–#52 without disrupting installed #52; map existing Java APIs and tests.
2. **Reliable memory evidence**: GA-04 (initial deterministic table), GA-02/GA-03 (path state), GA-10 (bitfields), GA-05/GA-06 (device-scoped definitions). No false dynamic maps.
3. **Reset-rooted analysis**: GA-01, GA-11 and their prerequisites; then GA-07 combines initialization/history/map without dumping all registers.
4. **Investigation and safe edits**: GA-09, GA-08, GA-13; independent transactional and GUI regressions.
5. **Documentation and agent workflows**: GA-16, GA-15, GA-12; retain report provenance and avoid model token use for deterministic checks.
6. **Later comparison**: GA-14 after a stable report schema and Ghidra Version Tracking evaluation.

Each milestone: focused Java tests -> exact 12.1.4 extension build on GitHub Actions -> immutable candidate commit -> queue plan in private Supervisor repo -> fail-closed execution under the **already active standing owner authorization** -> verified isolated-Ghidra regression -> review and merge. A queued or artifact-verified plan is not PASS. Do not merge on planned rather than observed test results.

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
