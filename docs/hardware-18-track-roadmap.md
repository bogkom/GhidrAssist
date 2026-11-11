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

The check is bounded and does **not** re-run the full CFG solver when
restoring a completed checkpoint. It can catch value-level lies that
pass an externally recomputed SHA-256 and the structural guards, but
the recorded predecessor register lattice and MMIO state from other
predecessors are not independently re-derived. Consequently neither
a completed checkpoint nor a partial intermediate worklist is treated
as authenticated proof of its writer or of full value-propagation
correctness. Partial worklists continue to be unpublishable until
normal solver convergence; the existing strict exact-input fingerprint,
typed bounds, rooted CFG and epoch/revision gates remain mandatory.

Deterministic Java 21 tests use only synthetic CPU32 source graphs
including indexed signed `D1.W * 2`, verified post-RTS `A0/D0`,
direct/unknown/partial MMIO STORE, `MOVEC` constant/register and
modulo-24 address wrap. Every hostile completed snapshot is written
inside a deliberately **rehashed, exact-key durable envelope** and
must fail `load` even with a valid checksum; a rejected `save`
must not overwrite prior valid evidence. Both the combined GA-02/03 +
GA-12 and durable per-function Java21 workflows run the adversarial
suite. GitHub Actions retains full Java25 Ghidra 12.1.4 PUBLIC
extension builds and actual isolated synthetic Ghidra headless
integration. No private ECU411 firmware, original Ghidra projects,
user profiles, OAuth, or stopped Wyse/Precision/Supervisor work
is involved. GA-02/03/12/18 remain PARTIAL; GA-14 deferred.

## GA-02/03/12/18 — 2026-11-10: deterministic bounded CALL source traversal and CFG-bound durable evidence

The read-only `HardwareInterproceduralMmEffects` solver now canonicalizes
each function's direct-CALL target adjacency by unsigned nonnegative
function entry before allocating its finite shared exploration budget.
Target duplicates remain representable but cannot consume extra unique
scheduled nodes. Previously the subset selected under an exhausted
node/edge budget could depend on incidental Ghidra reference enumeration:
a visible static SIMCR/MM MAY candidate might appear or disappear even
when the graph and maximum budget were identical. Canonical ordering makes
the bounded source inventory reproducible across insertion orders; its
sorted address priority does **not** assert caller invocation order,
branch feasibility, runtime SIMCR writes or active MM. Source nodes omitted
by the depth, function or batch limits are still `UNKNOWN/LIMITED`,
never negative hardware evidence.

GA-12 opt-in per-function durable fixed points and intermediate worklists
now undergo **independent semantic source-binding validation** after the
existing exact full-Program / Ghidra Listing / installed extension JAR
input fingerprint, deterministic Step hash, and disk envelope SHA-256
checks. This validates a bounded CFG rooted at the exact function entry
and the set of **statically source-reachable** instruction PCs.
Every decoded complete fixed point must match the number of reachable
source nodes, each STORE/VBR instruction's exact PC/kind/width/register,
the full set of reachable effect sites, pointer-state PCs, and the
24-bit modeled register/MMIO/VBR range. Each intermediate worklist node
and pending PC must also be a source-reachable CFG node, including when a
synthetic disconnected Step is present in the same function inventory.
Both `load` and `save` fail closed, so locally rehashed but semantically
contradictory records cannot masquerade as valid cross-JVM source evidence
or replace a valid disk slot. No `ObjectInputStream`, AI runtime model,
global database transaction, review token or new mutation API is added.

Java 21 deterministic regression covers reversed and duplicate CALL
target adjacency under a tight budget, positive/omitted MAY evidence,
cold versus resumed verified post-CALL register-to-MMIO paths,
correctly keyed durable restores and forged VBR-for-STORE, wrong width,
off-graph PC, disconnected graph node, impossible 24-bit register/MMIO,
and internally inconsistent reached-node counts. It also recomputes the
outer **valid** SHA-256 for deliberately inconsistent binary snapshots:
checksums prove integrity, **not** authorship or causal truth. Existing
GitHub Actions Java 25 full extension build and isolated synthetic Ghidra
12.1.4 PUBLIC headless tests remain the native integration gates.
Any native CFG changes occur only on generated synthetic data in CI;
no ECU411 firmware, original Ghidra projects, user profile, OAuth or
stopped Wyse/Precision/Supervisor process is involved. GA-02/03/12/18
remain PARTIAL and GA-14 remains deferred.

## GA-01/02/03/11/18 — 2026-11-10: MC68332-only RESET source address gate and independent initial SSP evidence

The existing static image-zero CPU32 RESET vector reader keeps its
legacy 32-bit PC interpretation when **generic CPU32** is selected.
With an **explicit MC68332** profile, an even decoded RESET PC above
`0x00FFFFFF` no longer automatically becomes a Ghidra RESET
function root or a direct-CALL / MMIO / MOVEC / ISR reachability
inventory. The complete high source value is preserved in the report
as **UNKNOWN RESET ROOT — SELECTED MC68332 24-BIT SOURCE BOUND**.
This is deliberately **not** silent `& 0xFFFFFF` address
normalization: physical alias/remapping and actual execution are
unknown. Normal 24-bit source-vector roots continue to work.

The **image-zero vector/ISR inventory** uses the same explicit
MC68332-only 24-bit scope as the previously verified relocated
VBR source-table scanner: a 32-bit pointer outside MCU24 remains
visible as `OUTSIDE_SELECTED_MCU24_RANGE` and is NOT upgraded
to a recognized handler, even if Ghidra maps a 32-bit CPU32
address. Generic CPU32 retains the wider source interpretation.
The pre-existing read-only `HardwareInterruptVectors` classification
is reused, rather than creating a second contradictory vector
counter. Source-only RESET reachability, VBR selection and any
ISR execution remain UNKNOWN.

The initial SSP is now separately classified as an **unsigned
32-bit source word**: null/erased, odd (a possible alignment
risk), aligned but memory-unverified, candidate one-past-the-24-bit
top (`0x01000000`, a potential downward-growing stack edge),
or outside selected MCU24 context. None of these categories
proves a mapped stack, a valid firmware image, RESET execution,
SIMCR/MM state or ISR activity. An anomalous SSP alone does
**not** discard a source-valid PC candidate. CPU32 generic
retains its wider addressing model.

Hardware sources: Motorola/Freescale `MC68332TS/D` Technical
Summary, **Rev. 2**, section 3.4.3, printed **page 27
(PDF page 27)** identifies `ADDR[23:0]`; section 3.4.11,
printed **page 29 (PDF page 29)** documents misaligned
word/long-word transfers. Original:
https://www.nxp.com/docs/en/data-sheet/MC68332TS.pdf .
The Motorola/Freescale `MC68332UM` User's Manual (1995/
Freescale 2004), sections 5.2 and 5.3, printed pp. 5-2
to 5-6, documents distinct 32-bit SSP/PC and CPU32 memory
model. Sources support **static constraints only**, not a
measurement of ECU wiring or runtime memory mapping.

Java21 deterministic regressions include a 32-bit high PC
distinguishing generic CPU32 from MC68332, erased/odd stack,
one-past device edge, wider stack context, and ordinary
MC68332 source. The existing genuine synthetic Ghidra
12.1.4 PUBLIC Java25 headless tests invoke the production
Analyze path for the normal RESET and image-zero vector inventory.
Two independent existing headless fixtures temporarily change only
their own synthetic vector high bytes: RESET PC source-root gating
and image-zero ISR vector 26 (`OUTSIDE` for selected MC68332
vs `UNMAPPED` for generic CPU32). Both restore original bytes
and retain the source-only guarantees. Full extension
build plus existing hardware source regressions remain
mandatory. No ECU411 firmware, original user Ghidra
projects, OAuth or stopped Wyse/Precision/Supervisor
workers are accessed. GA-01/02/03/11/18 remain PARTIAL;
GA-14 remains deferred.

## GA-18 — 2026-11-10: bounded Automation bearer-session and JSON-RPC wire identity

The external `ghidrassist-agent` now reads at most 16 KiB of its
locally selected JSON session receipt, rejects duplicate/Unicode-escaped
keys, malformed/noncanonical schema and port types (including Boolean,
floating-point and quoted ports), out-of-range port and malformed
Bearer token. Launcher-specific receipt metadata remains supported;
a locally edited receipt does **not** authorize writes, review
approval or model continuation. The active loopback JSON-RPC client
also rejects ambiguous duplicate response keys, non-finite JSON
numbers, non-object replies and responses >1 MiB, including valid
JSON followed by excessive trailing whitespace. Request JSON rejects
NaN at serialization instead of sending a nonstandard wire value.
The HTTP transport remains bound to `127.0.0.1` with existing Bearer
authentication; no remote endpoint is introduced.

The `ghidrassist-agent-start` launcher independently bounds and
checks existing session and readiness receipts (16 KiB), refuses
duplicate-key/NaN ambiguity, validates exact integer pid/port/schema
before trusting readiness and limits bootstrap RPC replies to 1 MiB.
The existing no-takeover policy for live processes, isolated
synthetic-only write consent and review-copy safeguards remain
unchanged. Strictness applies to local receipts and read-only wire
result interpretation; it does not create a new global Ghidra
transaction or prove that the remote process executed hardware code.

Python 3 tests exercise actual client/launcher modules with
deterministic synthetic receipts and mocked loopback HTTP, covering
valid minimal and extended sessions, duplicate escaped aliases,
malformed credentials and ports, overlong replies, nonfinite values,
and safe normal status. GitHub Actions runs these tests in the GA-18
launcher and GA-12/15 Agentic paths, plus complete Java25 Ghidra
12.1.4 PUBLIC extension and isolated actual synthetic CodeBrowser/
JSON-RPC regression triggered by changing the CLI. No original ECU411
firmware, user Ghidra projects, OAuth secrets or stopped
Wyse/Precision/Supervisor processes are accessed. GA-18 remains
PARTIAL; GA-14 remains deferred.

## GA-12/13/15/18 — 2026-11-10: unambiguous offline checkpoint JSON parsing

The previously merged offline provenance readers for four historical
checkpoint forms — bounded hardware source-pair inventory, single
hardware report, coherent three-format report set, and retained Agentic
evidence — now share a strict JSON decoder. At **every nesting level**
it rejects duplicated object keys (including a Unicode-escaped alias),
non-standard NaN/Infinity constants, floating exponents that overflow
to non-finite values, oversized integer/float tokens and malformed or
over-recursive input. Previously, Python's last-key-wins default could
accept a receipt containing contradictory serialized authority,
Program identity or completeness claims, **even with the exact
original SHA-256 unchanged** when the benign duplicate key was last.
This fix protects local historical evidence interpretation; it is not
a signature or source-authentication system.

Python3 adversarial tests capture actual CLI-written synthetic
checkpoints in all four formats, verify their unchanged compatibility,
then inject serialized duplicate authority/Program/completeness keys,
escaped aliases, rehashed NaN/Infinity and oversized ignored row
numbers. Both the GA-12 source/publication and GA-12/15 Agentic CI
lanes run the new tests, alongside the normal Java25 full extension
build and real Ghidra 12.1.4 PUBLIC synthetic CodeBrowser test triggered
by the CLI change. No production firmware, original user Program,
OAuth or stopped Wyse/Precision/Supervisor worker is involved.
GA-12/13/15/18 remain PARTIAL, GA-14 remains deferred.

## GA-08/12/15/18 — 2026-11-10: coherent three-report snapshots and Apply/Undo stale-token retirement

`analysis.report.manifest` is a new explicitly read-only,
empty-arguments-only Automation API v3 method. It reads a single
completed Ghidra Analyze state on the Swing EDT and emits one
versioned manifest for **all three** independent report products:
`markdown`, `config_csv` and `names_csv`. It binds exact Program
path, imported source SHA-256, Ghidra modification counter, opaque
analysis revision, selected CPU32/MC68332 profile and current GA-12
stage epoch to each format's own UUID generation, UTF-16 character
length and full UTF-8 SHA-256 digest. No server-side file write,
Analyze, Review, Apply or AI tool is performed by this query.

The external CLI supports:
`ghidrassist-agent report-set-checkpoint --output FILE --page-size N`
and offline
`ghidrassist-agent report-set-verify --input FILE`.
The capturing client compares the same manifest **before** fetching
all three formats and **after** a final terminal-page check for each.
Every intermediate HTTP page must match the manifest's Program,
revision, stage, profile, UUID and length. The concatenated content
for each section must independently match the manifest's UTF-8
SHA-256, with page offsets counted using Ghidra's UTF-16 units.
All three data sections and the read-only provenance are written
as **one** bounded, private, atomically published, SHA-256 checked
no-overwrite local JSON envelope. The total file cap is 7.5 MB.
No partial report-set file is published after failure. Offline
verification rejects missing formats, changed content, unknown
fields, incorrect counters and even locally rehashed forged Apply
or AI-resumption flags. SHA-256 proves file integrity, **not**
authenticated authorship or past firmware execution.

Automation API `hardware.apply.commit` and `hardware.apply.undo`
now also retire the completed hardware source/report epoch and
generation immediately after each successful synthetic/attested
working-copy mutation. Even if a Ghidra Undo/Redo transaction later
restores the original bytes or a revision-like value, an old report
cursor never becomes valid without a new explicit Analyze. This
does not add a Redo RPC or authorize new writes. Direct changes
from other Ghidra plugins still rely on the existing
Program/revision/stage-current checks.

The Java21 + Python3 deterministic regression covers an intentionally
mixed Analyze/Undo/Redo-like generation sequence, edits between
formats, changed identities and content, a transition after the
last body page, no-overwrite, truncated/forged reports and offline
verification. The real synthetic Ghidra 12.1.4 PUBLIC Java25
CodeBrowser/Xvfb + bearer JSON-RPC/CLI test publishes a three-format
read-only receipt, verifies it in an unrelated CLI process and
checks denial after Program switching, same-input reanalysis and
**actual safe Apply and Undo**. It does not claim that an actual
Ghidra Redo was exercised unless a separate native regression
explicitly confirms it. No original ECU411, user projects,
OAuth or stopped Wyse/Precision/Supervisor tests are touched.
GA-08/12/15/18 remain PARTIAL; GA-14 deferred.


## GA-08/12/15/18 — 2026-11-10: strict Review indices and atomic multi-page report receipts

Remaining mutating UI selectors `hardware.review.prepare`,
`hardware.apply.prepare` and `ui.table.select` now use one
**required** canonical, nonnegative JSON integer `row`/`index`
contract, with a conservative 0..4096 upper bound before accessing
Review, authorization or the Swing table. String-encoded numbers,
fractions, scientific notation, Boolean/null, containers, negative
values, 32-bit overflow and missing indices fail closed, before any
approval token can be minted. Target-specific list bounds and all
existing Review/Apply/Undo/copy authorization remain in force.
The CLI also preflights the same `--row` range.

The standalone `ghidrassist-agent report-checkpoint --output FILE
--format markdown|config_csv|names_csv --page-size N` now captures
a **complete read-only report**, not a resumable action, across many
real Automation API v3 `analysis.export` calls. It validates on
every page the exact scan UUID, opaque report revision, numeric
Ghidra Program revision, active project Program path, import SHA-256,
explicit CPU32/MC68332 profile, stage epoch, total UTF-16 code units,
page offsets, size and `more` flag. A final end-of-report request
with the same exact revision/generation refuses late Program change
or fresh Analyze before publication. Output is capped (1 MiB of
UTF-16 content, 2.5 MB encoded file), locally atomic, private,
SHA-256 integrity checked, and exclusive/no-overwrite. Failure or
stale evidence creates **no** final file. The separate offline
`report-checkpoint-verify --input FILE` checks field types,
complete/static-only scope, source counters and payload SHA; it
cannot authenticate historical author identity, AI state, Review
approval or Apply permission.

Deterministic Python 3 regression covers complete multi-page
capture, final sentinel, same-Program stale generation, changed
project identity/revision/epoch/content, incomplete pages, tampering,
forged authorization, UTF-16 and no-overwrite. CI's true Ghidra
12.1.4 PUBLIC Java25/Xvfb CodeBrowser/JSON-RPC suite adds 36
invalid `row`/`index` authenticated server requests and a real
native multi-page CLI report capture, offline verify after capture,
and duplicate-save rejection. Existing full Java25 extension,
Java21, GA-12 durable checkpoint and synthetic GUI workflows remain
required. This is **not** a global lock on Ghidra across separate
HTTP calls; the final cursor check protects observed changes up to
that check, not mutations after it. No private ECU411, production
Ghidra project/profile/OAuth or stopped Wyse/Precision/Supervisor
session is used. GA-08/12/15/18 remain PARTIAL; GA-14 deferred.


## GA-12/15/18 — 2026-11-09: typed page bounds and scan-bound hardware report exports

The Automation API v3 paginated endpoints now use one strict
`AutomationRpcPagination.pageInt` validator for both `offset` and
`limit` rather than Gson's permissive `getAsInt()`. Requests with
quoted numbers, fractions, exponent notation, Booleans, null,
containers, negative values, 32-bit overflow or an endpoint's own
page-size/offset budget are refused **before any Listing, ReAct,
Decompiler, MMIO, XREF, CALL path or hardware report read**. The
existing endpoint-specific limits (including Decompiler's legitimate
zero-length status probe) remain intact. An unbounded offset on a
cheap textual report is still limited to Java's nonnegative int range;
this does not authorize an unbounded response.

Hardware `analysis.report` and `analysis.export` now use separate,
ephemeral **UUID generations for each report format**, minted on
every completed Analyze even when imported firmware bytes and the
Ghidra modification number have not changed. Each first page
contains `revision`, `generation`, `stage_epoch`, `profile`,
`program_path`, `import_sha256` and the existing bounded static
content. For nonzero offsets the client must echo the EXACT previous
opaque revision as a JSON string and generation as a UUID string.
The GUI tab refuses different format, new scan, changed Program,
profile, source epoch, or stale revision before and after collecting
the read-only page. The CLI exposes
`--expected-report-revision` plus existing
`--expected-generation` for report/export follow-on pages.
The old unbound HTTP page continuation is intentionally refused;
initial offset-zero requests remain compatible.

The real Ghidra 12.1.4 PUBLIC / Java25 / Xvfb / Bearer JSON-RPC
CodeBrowser smoke tests perform hundreds of deterministic type/bounds
refusals across real paginated methods. They also verify end-of-report
pages with exact cursor, format isolation, source-pair bounds, and a
stale report refusal after Program switch and **fresh Analyze of the
same Program with the same revision**. The independent actual
synthetic CodeBrowser/Agentic test checks retained findings selector
bounds; full extension build, Java21 and ongoing CI remain required.
No user Program, private ECU411, OAuth or stopped local Wyse/Precision
and Supervisor workers participate. Static evidence is never actual
executed MM/VBR/ISR or Apply authorization. GA-12/15/18 remain
PARTIAL; GA-14 remains deferred.


## GA-12/15/18 — 2026-11-09: exact wire-format cursor identity for hardware and Agentic pagination

The pre-existing stage-epoch, active Program and findings-run guards
are preserved, but Automation API v3 now validates `expected_revision`,
`expected_program_revision` and `expected_findings_revision`
as **canonical, nonnegative, in-range, unquoted JSON integer numbers**.
Strings that resemble numbers, fractions, exponent representations,
Booleans, null, arrays, objects, leading zeros, negative values and
64-bit overflow do not silently coerce to a permitted Ghidra revision.
Hardware source-pair `expected_generation` and Agentic
`expected_run` must be genuine UUID-formatted JSON strings, rather
than arbitrary scalars or nonstring values.

For nonzero offsets, the actual HTTP Listing page requires the
prior Program revision; whole-function XREF pages require both
Program revision and function entry; hardware JSR/MOVEC pages
require revision and exact generation; Agentic findings pages require
Program revision, findings revision and exact run UUID. The CLI now
preflights the Listing/XREF requirements. The read-only Listing and
function-body XREF collectors verify the Program modification number
again **after** collecting page rows. Agentic likewise rechecks the
active Program/epoch after obtaining the retained page. A valid
cursor is NOT a completed analysis/Apply permission or a claim of
executed CALL/MM/VBR/ISR.

The real synthetic Ghidra 12.1.4 PUBLIC CodeBrowser/Bearer JSON-RPC
tests exercise dozens of negative requests across all four endpoints,
plus existing positive same-Program pagination, stale revisions,
different Program and stage-epoch invalidation. These are actual
production server requests, not a simulated HTTP validator.
Existing full Java25 extension builds, Java21 host assertions,
isolated CodeBrowser/Xvfb and GA-12 JVM restart regressions remain
the acceptance path. No private ECU411, original Ghidra projects,
OAuth or stopped Wyse/Precision/Supervisor workers. GA-12/15/18
remain PARTIAL, GA-14 deferred.


## GA-12/13/15/18 — 2026-11-09: strict JSON-RPC binding identity and late Program-session guard

The already merged GUI/API sidecar creation functionality from #259 is
hardened without changing its opt-in scope, bearer authentication,
synthetic/attested review-copy authorization, local-only destination
or Review/Apply separation. `agentic.review.binding.create` now requires
a **canonical, unquoted, nonnegative JSON integer** Program revision
in 64-bit range. JSON strings, fractions, exponent notation, negative,
Boolean, null, arrays, objects, leading zeros and overflow cannot be
coerced via Gson `getAsLong()`. The expected import identity must be
exactly 64 hexadecimal SHA-256 digits, with an exact Ghidra project
Program path. Unknown request fields (including attempted tool/Apply
approval) are rejected, instead of being silently ignored.

The production Java save helper now optionally accepts a live
`BooleanSupplier` which must remain true before expensive
fingerprinting and immediately before sidecar publication. GUI binds
it to active Program object/revision, same Query session and no
task/pending plan. Automation binds it to active Program and revision
plus the operator's opt-in property; an in-flight Program switch,
revision change or feature revocation cannot publish a stale sidecar.
This witness supplements the existing repeated full-input
fingerprints, checkpoint-byte identity, exclusive no-overwrite and
persisted Program identity; it does not grant authorization.

The true Ghidra 12.1.4 PUBLIC CodeBrowser Bearer JSON-RPC CI
executes over 20 invalid identity/authority-shaped requests and
requires HTTP 400 with **no sidecar file**. The real isolated
synthetic Ghidra Java25 restart suite additionally simulates a
Program/session switch deterministically between full scans and
the final exclusive link, proving fail-closed nonpublication.
Original evidence, firmware and saved project are untouched.
The sidecar remains a read-only integrity/provenance receipt;
later Program changes fail at the existing strict import/review
gate, and no old model/session/Apply permission is inherited.
GA-12/13/15/18 remain PARTIAL; GA-14 deferred. No local
Wyse/Precision/Supervisor worker was resumed.


## GA-12/13/15/18 — 2026-11-09: gated creation of full-Program-bound Agentic Review evidence

The previously integrated optional `Import Bound Checkpoint` path
is complemented by explicit `Create Bound Checkpoint` on the real
Query-tab GUI, with source file, NEW destination, new objective,
MC68332/CPU32 choice and human confirmation. Background fingerprint
scans must not freeze Swing EDT or auto-submit an analysis.

Automation API v3 also offers the explicitly disabled-by-default
`agentic.review.binding.create` operation: Bearer authorization PLUS
operator opt-in, synthetic-only or separately authorized isolated
review-copy write policy, exact Program path/import SHA/revision,
bounded objective/profile and one safe filename inside an already
configured local sidecar directory. No arbitrary paths, symlinks,
overwrite, firmware writes, inherited old model, tools or Apply.

The source file is checked before, after and at sidecar publication;
the same is true of the full persisted Program/Listing fingerprint.
A deterministic real Ghidra 12.1.4 PUBLIC synthetic TaskMonitor
changes bytes **during** this inspection and must refuse both
historical Review load and binding publication. The two-independent-
JVM Xvfb/CodeBrowser/JSON-RPC/CLI lane checks actual GUI creation
and authenticated server output after re-opening the Program,
including missing consent, SHA/revision/auth/path/refusal.
The checkpoint and manifested evidence remain statically observed
and untrusted: SHA is not an author's signature, no saved grant
or old approval transfers. GA-12/13/15/18 remain PARTIAL.


## GA-12/13/15/18 — 2026-11-09: opted-in bound Review in actual CodeBrowser

The GA-12 full Program/Listing + source + project + installed analyzer
fingerprint binding from #257 is now wired to a **separate, explicitly
selected** Query-tab `Import Bound Checkpoint` GUI action. The operator
chooses both local source checkpoint and local schema-1 sidecar, and
explicitly chooses `CPU32 generic` or `MC68332` (never inferred).
Asynchronous background fingerprinting prevents Swing EDT stalls.
The original import route remains available as **unbound historical
data**, never implicitly considered provenance-verified.

The real controller refuses replaced Program objects, revised Program
contents, changed chat session, running queries and pending plans
while a binding is checked; it reuses the existing new-chat-only
`stageImportedAgenticDraft` contract: no inherited session grants,
Accept All disabled, read-only tool budget 8, no reused plan,
no automatically started AI/Apply, independent new Submit and
Approve Plan required. No local sidecar or checksum constitutes actor
authentication, past execution, or original analysis-state proof.

An existing two-independent-JVM real Ghidra 12.1.4 PUBLIC /
CodeBrowser Xvfb / deterministic native ReAct / Bearer JSON-RPC CI
lane now writes a local binding in the first JVM and uses the
real **Swing controller entrypoint** after reopening the synthetic
Program in the second JVM. It asserts the button is installed,
fresh chat and read-only policy appear, no Program revision changes
or new model run are triggered, plus wrong Program, wrong MCU and
modified checkpoint fail closed. Existing GUI and CLI regression
checks remain active. No production ECU411 firmware, user project,
OAuth or stopped Wyse/Precision/Supervisor workers. GA-12/13/15/18
remain PARTIAL, GA-14 remains deferred.


## GA-12/13/15/18 — 2026-11-09: full Program-bound saved Agentic Review across JVMs

An additional **explicit opt-in** Java helper creates a local read-only
sidecar that binds a historical complete Agentic evidence checkpoint
and new objective to the existing GA-12 complete input fingerprint,
not merely the old firmware import SHA or transient modification
number. It covers the actual persisted Ghidra Program identity,
Listing, memory, functions, references and installed analyzer build,
with explicit MC68332/CPU32 selection. Only an unchanged Program may
reload this untrusted historical Review source in a fresh JVM;
any change to bytes, function name, imported source file, project
identity, profile or sidecar/checkpoint contents refuses the binding.
Both captures around the read must agree.

A private 0600 create-no-overwrite sidecar records only versioned
identity digests, objective and explicit **false** approval/Apply/
tool/model-restoration flags. This is **not** an approved Review
token, not a true old AI session or an actor signature; source
evidence must still be independently reviewed. It neither changes
existing GUI policy nor silently activates this opt-in binding for
historical legacy files. The real synthetic 12.1.4 PUBLIC Java25
CI repeats the existing three CFG JVMs and nine source JVM phases,
including a saved/reopened unchanged binding, synthetic function
rename, edited byte, different selected MCU, byte-edited source
checkpoint and no-overwrite. Java21/Python and normal extension
regressions remain mandatory. No ECU411, private Ghidra project,
user profile/OAuth or stopped local worker is accessed. GA-12/13/
15/18 remain PARTIAL; GA-14 remains deferred.


## GA-12/13/15/18 — 2026-11-09: bounded rooted Agentic checkpoint ancestry and Review handoff

The previous Agentic history supported only adjacent parent-child
checkpoint verification. New `agentic-lineage-chain-verify` performs
bounded **2–16** checkpoint root-to-leaf checks with exact source
SHA-256, every digest/parent run edge, complete retained evidence,
no repeated run or checkpoint, original imported firmware identity,
and a deterministic SHA-256 chain digest. The root must be unlinked;
a valid isolated pair is not proof that an older multi-run history
has no missing ancestors. This is an integrity/provenance claim
only, **not** authenticated actor identity or model/session replay.

A checkpoint with ancestry may now seed only a **fresh, unapproved**
Review draft, and only when all ancestors are explicitly supplied
oldest first (`--ancestor` repeated) and the chain remains unchanged
across the existing live Ghidra Program/Agentic evidence preflight.
New review drafts record bounded ancestry depth and digest;
`AWAITING_NEW_REVIEW`, no old plan, no tools, no Apply, and no
inherited authorization remain mandatory. Root checkpoints preserve
the existing Review draft path without `--ancestor`.

Python3 deterministically covers three generations, missing,
skipped or reversed links, wrong firmware, rehashed forged nodes,
repeated run, over-limit history, race and no live session, including
false-complete and no inherited approval gates. The existing actual
synthetic Ghidra 12.1.4 PUBLIC Java25 two-JVM CodeBrowser/JSON-RPC
ReAct test now also verifies the *rooted two-entry chain offline
after both Ghidra processes exit*; it does not claim that this test
ran a third native Agentic investigation. GitHub Actions exact
SHA gates include full extension compile and source-specific
regressions. No private ECU411, user Program, OAuth, stopped
Wyse/Precision or Supervisor processes. GA-12/13/15/18 remain
PARTIAL, with GA-14 deferred.


## GA-12/18 — 2026-11-09: V2 RESET inventory cross-counters and source completeness separation

A typed `GA12-CFG-REPORT-2` checkpoint now requires the **full
RESET-visited function set** in the CFG report to equal its independent
JSR/MOVEC `SourceInventory.resetVisited` set. Duplicate CFG RESET
entries and otherwise byte-valid, SHA-256-resealed disagreement are
invalid provenance, not trustworthy completed hardware evidence.
The existing root-recognized and CFG-incomplete flags must still
match. Original historical V1 CFG-only reports remain compatible,
without fabricated JSR/MOVEC source pages.

`eligibleForCompletedRestore` still means the completed **CFG stage**
passes its existing safety gates (review completeness, no CFG/pointer
omissions, no stage limit). Independent
`eligibleForCompleteSourceInventory` now refuses V1/absent sources,
unknown RESET root, incomplete RESET graph, omitted JSR/MOVEC sources
and explicitly uncertain source witnesses. This is a bounded observed
input classification only, never execution, MM/VBR/ISR or Apply proof;
valid partially observed source inventories remain restorable as
static **INCOMPLETE/UNKNOWN** and are not misclassified as corrupt.

Java21 adversarial tests cover duplicated and mismatched RESET
counters, byte-valid mutated V2, interrupted CFG and separate source
completeness. The real Ghidra 12.1.4 PUBLIC Java25 isolated
cross-JVM harness retains its three original CFG phases and extends
to eight typed V2/V1 source phases: cold write, same-input read,
resealed invalid JSR, resealed mismatched RESET, checksum-valid
but incomplete CFG, legacy V1 CFG-only, changed Program bytes,
and generic CPU32 profile refusal. Both malformed and incomplete
checkpoints must trigger **fresh analysis**, not publication of
a misleading completed stage. No private firmware, Ghidra project,
profile, OAuth or stopped Wyse/Precision/Supervisor workers used.
GA-12/18 remain PARTIAL.


## GA-12/18 — 2026-11-09: strict V1/V2 evidence decoding and semantic restore refusal

The typed GA12-CFG-REPORT-1/2 decoder now rejects **noncanonical
Boolean encodings** (only 0 or 1 accepted) and **malformed UTF-8**
(no silent replacement characters in provenance). V2 source inventory
RESET-recognized/incomplete flags must agree with the parent CFG
snapshot. The constructor enforces consistency before persistence,
and decode enforces it again on untrusted bytes before restore.
Malformed source coordinates (odd/out-of-range computed JSR, duplicate
PC) are refused by existing typed SourceInventory validation.
A correctly SHA-256-wrapped disk checkpoint is never mistaken for
proof that its *content* is semantically valid.

A Java21 adversarial suite changes canonical flags, injects invalid
UTF-8 into V1 and V2, creates conflicting RESET summary flags,
and mutates a serialized indirect JSR PC. The real Ghidra 12.1.4
PUBLIC Java25 isolated test extends the completed three-JVM CFG
plus five-JVM V1/V2 restore lane with a sixth V2 phase: it wraps a
semantically impossible odd JSR PC in a **valid exact full-input
disk-store digest**, then requires the restored V2 to be rejected
and fresh synthetic CFG recomputation. Cold/valid V2, legacy V1
CFG-only and stale Program/profile denial remain mandatory.

Importantly, **observed source inventory incompleteness** (unknown
indirect JSR or omitted MOVEC witnesses) remains visible and tagged
INCOMPLETE/UNKNOWN; it is not equated with corruption and never
becomes proof of missing hardware actions. Only corrupted or
internally contradictory checkpoint provenance is refused.
No production firmware, Ghidra projects/profiles, secrets or
stopped local Wyse/Precision/Supervisor testing lanes are touched.
This does not prove executed CALL, active MM/VBR/ISR, or Review/Apply
permission. GA-12/18 remain PARTIAL.


## GA-01/02/03/11/12/18 — 2026-11-09: real cross-JVM V2 source report restore, V1 conservative migration

An additional GA-12 acceptance lane expands the existing **three**
independent actual Ghidra 12.1.4 PUBLIC Java25 CFG restart processes
with **five independent JVMs** operating on a SECOND isolated,
byte-exact CPU32 RESET/JSR/MOVEC synthetic Program. A real Ghidra
headless bootstrap disassembles each source witness and creates the
same five defined functions used by the native-source tests; only
this disposable synthetic project is saved.

The V2 phases verify cold computed (source-write), exact same-input
reopen (source-read), historical GA12-CFG-REPORT-1 legacy restore
(source-v1), changed synthetic byte input (source-edit) and generic
CPU32 without explicit MC68332 selection (source-profile). The
full analysis-input fingerprint is independently captured in each
new JVM, including Program/Listing, imported SHA, language, selected
profile and extension identity. The V2 read must be **reused** with
both typed JSR/MOVEC source pairs and the unresolved JSR omission
count preserved; an in-place changed byte must yield a different
full-input hash and **recompute**, without reusing stale evidence.
Selecting CPU32 generic instead of MC68332 must not restore or
publish device-specific source rows. The historic V1 snapshot is
written under the same exact existing disk key for the isolated
fixture; it may restore CFG evidence only and MUST NOT synthesize
missing JSR/MOVEC witness pages. V2 inventory incompleteness is
still explicit, never promoted to complete firmware coverage.

CI requires the distinct true synthetic Ghidra bootstrap PASS
marker and **all eight independent JVM phase JSON receipts**,
plus full Java25 extension build. No AI model, host Supervisor,
running worker, Wyse/Precision project, original ECU411 firmware,
user profile or OAuth secret participates. Results are per exact
PR commit; merely decoding V1/V2 bytes in Java21 is not a substitute
for this real Ghidra restart check. Safety interpretation remains
static-only, not executed JSR, latched SIMCR/MM, selected VBR/ISR,
hardware address map or Review/Apply approval. GA-01/02/03/11/
12/18 remain PARTIAL; GA-14 remains deferred.


## GA-01/02/03/11/12/18 — 2026-11-09: real CodeBrowser RPC source pages, V2 durable source inventories

The previously merged bounded source-pair API now has an
isolated genuine Ghidra 12.1.4 PUBLIC Swing/CodeBrowser/Xvfb
**end-to-end JSON-RPC** acceptance path. Its THIRD synthetic
CPU32 Program uses the exact same source bytes, Listing disassembly,
Ghidra functions and branch-separated RESET/JSR/MOVEC witness
positions validated by the native headless regression:
RESET direct function 0x130, computed JSR 0x138 to SIMCR/MM
candidate 0x180 and MOVEC 0x144 in a different CFG arm; an
independent 0x200 function has computed JSR 0x206 before MOVEC
0x208. A disconnected unresolved JSR (A1) at 0x240 is an
UNKNOWN source and must increase omitted witness count, never
erase the two established pairs.

The native CodeBrowser scenario caught a stale-generation regression:
switching from synthetic Program A to B and then back to A could
reuse the old completed UI evidence because the Program modification
number had not changed. GhidrAssistPlugin.programActivated now
invalidates the departing Program's HardwareFlowStageCache and
HardwareEvidenceCache; HardwareAnalysisTab.currentScan requires
its exact stage epoch for **all** reports, including generic CPU32
and legacy-restored reports. This prevents old JSR/MOVEC page cursors,
checkpoint-derived CFG evidence and previous GUI report exports from
reviving across a CodeBrowser context switch. The API's existing
unsaved-Program switch refusal stays in force; the isolated native
fixture saves ONLY its synthetic Ghidra bootstrap before switching.

The real CodeBrowser test exercises authenticated production
`hardware.source_pairs.page` over HTTP: explicit generic CPU32
refusal; MCU-selected first, second and end pages; deterministic
source PCs and omitted counts; 400 for missing next-page
revision/generation, incorrect revision, forged generation, and
over-limit requests; stale cursor refusal after Program switch
and a new completed analysis with a different generation. The
actual installed `ghidrassist-agent` also assembles the two
pages into a local versioned, no-overwrite SHA-256 checkpoint and
verifies it after the Ghidra process has exited, with tampering
denied. The original synthetic MMIO Program is restored and
tested by all existing GUI regressions. No private firmware or
real user project is involved.

**GA-12 typed CFG report payload version 2**
(`GA12-CFG-REPORT-2`) optionally retains a complete, bounded,
immutable source inventory, including exact indirect-JSR/MOVEC
witnesses, RESET entries, omitted counts and source flags. The
outer disk store still uses its existing exact full-input
fingerprint, analyzer identity, per-program private path and
integrity digest. The decoder *explicitly accepts* legacy
`GA12-CFG-REPORT-1` as a typed completed CFG report but with
`sourceInventory=null`: no source-pair API output is reconstructed
from historic text/Markdown. V2 source inventory, if present, is
strictly bounded by the 64/32 source caps and rejects malformed,
truncated, unknown-future and oversized data. V2 correctly
reconstructs the same source evidence after a valid exact-input
disk restore. A valid V1 restored report is still eligible for
its original safe CFG fixed-point result, but **not** for source
pagination, and never for Review/Apply.

CI requires the full Java25 Ghidra build, real synthetic CodeBrowser
with Bearer HTTP and actual installed CLI, Java21 V1/V2 binary
roundtrip and legacy compatibility, and deterministic SHA-256 local
snapshot checks. This is CI synthetic GUI success, NOT manually
observed Wyse/Precision or formal Supervisor PASS. The evidence
is static only: no proof of executed JSR/return, MM latch, selected
VBR/ISR, or physical mapping. GA-01/02/03/11/12/18 remain PARTIAL,
and GA-14 is deferred.


## GA-01/02/03/11/12/18 — 2026-11-09: revision-bound Automation source pages and versioned local checkpoint

Completed, explicitly MC68332-selected Hardware Analysis now retains
the **bounded immutable** CPU32 indirect-JSR/MOVEC source inventory
(max 64 indirect witnesses, 32 MOVEC sites, 2048 pairs). Automation
API v3 adds authenticated, read-only `hardware.source_pairs.page`,
returning at most 32 stable, deterministically ordered pair rows,
total pair count, omitted/unknown source counts, RESET relation,
source SHA, Program modification revision, completed-report generation
token, and GA-12 stage epoch. Page offsets are valid only within the
SAME in-memory Program revision and generation; subsequent page
requests require both the expected revision and expected generation.
Explicit checkpoint clear also invalidates the cursor without a
Program modification. The API never creates a direct CALL edge,
invokes an AI model, approves Apply or claims runtime SIMCR/MM/VBR/ISR.

Data comes ONLY from the actual successful production flow analysis,
passed through the completed Hardware Inventory into the UI; the
source inventory is intentionally not serialized by legacy GA-12
durable CFG report snapshots. If only an old durable report was
restored, pagination fails with SOURCE_INVENTORY_NOT_RETAINED instead
of parsing Markdown, creating invented provenance or publishing
incomplete evidence as if complete. Ordinary report export and
first-page Markdown retain backward compatibility.

`ghidrassist-agent source-pairs` fetches one page. The new explicit
`source-pairs-checkpoint --output <local path>` reassembles all
bounded source pages under the exact server-supplied revision and
generation. It writes only a local atomic create-no-overwrite JSON
envelope with versioned kind, original import SHA, stage epoch,
row counts, omitted counts, source flags and SHA-256 of canonical
payload. Offline `source-pairs-verify --input <path>` refuses
tampering, duplicate/unsorted rows, inconsistent counts and
false-complete source claims. The JSON is a **read-only provenance
snapshot**, not a Ghidra saved Program, a resumable CFG checkpoint,
a source of Apply approval or a cross-revision cursor. Missing
source SHA and omitted/unknown source witnesses cannot claim
complete evidence.

Acceptance requires Java21 source and native Ghidra 12.1.4 PUBLIC
Java25 extension CI. Native synthetic CPU32 report tests inspect
both source pages from the exact production Report, require all
existing RESET/JSR/SIMCR/MOVEC relations and explicitly retire the
stage epoch without revising the Program. Python deterministic
CLI tests cover page stitching, race, changing generation/revision,
incomplete inventory, no-overwrite and checksum tampering. This
does not restore private ECU411 firmware, user Program, profile,
OAuth or suspended Wyse/Precision/Supervisor tests. GA-01/02/03/
11/12/18 remain PARTIAL; GA-14 remains deferred.


## GA-01/02/03/11/12/18 — 2026-11-09: complete bounded joint-source pagination

The production RESET / byte-witnessed JSR / conditional MM MAY / MOVEC
co-location used to expose at most the first 32 joined pairs. This
package adds an explicit **bounded, immutable, deterministic offset /
limit page API** for the existing pure-Java source-join solver. The
old inspect(...) entry point remains the first page (offset 0), so
existing report clients and native CPU32 headless evidence continue
to work. Each returned page includes total observed pair count,
selected input source counts, omitted indirect/MOVEC evidence,
page offset/limit/nextOffset and hasMore. The full pair count and
omitted counts must NEVER be reduced to the visible row count.
No page caches all candidate pairs; it enumerates only the bounded
64 indirect x 32 MOVEC source inventory, at most 2048 pairs, and
materializes at most 32 output rows. The cursor denotes a source
ordering within one Program/revision only; it is not a cross-revision
durable resume token or proof that omitted or unknown sources are
absent.

Deterministic Java21 regression stitches all 64 pages of 32 pairs,
checks no duplicates or gaps, first/middle/final/out-of-range
windows, omission counts, uncertain RESET source, input order
invariance, cap rejection and immutable rows. Page markdown is
rendered under HardwareJointSourcePublication's entry/exit
identity/revision/epoch fence; changing the Program revision during
rendering or invalidating the stage refuses the entire page. The
existing Ghidra 12.1.4 PUBLIC native synthetic same-Program
RESET/JSR/MM/MOVEC test also verifies that production Markdown
has first-page metadata with exact count and no phantom next page.
This is not a claim that external Automation API clients can yet
request arbitrary pages: wiring page requests into that API and
versioned durable GA-12 checkpoint provenance remain later work.

Safety: synthetic CI only; no original ECU411, private project,
profile, OAuth, runtime MM latch, selected VBR, ISR execution,
physical chip-select mapping, automatic Apply, or stopped
Wyse/Precision/Supervisor test worker. GA-01/02/03/11/12/18
remain PARTIAL and GA-14 is deferred.


## GA-01/02/03/11/12/18 — 2026-11-09: native Ghidra in-flight revision refusal and unproven JSR inventory

An isolated, byte-exact CPU32 synthetic Program extends the already
verified production RESET/direct-CALL/byte-proven indirect JSR/SIMCR-MM/
MOVEC-to-VBR source report with a disconnected unknown JSR (A1) at
0x240. This decoded computed CALL has **no** bounded MOVEA source
proof. It must increase the joint source report's omitted/UNKNOWN
indirect witness inventory while preserving the two independent
byte-proven JSR/MOVEC source pairs. It never creates a direct CALL
edge, proves lack of MMIO writes or changes the original firmware.

After the production report's ordinary generic CPU32 refusal,
selected MC68332 source join, RESET subset and branch/CFG tests, the
**same native 12.1.4 PUBLIC GhidraScript** runs production Analyze
twice with a TaskMonitor proxy that makes a committed, comment-only
revision edit to the *isolated synthetic Program* after respectively
one and twelve actual monitor checkpoints. A new Ghidra transaction
updates the real Program modification number while the analysis is
in progress; a Java-only synthetic revision token is insufficient.
The production method must reject both edits with STALE_REVISION
or fail-closed cancellation and never return a partial Report.
GitHub Actions requires the distinct native
"GA18 REAL JOINT REVISION REFUSAL PASS: injected=2 unresolved=1"
marker in addition to the existing full same-Program source evidence
PASS marker. This is an integrated interruption regression,
not a formal Wyse/Precision/Supervisor host PASS.

Safe scope: synthetic fixture only; no ECU411 image, production
Ghidra Program, user profile, credentials, OAuth, Review/Apply or
stopped local testing. The static source report does not infer
executed JSR, actually latched SIMCR/MM, active VBR/ISR or a
physical hardware mapping. Exact-PR-head full Java25 extension
build, Java21 source regressions where triggered and real synthetic
headless Actions are required before merging. GA-01/02/03/11/12/18
remain PARTIAL; GA-14 remains deferred.


## GA-01/02/03/11/12/18 — 2026-11-09: atomic full-report revision safety after RESET/JSR/MOVEC source reconciliation

The real-Ghidra RESET/direct-CALL/byte-witnessed indirect-JSR/SIMCR-MM/
MOVEC-to-VBR production report from merged #247 previously checked
Ghidra Program revision at selected CFG/CALL analysis stages but did
NOT fence **the complete final Markdown report** at publication.
An analysis edit, native Undo/Redo, imported source identity change,
explicit MC68332 profile transition, Program switch or stage cache
invalidation after a previously accepted row could otherwise leave
stale RESET, JSR, MMIO or MOVEC locations in output.

A bounded read-only HardwareJointSourcePublication now captures an
identity-bound HardwareAnalysisRevision and process-local function
stage epoch once at the start. The source-join publication checks
this exact revision before and after rendering; the complete final
report, after source evidence/CSV/roles have been assembled, checks
the same revision again on entry and exit. A stale epoch/revision
throws STALE_REVISION; no partially rendered markdown or returned
Report is made available, and no stale report is persisted as
GA-12 checkpoint. Explicit invalidation is recognized even when
Program modification number stays constant. No Apply authorization,
storage schema, source import or user Program is changed.

The prior source join also omitted unresolved/unproven computed CALL
sites from its incompleteness count; those sites now contribute to
the reported unresolved/omitted indirect inventory so that source
silence cannot be mistaken for a complete negative MMIO conclusion.
The existing 32-pair display bound, independent VBR site-count
limits, RESET subset distinction, unknown/partial CFG route safety,
and static-only interpretation are retained.

Java21 deterministic acceptance forces edits at renderer entry
and exit, same-name/different Program, original source SHA and
language changes, device selection changes, explicit stage epoch
retirement, late Undo/Redo-style revisions, and a controlled
two-sample race after source text construction; every failure
discards the whole report rather than leaving earlier source rows.
Exact SHA full Ghidra 12.1.4 PUBLIC Java25 extension build and
existing genuine synthetic same-Program RESET/JSR/MOVEC headless
test remain mandatory. No ECU411 firmware, user project/profile,
OAuth or stopped Wyse/Precision/Supervisor worker touched.
The gate protects evidence freshness, not real instruction execution,
latched MM, active VBR/ISR, physical chip selects or Review/Apply.
GA-01/02/03/11/12/18 remain PARTIAL, GA-14 deferred.


## GA-01/02/03/11/18 — 2026-11-09: real same-Program RESET / byte-witnessed JSR / MOVEC source correlation

The native CPU32 Listing CFG fixture from #246 verified Ghidra's
instruction flow with representative addresses, but not the **whole
production source join**. This package adds an exact isolated CPU32
binary with a plausible image-zero RESET PC at 0x100, an exact direct
JSR to function 0x130, byte-proven MOVEA.L #0x180,A0 + JSR (A0)
at 0x132/0x138, and a separate MOVEC D0,VBR at 0x144. A decoded
BNE/BRA diamond places the JSR and MOVEC sites in mutually exclusive
static arms. The synthetic indirect target at 0x180 contains a
literal source candidate STORE to MC68332 SIMCR 0xFFFA00.
A second independent function at 0x200 contains an indirect JSR
at 0x206 and a MOVEC at 0x208 in a forward CFG path but is **outside**
the bounded observed RESET direct-call subset. Both source functions
share the same indirect target; they do not create new RESET edges.

The new native headless GhidraScript reads original opcode words,
validates decoded instructions, exact Function bodies and real Listing
branch successors, then uses the actual packaged GhidrAssist JAR to
call production GhidraHardwareFlowService.analyze on the **same**
synthetic Program in generic CPU32 and explicitly selected MC68332
modes. The generic-device report must refuse MCU-specific claims.
The selected report must preserve two distinct same-function source
pairs, the RESET-subset distinction, MAY-to-MM source classification
and separate CFG relations NO_OBSERVED_ORDERED_ROUTE and
POSSIBLE_JSR_BEFORE_MOVEC. GitHub Actions requires a native PASS
banner after the complete Java25 extension build and preceding
synthetic tests. Existing independent Java21 and hardware gates remain
applicable. No alternate toy implementation supplies the production
join output.

A static JSR path does not prove an executed call or return;
branch separation is not a runtime proof; a source MMIO write does
not establish latched MM, and MOVEC does not establish selected VBR,
ISR activity, physical chip-select map, or Review/Apply entitlement.
The synthetic data is not ECU411 firmware. No production Ghidra
project, profile/OAuth or stopped Wyse/Precision/Supervisor test
worker is modified. GA-01/02/03/11/18 remain PARTIAL; GA-14 deferred.

## GA-01/02/03/11/18 — 2026-11-09: real Ghidra CPU32 branch/cycle CFG source-route acceptance

The Java21 pure CFG site-order regression already covers diamond and
loop models; the previous native Ghidra source fixture only required
presence of the production report heading. This package adds an
**independent byte-exact isolated CPU32 binary** with BNE/BRA
branch-separated instruction paths, a backward conditional loop,
a linear path, and an unresolved JMP (A0). A Java GhidraScript
calls Ghidra 12.1.4 PUBLIC's actual DisassembleCommand, verifies
original opcode bytes, decoded Listing mnemonics and instruction
lengths, and extracts real getFallThrough/getFlows() successors.
Those decoded edges are passed to the **actual packaged extension
JAR's** HardwareCfgSiteOrder (not a copied test implementation),
with assertions on branch separation, forward/reverse reachability,
cyclic bidirectional reachability, incomplete Listing and unreachable
computed jump targets. The extension build Actions job requires
an explicit PASS banner from that headless process and fails closed
on any reported test exception or missing banner.

The new synthetic image cannot prove JSR and MOVEC **execution**:
the selected test PCs are representative sites for graph-order
classification, and the independently tested production report
continues to require explicit MC68332 selection and byte-proven
indirect JSR / MOVEC sources before attempting a real same-function
join. The CFG order relation never creates a direct CALL edge,
RESET execution claim, active SIMCR/MM, selected VBR, ISR or
Review/Apply authorization. The synthetic binary has no private
firmware or user data. Acceptance is exact-head Java21 source checks,
full Ghidra 12.1.4 PUBLIC Java25 extension compilation, real
headless CPU32 fixture and existing hardware/GA-12 safety gates.
No user Ghidra projects/profiles/OAuth or stopped Wyse/Precision/
Supervisor jobs touched. GA-01/02/03/11/18 remain PARTIAL,
GA-14 deferred.


## GA-01/02/03/11/18 — 2026-11-09: bounded same-function JSR/MOVEC CFG route evidence

The source-only indirect-JSR ↔ MOVEC-to-VBR same-function report now
adds a **separate** static instruction CFG order annotation based on
actual Ghidra Listing successors. Distinct source sites receive one
of POSSIBLE_JSR_BEFORE_MOVEC, POSSIBLE_MOVEC_BEFORE_JSR,
POSSIBLE_BOTH_ORDERS, NO_OBSERVED_ORDERED_ROUTE or UNKNOWN. The
bounded graph refuses incomplete decoding, missing or unreachable
source PCs, off-graph edges, duplicate PCs, unmodeled computed jumps,
CALLOTHER, outside-function jumps, truncated dataflow, over-budget
functions and out-of-domain nodes. A computed JSR itself remains a
CALL barrier with only **potential** fallthrough; neither call return
nor any hardware side effect is established. Site co-location remains
independent from CFG order; no indirect RESET edge is invented.

The Java21 deterministic tests cover branch-separated sites, forward
and reverse paths, loops, incomplete/unreachable/malformed CFG,
source-list immutability, 24-bit bounds and the 1500-node cap. The
existing real synthetic Ghidra 12.1.4 PUBLIC RESET/VBR script now
requires the new source-only CFG section in the device-selected
production report, plus generic CPU32 profile refusal. Acceptance:
exact final SHA Java21 test, full Java25 Ghidra extension build,
and genuine synthetic headless GitHub Actions. This is NOT evidence
of executed instruction order, active MM, selected VBR, active ISR,
physical device mapping or Review/Apply entitlement. No original
ECU411 firmware, user projects/profile/OAuth or stopped
Wyse/Precision/Supervisor tests touched. GA-01/02/03/11/18 PARTIAL;
GA-14 deferred.


## GA-01/02/03/11/18 — 2026-11-09: bounded RESET / indirect SIMCR-MM / MOVEC-VBR co-location

The production hardware flow previously emitted independent static
`HardwareIndirectMmMay` and MOVEC-to-VBR source-table sections,
but could not show whether a **byte-proven indirect JSR MAY-to-SIMCR
source** and an independently decoded **MOVEC-to-VBR source** were
located inside the **same function** in the observed bounded RESET
direct-CALL subset. A new pure-Java,
`HardwareResetIndirectVbrCorrelation` source-only join renders exact
per-instruction identities, possible indirect target, candidate
source-image VBR base, and whether the containing function belongs
to the observed RESET direct-call subset. It is wired into
`GhidraHardwareFlowService` only after explicit MC68332 selection,
using the existing same-Program indirect MM and VBR inventories,
without creating or changing any CALL edge.

**Critical evidence limit:** co-location in one function does not
prove a feasible CFG path between the instructions, their execution
order, an executed indirect JSR, a prior SIMCR write, the latched MM
state, a selected VBR, hardware IRQ/ISR or any Apply permission.
The two potential effects stay separate, even if both are source
candidates within a function linked by RESET graph membership.
UNKNOWN/partial CFG sources and an unrecognized RESET root remain
explicit. An invalid/missing candidate VBR table base is UNKNOWN.
Every class/result is immutable and bounded (64 indirect inputs,
32 MOVEC inputs, 32 displayed pairs); missing source records,
overflow and truncated displays carry explicit incompleteness
rather than negative conclusions. Unaligned/odd indirect JSR or
target identities from the broader byte-witness inventory are counted
as omitted/UNKNOWN instead of crashing the entire hardware Analyze.
Generic CPU32 yields a clear not-evaluated profile gate.

The independent deterministic Java21 regression covers same-function
pairing, unrelated source exclusion, independent observed/unknown
RESET membership, unknown MM source and VBR, competing candidate
pairs, complete vs clipped evidence, duplicate instruction-site
refusal, 24-bit source scope and illegal PC/owner coordinates.
Acceptance requires exact final PR SHA Java21 workflow, full Ghidra
12.1.4 PUBLIC Java25 extension build, and real synthetic Ghidra
headless hardware/RESET/CPU32 regressions on GitHub Actions.
Original ECU411 firmware, production Ghidra projects, local profiles,
OAuth and stopped Wyse/Precision/Supervisor tests untouched.
GA-01/02/03/11/18 remain PARTIAL; GA-14 deferred.

## GA-01/02/03/11/18 — 2026-11-09: RESET-aware bounded MOVEC/VBR source-image scan priority

When more than three distinct static MOVEC-to-VBR candidate bases
were recognized, the GA-11 read-only table planner previously scanned
the **lowest numeric bases**. This could omit the candidate from a
known static RESET direct-call subset solely because an unrelated
source image contained lower numerical table addresses.

The planner now preserves the same strict **three-table** and
**32-displayed-site** bounds, but ranks each DISTINCT candidate base
by the best available source site: observed bounded RESET direct-call
subset before outside/unknown sources; within each relation, complete
local MOVEC source context before incomplete CFG/unknown prior CALL.
Equal ranks use ascending address for deterministic output, and
multiple MOVEC sites referencing one base share the best (minimum)
rank. Unknown RESET roots cannot supply privileged RESET membership.
This is a **scan-budget heuristic only**, NOT a claim that the CPU
executed RESET, that a MOVEC write selected a particular VBR, that
the ISR/IRQ is active, or that its hardware effects occurred.

A MOVEC source site must also have an even function entry and
instruction PC inside the selected MC68332 24-bit source domain,
and its instruction PC cannot precede its declaring function entry.
Malformed source ownership fails closed before any table is scanned.
Existing Ghidra vector classification, VBR source-image reading,
24-bit table-end and SIMD/MMIO controls are unchanged.

Java21 deterministic regressions cover five candidate table bases
under a three-table budget, duplicate best-source ranking, unknown
RESET root, incomplete CFG and prior-call uncertainty, independent
display/table bounds and malformed MOVEC source ownership. Exact
final SHA acceptance requires the focused Java21 VBR test, complete
Ghidra 12.1.4 PUBLIC Java25 extension build, and real synthetic
RESET/VBR/ISR/CPU32 headless GitHub Actions regression. No original
ECU411 firmware, production Ghidra project, user profile/OAuth or
stopped Wyse/Precision/Supervisor worker touched. GA-01/02/03/11/18
remain PARTIAL; GA-14 deferred.

## GA-02/03/11/18 — 2026-11-09: require independent outer CALLs for two-hop MMIO agreement

The read-only two-hop CPU32 pipeline (sampled outer CALL → verified
acyclic bridge → exact inner CALL → leaf STORE) now requires **at least
two distinct complete outer CALL PCs** before returning
`SAMPLED_AGREEMENT`. This applies both to the public whole-sample
inspector and to each exact bridge/leaf/STORE cohort independently.
Previously one completely decoded outer CALL could be classified as
cross-CALL agreement even though no second call supplied corroborating
source context. Singleton cohorts now return `INCOMPLETE` with no
approved address/word/bit width, while preserving bounded source-only
provenance; a different bridge's independent pair cannot lend its
caller count to the singleton bridge.

The deterministic Java21 regressions cover a one-caller exact bridge
and leaf, global and scoped inspectors, a mixed three-caller inventory
with one singleton bridge and another independently agreeing pair,
and the production Markdown representation. Existing divergent,
branch-convergent, pagination, source-identity, revision, stack A7,
RESET/ISR and Ghidra synthetic tests remain mandatory. The new
restriction does **not** upgrade any sampled result into execution
proof, active SIMCR/MM, physical CS mapping, active relocated VBR/ISR,
or Review/Apply entitlement. The source register solver, native
Ghidra Listing and transactional checkpoints are unchanged. Require
exact final SHA Java21 workflow, full Ghidra 12.1.4 PUBLIC Java25
extension build and relevant actual synthetic headless Actions.
GA-01/02/03/11/18 remain PARTIAL; GA-14 remains deferred. No
original ECU411 firmware, user Ghidra project/profile/OAuth or
stopped Wyse/Precision/Supervisor workers touched.

## GA-02/03/12/18 — 2026-11-09: atomic revision-bound cross-CALL source report

The existing one-hop sampled CALL-site reconciliation continues to
require a distinct complete source row for every sampled caller at the
same callee and exact STORE PC; no new execution or MMIO certainty is
inferred. A single complete CALL now explicitly returns `INCOMPLETE` instead
of `SAMPLED_AGREEMENT`: at least two distinct direct caller sites are
required for a cross-CALL assertion, including for direct API callers
outside the production Markdown renderer. Previously its Markdown renderer validated the live Ghidra
Program revision separately around each row but could keep an earlier
known address/word if the Program changed after that row, including
the early return at the bounded display cap.

The whole cross-CALL Markdown publication now checks the captured
`HardwareAnalysisRevision` on entry and **again immediately before
returning all text**, including the clipped-display case. A changed
Program identity, modification number, MCU profile, language or source
SHA discards **all** sampled source locations, provenance, address and
word; the renderer returns only a `STALE_REVISION` refusal. No stale
report section can be promoted into a GA-12 checkpoint or trusted
hardware conclusion by a partial earlier row. The existing per-row
checks remain in place. Deterministic Java21 regression forces an edit
after successful source reconciliation and at the report-cap branch;
both must erase all address and STORE evidence. An unchanged report
retains the explicit `INCOMPLETE DISPLAY` marker.

Acceptance: exact-HEAD Java21 reconciliation tests, full Ghidra
12.1.4 PUBLIC Java25 extension build and applicable genuine synthetic
GitHub Actions regression. This protects report publication; it
does not prove executed CALL/RESET, active MM, physical bus mapping,
VBR/ISR activation or permission to Review/Apply. No ECU411 firmware,
user Ghidra projects/profiles/OAuth or stopped Wyse/Precision/
Supervisor workers touched. GA-02/03/12/18 remain PARTIAL.

## GA-06/10/16/18 — 2026-11-09: SIM D-2 source-backed register byte offsets and access

Following the source-only SIMCR/SYNCR bit-diagram and mask verification,
ten further SIM register rows are now correlated with the independently
inspected **MC68332UM Table D-2** on Appendix D-4/PDF218 and its
D-5/PDF219 continuation. This addresses the non-bitfield profile gap:
seven previously `UNVERIFIED` register-source metadata entries now
carry concrete physical folio and source `S`/ `S/U` access classes
for SYPCR, SWSR, PORTE0, DDRE, PFPAR and CSPAR0/1. Existing
CSBAR0, CSBAR8, CSOR8 remain included as source-page boundary
witnesses, but no active chip-select mapping is asserted.

The reviewed table uses **aligned 16-bit row addresses** for both
16-bit registers and registers occupying the **lower byte**.
SYPCR is physically `0xFFFA21` in row `$YFFA20`; SWSR
`0xFFFA27` in row `$YFFA26`; PORTE0 `0xFFFA11` in row
`$YFFA10`. The new pure-Java, bounded, read-only
`HardwareSimD2RegisterWitness` keeps these identities separate,
checks width and profile access class, and matches each register
name after its **own** row address on the claimed physical page
before the next address, including wrapped SYPCR text.
Missing/shifted PDF page and changed profile claims return
incomplete instead of a trusted address.

The existing publisher-NXP CI first validates immutable PDF
SHA-256 and total 265 physical pages and then verifies ten
Table D-2 rows from exact PDF pages 218/219; independent
Java21 tests cover bad row association, wrong pages,
unbounded inputs and low-byte addresses. Full Ghidra
12.1.4 PUBLIC Java25 build and relevant real synthetic
safety gates remain required on exact HEAD. These static
catalog addresses do **not** prove active SIMCR/MM, configured
watchdog, CSBAR/CSOR physical bus map, runtime execution or
read/write permission. No local RAG copy authenticated, original
ECU411 firmware, user Ghidra project or OAuth modified.
GA-06/10/16/18 remain PARTIAL; GA-14 deferred. Stopped
Wyse/Precision/Supervisor tests remain stopped.

## GA-06/10/16/18 — 2026-11-09: exact MC68332 chip-select address-table PDF evidence

After the 15 SIMCR/SYNCR diagram-to-mask checks and the separately
completed GA-08/13 transactional pointer receipt package (merged #238),
this bounded read-only work expands manufacturer register evidence to
26 chip-select-related SIM entries. A reviewed Table D-2
`HardwareSimChipSelectTableWitness` validates the actual **address,
register role, physical publisher-PDF folio and concrete profile
offset/width** for CSPAR0/1, CSBARBT/CSORBT and CSBAR0..10/CSOR0..10.
It preserves the non-obvious folio boundary: CSBAR4 $YFFA5C is
printed D-4 / physical PDF 218, while CSOR4 $YFFA5E begins D-5 /
physical PDF 219. Changed rows, wrong/swapped/absent pages, duplicate
PDF rows and generic CPU32 scope cannot become verified register
addresses. The implementation neither infers additional field masks
nor modifies existing chip-select decoders.

The independent official manufacturer-PDF Actions job verifies
the same reviewed SHA-256/265-page MC68332UM source, extracts exact
physical PDF 218/219 and runs all 26 table-row checks; standalone
Java21 tests exercise deterministic negative cases without source
network access. Full Ghidra 12.1.4 PUBLIC Java25 extension
compilation and actual synthetic headless safety regression remain
mandatory at final exact commit SHA.

Evidence is static **register-address metadata** only. A register
row does not prove physical CS assertion, active MM, external bus
mapping, an executed firmware write or Review/Apply eligibility.
No original ECU411 firmware/user Ghidra projects/OAuth modified,
no stopped Wyse/Precision/Supervisor workers restarted.
GA-06/10/16/18 remain PARTIAL; GA-14 deferred.


## GA-08/13/18 — 2026-11-09: transactional argument/local pointer rename receipts

Previously the GA-13 Program Options receipt and revision-guarded
read-only audit covered approved **Function** renames, while actual
Ghidra parameter/local pointer renames used atomic explicit
Review/Apply/Undo but left no correlated saved operation record.

A versioned, SHA-256-integrity-checked, bounded
`HardwareScopedVariableReceipt` now records each **explicitly
approved** existing typed pointer variable rename in the Ghidra
Program's own transactional Options. The storage key binds the
exact `Function entry / PARAMETER|LOCAL / ordinal`; the body
retains storage identity, before/after names, review-time Program
modification number, source SHA and the operation origin with
**actor UNKNOWN**. The checksum detects accidental corruption;
it does NOT authenticate editor identity or make the receipt
tamper-proof. Any previously stored record at a target key blocks
silent overwrite and the ENTIRE selected batch rolls back.

`HardwareScopedVariableService.audit(Program)` reads the same
Program Options, decodes *all* records with strict version/key
checks, and independently looks up live typed Ghidra variables
by function/kind/ordinal. Each row distinguishes current approved
name from changed name, changed pointer type/SourceType, changed
storage, missing variable, changed source import or missing source
identity. `auditCsv(Program)` and the immutable
`Snapshot.csvRevisionBound` refuse reports after edits, native
Undo/Redo, Program switches or revision changes between source
collection and CSV publication. CSV remains read-only, sanitized
against spreadsheet formulas and never an Apply input.

Deterministic Java21 regressions exercise canonical serialization,
checksum tampering, invalid/oversized records, duplicate and
foreign Options keys, stale Program owner/revision, mid-export
race, altered pointer type/storage/name and source SHA uncertainty.
The real synthetic Ghidra 12.1.4 PUBLIC headless fixture checks
two original argument/local receipts, Undo removing both, Redo
restoring both, rejected stale CSV, then one explicit four-variable
batch across two independent Functions, preserving the older
two receipts through the newer batch's Undo/Redo. A **separate
two-JVM, same-on-disk-project regression** now saves actual typed
parameter and local receipts alongside a function receipt in
the first Ghidra process, reopens that same isolated Program
in the second process, and requires both current names, storage
identities and source import checksum to survive without any
read-only audit mutation. No new
automatic naming, inferred A-register variables, actor attribution,
external database, production firmware or user settings.
No model tests or stopped Wyse/Precision/Supervisor.

GA-08/13/18 remain PARTIAL, GA-14 deferred. Exact final HEAD
Actions full Java25 extension build, Java21 policy and genuine
synthetic Ghidra tests required before integration.


## GA-06/10/16/18 — 2026-11-09: MC68332UM source-checked register mask diagrams

The previous 15-field MC68332 SIMCR/SYNCR source ledger and exact
physical PDF-page token witnesses remain unchanged. A new bounded,
read-only `HardwareBitfieldLayoutWitness` compares all existing
explicitly selected device-profile masks to bit positions
independently reviewed from the MC68332UM Appendix D diagrams:
SIMCR D-5 / physical PDF 219 and SYNCR D-6 / physical PDF 220.
It computes masks from the 15 reviewed MSB:LSB ranges rather than
copying claimed profile masks, rejects missing/extra fields, altered
mask claims, absent/shifted diagram pages and invalid source text.
It also distinguishes a field's physical PDF **diagram page** from
its prose/description page: SUPV is drawn on PDF 219 but described
on 220; RSTEN/STSIM/STEXT drawn on 220, described on 221.
Reserved bits remain uninterpreted (SIMCR `0x1430`, SYNCR
`0x0078`, including SYNCR hardware status bits).

The separate official-NXP-PDF Actions job first validates the
reviewed PDF SHA-256 and 265-page count, extracts exact physical
pages 219–221, then verifies distinctive bit-number headers and
ordered field-diagram text from those same immutable bytes, followed
by the 15 position-to-profile-mask checks. Standalone Java21
regressions cover the independent reference, profile-mask
corruption, swapped page text, missing and unexpected fields, and
bounded input. Full Ghidra 12.1.4 PUBLIC Java25 extension build and
existing hardware CI remain required at the exact final HEAD.

**Evidence limit:** a reviewed PDF diagram plus pinned publisher
source is stronger than a field-name string, but is not an
automated image parser or proof of every documented bit meaning,
reset condition, physical device identity or executed firmware
write. Local/RAG copies remain unauthenticated by this runtime
class; no automatic Review/Apply or private firmware modification.
GA-06/10/16/18 remain PARTIAL, GA-14 deferred. No stopped
Wyse/Precision/Supervisor tests reactivated.


## GA-15/18 — 2026-11-09: complete UTF-16 bounded Agentic response evidence

The existing `BoundedAgenticStream` retained a high UTF-16 surrogate
at the end of an intermediate provider callback while waiting for a
later low surrogate; its `text()` view could therefore briefly expose
an invalid code unit to UI/RAG. A full provider callback shorter than
the configured limit could also bypass source-content validation,
and an invalid limit was accepted if the response was already short.

This package holds an unfinished high surrogate **privately** until
the matching next callback arrives; only complete code points enter
the bounded retained prefix. Unpaired low/high surrogates and input
exceeding the hard cap mark source loss. `completeSource()` remains
false when the final provider callback has an unmatched high;
`fullResponseComplete()` detects malformed full callbacks even
below the cap. `bounded()` always validates the limit and returns
only valid UTF-16 prefix characters. The existing production
`ReActOrchestrator` now marks `FindingsCache` source INCOMPLETE
at both iteration and synthesis completion whenever full text or
stream callback evidence is truncated/invalid. It never upgrades
untrusted partial model text to a complete hardware claim.

Java21 deterministic regression exercises a supplementary Unicode
character split between two callbacks, full-response split at
capacity, isolated low/high surrogates, high followed by ordinary
text, malformed short full callbacks, reset and invalid-limit bypass.
The GA-15 bounded findings workflow executes those tests with the
existing dropped-source and pagination-staleness suite. Full
Ghidra 12.1.4 PUBLIC Java25 build and applicable real synthetic
Automation API/CodeBrowser GitHub Actions remain required on exact
final SHA. There are no model-based test calls, UI Apply permissions,
private firmware or historical Supervisor/Wyse tests.

GA-15/18 remain PARTIAL; GA-14 remains deferred.


## GA-05/08/13/18 — 2026-11-09: correct function-local pointer namespaces across approvals

The existing `HardwareScopedVariableReview.propose` is now safe for
batched previews containing variables from **multiple** Ghidra
Functions: candidate-name collisions are scoped to a specific Function
entry, while the exact candidate identity is `function entry / kind /
ordinal`. Duplicate ordinals under different storage in one Function
are rejected instead of resolving the first convenient storage.
Independent functions may legitimately contain the same stack slot,
ordinal, generated name and proposed pointer placeholder. Existing
Ghidra Service `apply` also rejects repeated
`Function/kind/ordinal` even if a forged Proposal contains another
storage description.

Deterministic Java21 regressions check two independent Functions,
false global collisions, collision within a Function, forged
duplicate ordinal/storage and binding a reviewed Proposal to its
original Function. Actual synthetic Ghidra 12.1.4 PUBLIC headless
uses two independent FunctionManager objects, each with a genuinely
typed pointer parameter and stack local; a single four-item explicit
approval batch must preserve independent Function namespaces.
A late forged observation for the second Function must roll back the
first Function and leave all four names untouched. The same fixture
requires real native Undo/Redo of all four names, strict duplicate
ordinal refusal and denial of stale replay. All five new receipt flags
are mandatory in the Python CI harness.

This is *not* automatic naming from an A-register: every candidate
must refer to an existing Ghidra variable with stable exact type,
ordinal, storage and Function owner. No parameter/local rename
history is claimed when native Undo erases it, no actor identified,
no private MCU firmware/production project changed. Review/Apply
continues to require explicit confirmation and a current Program
revision. No Wyse, Precision or legacy Supervisor.
GA-05/08/13/18 remain PARTIAL; GA-14 deferred.


## GA-08/13/18 — 2026-11-09: live revision-bound approved-rename audit CSV

The existing GA-13 transactional Program Options receipt and
Review/Apply/Undo machinery is retained unchanged. A new
`HardwareFunctionRenameAudit.Snapshot.csvRevisionBound` requires a
matching process-local `HardwareAnalysisRevision` for the source
Program and approved revision before **and after** assembling the
read-only CSV. It throws `STALE_REVISION` if the Program, profile,
import SHA or modification number changes while the report is being
built; no partial receipt export can be presented as current. The
production `HardwareFunctionRenameService.auditCsv(Program)`
performs the existing full Options + live Function/SourceType audit,
then exports through this guard, with no writes or changed Apply
authorization.

Deterministic Java21 source tests cover accepted same Program/source,
changed revision, different Program owner, profile changes, import
source SHA changes and an edit *between* the two CSV checks. The
existing real Ghidra 12.1.4 PUBLIC Java25 headless two-function
approved-renames fixture now requires a current CSV containing the
two GhidrAssist transactional receipts, rejects the previous CSV
after genuine native Undo, and regenerates a new current receipt CSV
after genuine Redo. The Python CI harness requires distinct proof
flags. All existing collision, rollback and corrupt-receipt gates
stay in place. SourceType USER_DEFINED still identifies no human/AI
actor; no append-only history is invented, and native Undo can
remove transactional receipts. Arbitrary local user Ghidra profiles,
ECU411 projects, OAuth and automated Apply remain untouched.

Acceptance is exact-head Java21 + full Ghidra 12.1.4 PUBLIC extension
build and actual synthetic Ghidra CI. No Wyse/Precision/Supervisor
timer or worker. GA-08/13/18 remain PARTIAL; GA-14 deferred.


## GA-06/10/16 — 2026-11-09: exact MC68332UM physical PDF folio field-name witnesses

The 15 previously modeled MC68332 SIMCR/SYNCR bitfield
source-page **claims** remain bounded and device-scoped. This
package adds read-only `HardwareBitfieldPageWitness`, which compares
the complete discriminative field-name token against actual extracted
page text for each claimed one-based physical PDF folio, returning
`NAME_ON_CLAIMED_PAGE`, `NAME_NOT_ON_CLAIMED_PAGE`,
`PAGE_TEXT_MISSING`, `SHORT_NAME_AMBIGUOUS` or
`FIELD_PAGE_CLAIM_UNUSABLE`. The page inventory is limited to 16
items of 256 KiB each and emits immutable rows, mask **claims**,
physical folio numbers, edition claim and publisher checksum metadata.
Short terms `MM`, `W`, `X` and `Y` cannot serve as independent
bitfield witnesses. No text match proves mask/meaning/reset semantics
or execution. Generic CPU32 never inherits the MC68332 ledger.

The existing official SHA-256-pinned MC68332UM source CI gate now
compiles Java21 source-page witnesses **after** validating that the
downloaded NXP publisher PDF matches the reviewed digest and has
265 physical pages; extracts D-5/D-6/D-7 folios 219/220/221; and
requires exact full field-name matches for SHEN on page 219 and
STEXT on page 221. Standalone deterministic Java21 test covers all
11 discriminative synthetic token names, missing/shifted pages,
substring collisions, size caps and unknown device scope.
No PDF bytes or RAG copies are uploaded or authenticated implicitly.
The runtime source ledger remains CLAIM_ONLY; none of these checks
automatically validates a local PDF or warrants Review/Apply.

Acceptance requires the exact final GitHub Actions SHA, official
publisher PDF witness, full Ghidra 12.1.4 PUBLIC Java25 extension
build and regression suite. No Wyse/Precision/Supervisor, private
ECU411, user project/profile, secrets, or production Apply.
GA-06/10/16 remain PARTIAL; GA-08/13 continue independently,
GA-14 deferred.


## GA-02/03/11/12/18 — 2026-11-09: branched two-hop CALL cohorts, two leaves and live Listing revision

The existing bounded two-hop CPU32 solver is retained; this package
extends **source reconciliation**, not the underlying CALL solver.
An exact `bridge entry → leaf entry → STORE PC` cohort is evaluated
independently, so two separate leaf functions and several distinct
STORE instructions within the same leaf do not borrow each other's
caller identities or generate spurious `INCOMPLETE` results. For
each cohort, *all* directly sampled callers entering its verified bridge
must have exactly one matching CALL origin and STORE row. Global solver
uncertainty, hidden pagination, aliases, source omissions, untrusted
bridge-to-leaf links and incomplete caller data still fail closed.
An agreement applies only to sampled direct CALL contexts; it is NOT
proof of execution, active SIMCR/MM, a physical chip-select mapping,
ISR activation, or a Review/Apply entitlement.

A second revision guard surrounds the **whole Markdown report**.
Formerly each row was checked before and after individually; an edit
between rows could leave earlier, stale known values in the report.
Now any changed `HardwareAnalysisRevision` at publication discards
the entire report and every candidate/provenance row. This also
covers the early bounded display return. The original function-stage
epoch guard remains intact, and contextual sources are never stored
in durable GA-12 checkpoints.

Java21 deterministic regression proves a bounded acyclic branched
bridge with two paths assigning identical A1 before nested CALL;
two distinct leaf functions, three STORE PCs and four independent
caller sites; explicit distinct-cohort provenance; a contradictory
branch assignment that leaves the inner MMIO alias unknown; foreign
and truncated row refusal; and a mid-report revision change that
cannot leak earlier source addresses.

The actual synthetic **Ghidra 12.1.4 PUBLIC** headless fixture now
decodes both a CPU32 BNE/BRA-convergent bridge and two distinct leaf
functions with two STORE PCs in the first. It validates the
three-source-cohort reconciliation from actual Ghidra-translated
Listing/P-code steps. The same integration uses an actual CodeUnit
EOL annotation transaction on its synthetic bridge to advance the
real `Program.getModificationNumber()`; pre-change two-hop source
provenance must be rejected as `STALE_REVISION` with no address or
caller provenance, while the transaction rollback keeps source bytes
unchanged. The harness explicitly requires these receipts.

All claims remain static and limited to modeled synthetic CPU32
source paths. Requirements: deterministic Java21 tests, full
Ghidra Java25 extension compilation, exact-HEAD GitHub Actions
and genuine synthetic Ghidra headless regression. Do not run
stopped Wyse/Precision/Supervisor, modify private firmware,
production projects or Apply. GA-02/03/11/12/18 stay PARTIAL;
GA-14 remains deferred.


## GA-02/03/12/18 — 2026-11-09: sampled two-hop CALL source provenance

The two-hop CPU32 direct outer CALL -> fully decoded bridge with one
inner direct CALL -> bounded leaf STORE solver was already implemented.
This package does **not** duplicate that solver or promote its
source-only MAY observations to a global callee effect.

A bounded, read-only second-level reconciliation groups rows for one
leaf STORE PC while retaining outer caller PC, outer CALL PC, bridge
entry, nested CALL PC and final leaf/store origin. Independent sampled
CALL contexts with matching width/address/word may be labeled
SAMPLED_AGREEMENT; differing contexts are SAMPLED_DIVERGENCE.
Any skipped/invalid outer or bridge, unknown inner A/D register, missing
leaf, unresolved STORE alias, mismatched source/bridge origin, duplicate
or foreign source, pagination or incomplete caller is INCOMPLETE.
The report explicitly marks unsampled outer CALLs as UNKNOWN. Neither
agreement nor divergence is runtime execution, active SIMCR/MM, global
firmware completeness, a physical bus mapping or Review/Apply approval.

A process-local HardwareAnalysisRevision comparison before **and after**
reconciliation returns STALE_REVISION without address or provenance
when program, profile, owner or modification changes. The existing
GhidraHardwareFlowService analysis-epoch gate surrounds the new report.
No ephemeral process modification number is added to cross-process
GA-12 durable keys; contextual reports are never saved as complete
function CFG stages.

Java21 regressions exercise independent convergent/divergent outer
callers, unresolved pointer, incomplete caller, truncated rows,
missing/foreign source, duplicated CALL PC, Ghidra-revision changes
before/between gates and fail-closed Markdown. Genuine Ghidra 12.1.4
PUBLIC Java25 headless two-hop CPU32 synthetic CALL fixture verifies
that two conflicting and a third unknown A0 source yield INCOMPLETE
and no false global MMIO proof. Acceptance requires all exact-HEAD
Actions workflows, full extension compile and deterministic reports.
No Wyse, Precision, Supervisor, private ECU411, user project or Apply.

GA-02/03/12/18 remain PARTIAL; GA-14 deferred.


## GA-02/03/12/18 — 2026-11-09: sampled CALL-site consensus and revision barrier

The production one-hop source analyzer already resolves A/D context
separately at each fully decoded direct CALL and conservatively joins
predecessors; two-hop analysis also exists. Do NOT duplicate those
solvers. A new bounded *reporting-only* reconciliation class inspects
one callee STORE PC across independently observed direct caller sites.
It distinguishes **SAMPLED_AGREEMENT** (same address, width, optional
word and STORE kind), **SAMPLED_DIVERGENCE** (conflicting candidates),
**INCOMPLETE** (pagination, unknown alias, incomplete caller/callee,
missing/foreign/duplicate rows, unknown context), **NO_SAMPLED_CALLS**
and **STALE_REVISION**. Every result retains source CALL/STORE
provenance; even unanimous sampled contexts are explicitly MAY-source
observations, not universal callee effects or runtime execution.

The existing GhidraHardwareFlowService Hardware Analysis markdown now
includes a bounded, read-only Cross-CALL reconciliation section. It
reuses the already sampled decoded CALL/callee contexts and reports
only pairs with at least two sampled direct callsites; incomplete global
caller inventory suppresses agreement, and a 24-row budget is labeled
explicitly. The genuine Ghidra 12.1.4 PUBLIC headless call-context
fixture must show an INCOMPLETE row for a third caller with an
unproved A0, never sampled/global agreement.

A process-local HardwareAnalysisRevision gate must match both before
and after reconciliation. If Ghidra changes its analysis revision
while the reconciliation runs, it returns only STALE_REVISION, with
zero candidate provenance and no address. It never writes GA-12 cache
or Review/Apply state. Crucially, this does NOT modify the
cross-process durable function checkpoints or assume that the
imported executable SHA changes on Listing edits.

Java21 deterministic regression covers same/different callers,
multiple differing A0 values, truncated display, unknown pointer,
incomplete caller, foreign row, missing STORE, duplicate CALL PC,
profile/Program owner mismatch and revision transition between the
two gates. Existing Ghidra 12.1.4 PUBLIC / Java25 genuine headless
CALL-context and CodeBrowser/Xvfb regressions remain mandatory on
the exact final commit. No original ECU411 firmware, user projects,
local Wyse/Precision, Supervisor tests, runtime MCU claims or Apply.

GA-02/03/12/18 remain PARTIAL; GA-14 stays deferred.


## GA-02/03/11/12/18 — 2026-11-09: real branch join and live Ghidra revision

The existing isolated Ghidra 12.1.4 PUBLIC/Xvfb synthetic source
gains an actual decoded CPU32 function with conditional/unconditional
branch edges and conflicting A0 provenance: one path points to SIMCR
0xFFFA00, the other to CSBAR7 0xFFFA68. A single later indirect
MOVE.W does not prove either destination; the actual production
Listing/P-code CFG translator and the existing conservative join must
produce one unresolved source effect. The complete branch result is
persisted in JVM 1 and byte-compared with the retranslated result
after re-opening in JVM 2. CFG reachability remains a static
possibility, not a runtime branch choice or executed MMIO write.

Revision invalidation is exercised against a **real Ghidra Program
modification**, not an artificial increment: after independently
restoring durable function-stage evidence, the second CodeBrowser JVM
captures the existing process-local HardwareAnalysisRevision,
changes an annotation inside a transaction on the disposable source,
and verifies that the original revision no longer matches the
Program's actual modification counter. The production
HardwarePartialStageRunner is invoked with that revision-bound
stillCurrent gate: it must throw CancelledException and leave no
complete or incomplete stage for the changed Program. The transaction
is rolled back and the original branch CFG is checked again.

Deliberately do NOT inject ephemeral Ghidra modification numbers into
durable cross-JVM cache identifiers: they are not guaranteed stable
across process restart. Retain SHA-256, source/profile/CFG/budget
binding for disk stages; use the process-local revision for
in-flight analysis cancellation. This does not claim comprehensive
invalidation of every long-lived cache on arbitrary annotation edits.

Acceptance requires real Ghidra Java25 extension, actual Xvfb
CodeBrowser two-JVM regression, deterministic Java21 coverage and
all exact-HEAD GitHub Actions. No private firmware, original projects,
Wyse/Precision/Supervisor, or automatic Apply. GA-02/03/11/12/18
remain PARTIAL; GA-14 remains deferred.


## GA-02/03/12/18 — 2026-11-09: wrap-width overlap and multi-function pending CFG

**Candidate:** use the existing CPU32 modulo-24-bit byte intersection
solver to test isolated 8/16/32-bit writes around 0xFFFFFF -> 0x000000.
Track one-byte no-op for an unrelated word, a 16-bit spanning write
that invalidates the wrapped word, a 32-bit spanning write that
invalidates *both* high and low tracked words, and an unrelated SIMCR
word that must remain intact. A later complete aligned word can
re-establish its own value. These are static source candidates only.

**Durability:** the real Ghidra 12.1.4 PUBLIC CodeBrowser fixture now
stores TWO distinct incomplete typed worklists for separately decoded
CPU32 functions (0x60 and 0x80) in the same directory. Each stops after
two genuine translated CFG iterations. The first JVM verifies two
independent disk slots and no completed evidence. The second JVM
reopens the isolated project, re-translates both sources, compares
typed progress SHA-256, refuses changed source and MCU profile or
the other function's graph, resumes both through the production
HardwarePartialStageRunner (not cold fallback), compares complete
result bytes with independent cold solves, and commits both without
corrupting the other slot. This complements the existing longer
single-function 16-iteration real translated restart.

Acceptance requires source-only Java21 assertions, real synthetic
Ghidra 12.1.4 PUBLIC Java25/Xvfb two-JVM receipts, and exact-HEAD
GitHub Actions, followed by review and integration. A passing static
test does not prove actual MM mapping, runtime execution or ECU411
behavior. No private projects, Wyse/Precision or Supervisor worker.
GA-02/03/12/18 remain PARTIAL; GA-14 is deferred.


## GA-02/03/12/18 — 2026-11-09: real translated P-code interruption and byte overlap

The first full two-JVM regression for an **interrupted real translated**
CPU32 Listing CFG, not just an invented 96-node Step graph: the isolated
256-byte CodeBrowser source now contains a real 20-instruction function
(MOVEA.L immediate to A0, 17 NOP instructions, MOVE.W via A0, RTS).
The first Ghidra JVM decodes all instructions, translates them via the
production GhidraHardwareFlowService, executes one bounded 16-iteration
slice and persists the incomplete typed worklist. Incomplete progress
must not appear as completed Review/Apply source. The second independent
Ghidra JVM reopens the same isolated project, retranslates the source,
requires the exact worklist iteration count, verifies source/profile/
budget mismatch rejection, resumes the actual worklist using the
production HardwarePartialStageRunner and compares every encoded output
byte with a cold full fixed point. Only a complete result may replace
the pending cache slot.

A second genuine CPU32 function writes SIMCR as a full word, overwrites
the high byte with MOVE.B to the same effective address, then writes
another full word. The existing HardwareDataflow overlapping-byte model
must invalidate the previous complete register value after the byte
write, and reestablish a known word only after the final complete write.
This is **static** instruction/source evidence, not observed hardware
bus transactions, activation of MM, or execution on ECU411. The earlier
indirect-A0/unknown-A1 cases, corrupt checkpoints and 96-node
interrupted synthetic worklist remain independent tests.

Acceptance: full Java25 extension, real Ghidra 12.1.4 PUBLIC/Xvfb
two-JVM JSON receipts, exact-HEAD GitHub Actions, source SHA and
regression continuity. No Wyse/Precision/Supervisor, original firmware
or user projects. This advances but does not complete GA-02/03/12/18;
GA-14 remains deferred.


## GA-02/03/12/18 — 2026-11-07: actual CPU32 indirect MMIO, alias and restart

A cohesive source-only acceptance candidate extends the existing Ghidra
12.1.4 PUBLIC/Xvfb CodeBrowser fixture with two **real decoded CPU32**
functions. The first statically writes MOVEA.L #0x00FFFA00,A0, then
MOVE.W #0x40CA,(A0), then RTS. The second uses the same A0 source,
writes through an unknown A1 alias, then writes via A0 again. The test
does not run MCU instructions; it translates real Listing/P-code into
the existing bounded HardwareDataflow CFG, checks A0 propagation,
rejects resolution of the A1 write, and requires unknown-alias provenance
at the later A0 site. No claim of active SIMCR/MM follows.

Production translation now counts both direct output-to-RAM P-code
effects and indirect STOREs. If a source mnemonic hides multiple
underlying memory writes, lacks a verifiable memory effect, or its
independently provable P-code and Listing addresses disagree, the
instruction becomes a conservative unknown alias, not a published
single-register write. The pure Java21 suite adds ten source-consistency
assertions alongside the width-aware P-code constant suite.

Completed results for **both real translated CPU32 functions** are saved
in separate disposable GA-12 function-stage slots during the first
CodeBrowser JVM. A second actual CodeBrowser JVM reopens the project,
retranslates the same instructions, verifies byte-for-byte completed
stage equivalence, checks source/profile invalidation and compares a
digest across processes. The existing 96-node *translated synthetic*
interruptible worklist regression remains independent; this new case
does not claim full P-code worklist resumption or arbitrary CPU32
instruction coverage. Acceptance requires full Java25 extension and
all exact-HEAD GitHub Actions tests. No Wyse/Precision/Supervisor,
private ECU411 firmware, external AI or Apply is involved.

GA-02/03/12/18 remain PARTIAL after this candidate; GA-14 stays deferred.


## GA-02/03/12/18 — 2026-11-07: size-correct real P-code MMIO addresses

**Implementation candidate:** the existing genuine Ghidra Listing CFG
translator uses a pure Java, width-aware constant evaluator for COPY,
INT_ZEXT, INT_SEXT, INT_ADD and INT_SUB. It applies P-code input/output
varnode widths, computes signed extension from the input sign bit and
arithmetic overflow at the declared result width, and only then applies
the CPU32 24-bit external bus mask to a proven four-byte STORE pointer.
Unsupported operations, unknown values, incompatible widths and truncated
pointers stay UNKNOWN; a P-code instruction with multiple STOREs is still
unresolved and conservatively treated as an alias barrier. This does not
claim MCU MM or hardware execution.

**Regression:** independent Java21 source-only suite exercises 8/16/32/64-bit
sign extension, zero extension, arithmetic wraps, malformed widths,
unknowns and 24-bit address boundaries. The existing real synthetic
Ghidra 12.1.4 PUBLIC/Xvfb CodeBrowser two-JVM test additionally reads
the actual decoded Listing instruction at 0x20, requires exactly one
real P-code direct COPY-to-RAM effect for each synthetic SIMCR and SYNCR
write and resolves both source addresses through
the same production method in each JVM. Full Java25 extension and
all required exact-head CI must pass before integration.

**Limits:** this verifies one real synthetic instruction plus general
width semantics, not the complete P-code translation of every 68332
instruction, indirect runtime execution, hardware mapping or schema
migration. GA-02/03, GA-12 and GA-18 remain PARTIAL.


## GA-12/18 — 2026-11-07: typed worklist request/CFG identity guard

The existing durable function-stage loader now rejects a structurally valid
and correctly SHA-256-rehashed pending fixed-point state if its embedded
function entry or iteration budget differs from the requested one, or any
recorded state node is absent from the current translated CFG. These are
cache misses before invoking the solver, not uncaught stale-progress
exceptions. The valid worklist still resumes after a real second JVM
restart.

The isolated Ghidra 12.1.4 PUBLIC/Xvfb two-JVM regression uses nine typed
negative cases (six schema/state corruptions, wrong entry, wrong budget,
foreign graph node), each with fresh cold analysis checked against the
independently completed typed result. Checksum is corruption detection, not
authentication. This does not validate arbitrary genuine Ghidra P-code
translation or schema migrations; GA-12 remains PARTIAL and merge requires
full Java25 build and exact-HEAD CI.


## GA-12/18 — 2026-11-07: checksum-valid malformed interrupted worklist refusal

The existing two-JVM real synthetic Ghidra 12.1.4 PUBLIC/CodeBrowser
test now reproduces six malformed typed pending CFG states inside
**correctly rehashed** copies of the first JVM's real disk envelope:
unknown schema, iteration counter at the fixed-point budget, invalid
register, invalid 24-bit MMIO cell, successor absent from the state
map, and duplicate pending successor. Both pending and completed codecs
must refuse each file. The real stage runner must cold-recompute a
nontruncated result byte-identical to independent fixed-point analysis.
The untouched original worklist must still resume in a second Ghidra
JVM. This separates structural schema validation from simple SHA-256
corruption detection: a digest is not authentication of the writer.

This is model-free isolated regression, not an assertion of the complete
Ghidra P-code translation pipeline, old schema migration, real firmware
execution, MCU MM activation, or operator authorization. GA-12 remains
PARTIAL; full Java25 extension and exact-SHA CI are acceptance gates.


## GA-12/18 — 2026-11-07: corrupt interrupted worklist fail-closed regression

After the actual second-JVM restore test, disposable copies of its real
first-JVM partial stage are deliberately corrupted in three independent
ways: a flipped checksum byte, a truncated file and a file exceeding
the bounded store maximum. Both partial and complete codecs must refuse
every damaged stage. A real subsequent fixed-point runner invocation must
start cold, finish without truncation and produce the exact same typed
result as an independent cold analysis. The original valid checkpoint
remains untouched and must still resume in the second JVM.

This is isolated synthetic Ghidra 12.1.4 PUBLIC/Xvfb CI, not evidence of
full Ghidra P-code serialization, legacy schema migration, runtime MCU
execution or approved Apply. GA-12 and GA-18 remain PARTIAL until the
independent acceptance criteria in this roadmap are met.


## GA-12/18 — 2026-11-07: real two-JVM interrupted CFG fixed-point recovery

Acceptance candidate: a real **synthetic Ghidra 12.1.4 PUBLIC/Xvfb
CodeBrowser** starts a 96-node deterministic translated CFG worklist
keyed to the same isolated project's original import SHA-256, full
256-byte synthetic Program image, selected Listing instruction and
language. The first JVM is deliberately cancelled *after* it persists
a bounded incomplete fixed-point slice; this progress is **not**
complete evidence and cannot be loaded through the completed-result
codec. After first JVM exit, a genuinely new Ghidra process reopens
the same synthetic project and Program. The second process loads the
actual pending worklist, continues to a complete fixed point, compares
its typed result byte-for-byte with a cold analysis, verifies the
synthetic indirect MMIO address and saves a completed cache stage.

Negative assertions: changes to exact source input, analyzer generation,
MC68332-vs-generic CPU32 profile, language, translated CFG steps and
fixed-point iteration budget all **refuse** the old partial stage and
completed result. The durable stage store is the existing GA-12
implementation; no new cache system or privileged Apply flow is
introduced. Deterministic test receipts and extension build are
pinned to the precise GitHub SHA.

**Scope:** the translated 96-node CFG is synthesized for stable
fixed-point slicing, not 96 disassembled instructions in firmware;
the actual CodeBrowser/Program, full disposable 256-byte image and
Listing identity participate in input verification. This validates
the cross-JVM durable worklist protocol, not the complete Ghidra
P-code translation pipeline for arbitrary ECU411 firmware. The
latter and migration of all legacy analyzer/profile schemas remain
separate GA-12 acceptance criteria; do not mark GA-12 COMPLETE.


## GA-15/18 — 2026-11-07: bounded streamed ReAct evidence

**Candidate milestone:** the ReAct LLM callback paths now bound
stream accumulation to 128 KiB per iteration, 32 KiB for the GUI
preview and 16 KiB for reflection, and final synthesis is independently
capped. UTF-16 surrogate pairs, including pairs crossing callback boundaries, are not split. Any overflow marks the
shared `FindingsCache` as structurally source-incomplete and bumps the
pagination revision; no successful terminal ReAct result can claim
a *complete retained-evidence checkpoint* when source text was
discarded. Java21 deterministic 50k-chunk tests validate bounded
memory, revision invalidation, eviction survival and source-incomplete
prompt warnings; Java25 full Ghidra 12.1.4 extension and real
scripted Xvfb/CodeBrowser ReAct CI required on exact HEAD.

**GA-15 remains PARTIAL**: independent tool-specific paging,
large-context summarization quality and resumed interrupted
investigations require further acceptance. This is static and
model-free deterministic CI, not source completeness of ECU411.


## GA-12/15/18 — 2026-11-07: checkpoint ancestry and schema consistency

**Implementation candidate for independent reviewed task provenance:** new
`--parent` option on explicit CLI `agentic-checkpoint` records SHA-256 and
opaque run ID of a complete, verified prior checkpoint; new read-only
`agentic-lineage-verify` checks both checkpoints and the exact ancestry
without any live session, model access, tool rights or Apply authorization.
Reject missing/rewritten parent fields, same-run, incomplete/evicted,
wrong-firmware and rehashed forged-run cases. The isolated synthetic Ghidra
12.1.4 PUBLIC / Java25 second-JVM checkpoint must link back to the original
and the external post-exit CLI must validate that exact relationship.
Untrusted historical evidence metadata is bounded consistently across the
Java Saved Checkpoint importer and Python CLI: explicit nullable strings,
integral relevance and nonnegative timestamp.

**Audit:** checkpoint continuation from merged #218 is complete as a
read-only review milestone. GA-12 stays **PARTIAL**: interrupted function/
CFG/P-code stage persistence and recovery, analyzer cache migration across
schema/profile revisions and durable change provenance beyond Agentic
snapshots remain to be proved. GA-15 stays **PARTIAL**: broader tool-specific
pagination and long-context completeness and cancellation recovery still
need coverage. This package does not restart or restore an old LLM process;
nor does a checksum authenticate a source actor or establish firmware runtime
execution. Exact-head Java21/Python3, real synthetic Ghidra/Xvfb and full
Java25 extension CI are required before integration.


## GA-12/15/18 — 2026-11-07: end-to-end independent checkpoint continuation package

**Implementation candidate:** Import Saved Checkpoint from Query tab;
strict bounded canonical SHA-256 and complete-source validation with
the *currently open* Program import SHA; fresh new objective, chat ID
and READ_ONLY/8 policy; separate Submit and Approve Plan with no old
run/plan/session restoration. A real synthetic Ghidra 12.1.4 PUBLIC
CodeBrowser restarts in an independent JVM, then stages old untrusted
evidence in a new Query chat, separately approves a NEW scripted test
plan, runs one actual native read-only tool and persists a **new**
SHA-256-verified checkpoint. It must reject wrong firmware, corrupted
or incomplete saved evidence and not regrant old permissions. Exact-SHA
full Java25 extension build, real Ghidra/Xvfb, Java21/Python3 and all
existing regression workflows are required before merge.

**GA-12 status remains PARTIAL until the broader roadmap's persistent
analysis state, provenance/history, recovery and user-facing acceptance
criteria are independently audited.** This checkpoint continuation does
not restore model context or authorize Apply and does not validate legacy
CodeBrowser profile migration (#98).


## GA-12/15/18 — 2026-11-07: fresh CodeBrowser JVM source-identity regression

Candidate regression runs a complete first ReAct + private evidence snapshot,
closes its real synthetic CodeBrowser/JVM, and **starts a second Ghidra 12.1.4
PUBLIC application process** on the *same isolated Ghidra project and Program*.
In the new Swing tool it compares import SHA-256 and Program revision with
persisted checkpoint metadata, requires a fresh empty Agentic registry, refuses
old Review Draft without current live evidence and checks there is no pending
approved plan, running model or inherited Accept All/task policy. Later offline
CLI processes must still verify/read the SHA-256 checkpoint without granting
live resume. The comparison records whether the volatile modification number
matches or differs; neither outcome grants approval. GA-12/15 remain PARTIAL
until a deliberate user-driven new Review is re-established after restart.


## GA-12/15/18 — actual Swing Approve Plan and post-exit evidence test candidate

New deterministic Xvfb/Ghidra 12.1.4 regression covers the *actual*
JButton → production TabController → independent scripted ReAct route.
A third real ReAct invocation runs one read-only Ghidra tool after a
freshly supplied test-only plan; separate process verification of the
offline checkpoint after Ghidra exits is also checked with an explicit
nonresumability denial. This does not establish manual end-user approval
or live model restoration; GA-12/15 remain PARTIAL until all user workflows,
restart migrations, and source-identity requirements are complete.


## GA-12/15/18 — 2026-11-07: independent follow-up ReAct execution candidate

CI-only explicit fresh-plan approval marker now gates a **second real ReAct
execution** with the policy captured from the newly created Query chat. A
synthetic Ghidra 12.1.4 CodeBrowser checks no run before approval; after
approval it executes exactly one actual read-only native tool, observes new
Program registry generation, terminal SUCCESS, old-run/checkpoint rejection,
and unchanged firmware revision via authenticated CLI. This is a deterministic
CI substitute for the human review action, **not a real user-click approval**
or restored model conversation. GA-12/15 stay PARTIAL.


## GA-12/15/18 — same-Program Swing Query staging check (2026-11-07)

The read-only Review Draft's full evidence and SHA verification now feed a
real test of the production Query controller on the Swing EDT in isolated
synthetic Ghidra 12.1.4. The independent chat ID, disabled old session grants,
READ_ONLY / max 8 tool calls, untrusted Query text, and absence of automatic
planning or ReAct execution have explicit deterministic assertions. Approval
continues to require separate GUI Submit and Approve Plan; the fixture does
not invoke a real LLM or perform privileged Apply. Full CI and exact SHA are
required before integration; GA-12/15 remain PARTIAL.


## GA-12/15/18 — 2026-11-07: GUI import of independently reviewed Agentic evidence

Candidate: a bounded JSON Review Draft can be loaded via Query → Import
Review Draft only when its SHA and all live Program/run/evidence identities
match. Import stages **only new query text**, resets previous tool policy
to read-only with finite budget and requires independent **Submit** then
**Approve Plan**. No checkpoint or draft carries executable rights.
Java25 full extension + real synthetic CodeBrowser CI and deterministic
review-draft regression required on exact candidate SHA. Not LLM session
restore, not firmware runtime evidence. GA-12/15 remain PARTIAL.


## GA-12/15 — 2026-11-07 candidate: independently reviewed source handoff

New `agentic-review-draft` prepares a locally bounded, no-overwrite and
read-only review proposal from **fully matched live** synthetic Agentic
checkpoint evidence, with an entirely new operator-supplied objective.
It explicitly refuses inherited approval, tool permissions, plan and
LLM session state. Python3 regressions and real synthetic CodeBrowser
ReAct/JSON-RPC/CLI E2E verify safe creation, no-overwrite and forged
checkpoint rejection. The proposal is NOT an automatic new ReAct run;
GA-12/15 remain PARTIAL pending an explicit GUI-driven new Review gate.


## GA-12/15/18 — 2026-11-07 candidate: full live checkpoint content match

The local read-only Agentic preflight now compares every retained evidence
row with real live ReAct/CodeBrowser JSON-RPC pages under exact Program,
import SHA, run, terminal state, cache revision and completeness counters.
Actual synthetic Ghidra 12.1.4 PUBLIC GUI CI verifies CLI success and
denials of forged-but-rehashed rows, stale runs and invalid Bearer token.
A matching result remains `NEW_REVIEW_REQUIRED`: no model session replay,
no inherited tool authorization, no Apply. GA-12 and GA-15 still PARTIAL.


## 2026-11-07 — GA-12/15 resume preflight checkpoint identity

Candidate: explicit authenticated, read-only Agentic preflight compares a
locally SHA-256-verified retained-evidence checkpoint to the **currently
active** Program, import SHA-256, revision, run token, terminal outcome,
page-generation and completeness counters. The command never resumes
LLM state, tools or Apply and always requires new Review. Deterministic
Python3 tests cover matching, mismatched and stale cases. Ghidra 12.1.4
PUBLIC/Java25 full extension and real synthetic GUI/JSON-RPC CI must pass
at the candidate SHA before integration. GA-12/15 remain PARTIAL: this
only prepares a guarded handoff, not a full model-session restore.


## 2026-11-07 — GA-12/15 source completeness follow-up

Merged #206/#207 protect the identity and terminal lifecycle of Agentic runs;
merged #208 (7/7 exact-head Actions SUCCESS on
`0876b2b7905ad151e76df465345d3aa879b95558`) synchronizes
live textual findings views and prevents complete checkpoints after
single-field truncation. Next the extractor also marks skipped individual
lines >300 characters as structurally incomplete, not merely transcripts
exceeding scan/row limits. Java21 and actual isolated Ghidra 12.1.4
regressions must verify these boundaries on the candidate SHA. All remains
static/synthetic; no Supervisor or private ECU411 execution.

Status: **IN PROGRESS — integrated baseline 2026-11-06 (PR #198)**. Scope source: user-approved 2026-10-28 requirements (A–H, additional features 13.1–13.7, PDF/RAG, testing and Codex Supervisor integration).



## GA-15/18 — anulowanie, przełączenie Program i spóźniony callback (2026-11-07)

**Baza:** scalony PR #204, `master`
`2db426688f351fc9eba4675d23b317bcb51345c6`, po
6/6 workflow GitHub Actions SUCCESS dla dokładnego HEAD
`6db505a1e11a15c35bd54e1b0a42e5fcd40ef9f0`.

**GA-15 — PARTIAL, fail-closed przy anulowaniu:**
`ReActOrchestrator` publikuje callback anulowania związany z
**dokładnym aktywnym przebiegiem** w rejestrze dowodów.
Zmiana aktywnego Program w CodeBrowser natychmiast usuwa
jego odczytowy cache i żąda anulowania nadal aktywnego ReAct.
Stara callback cancellation NIE może anulować kolejnej sesji.
Zakończonej sesji nie anuluje się ponownie przy unieważnieniu.
`ReActResult.CANCELLED` raportuje faktyczną liczbę
wykonanych już narzędzi z dziennika ToolRegistry.
Anulowanie najpierw zapisuje terminalny wynik `CANCELLED`,
dopiero później powiadamia dostawcę LLM — dostawca może
bowiem wywołać `onError` synchronicznie już podczas
`cancelCurrentRequest()`. W takim wyścigu wynik ma
pozostać `CANCELLED`, nie `ERROR`.
Opóźnione callbacki LLM po zakończeniu run nie mogą ponownie
dopisywać dowodów, aktualizować UI ani wznawiać etapów
ReAct nawet jeśli inny run zresetował globalną flagę cancel.

**GA-18 — PARTIAL, pełna asercja CI:** dwa nowe scenariusze
na rzeczywistej, syntetycznej Ghidrze 12.1.4 PUBLIC
(Java25, CodeBrowser/Swing, Xvfb) testują:
(1) `RUNNING → CANCELLED → delayed model callback`, gdzie
wynik narzędzia `ga_get_current_address` jest już
zweryfikowany, ale ukończenie modelu celowo opóźnione;
(2) `Program A → Program B → Program A` podczas
`RUNNING`, gdzie API odmawia starych dowodów w obu
programach. W obu scenariuszach zewnętrzny proces
używa produkcyjnego Bearer JSON-RPC i `ghidrassist-agent`,
sprawdza brak reanimacji dowodów po opóźnionym callbacku,
status CANCELLED, brak zmian rewizji Program i dokładną
liczbę już wykonanych narzędzi. W scenariuszu ręcznego
anulowania wolno zapisać **niekompletny** checkpoint
do odczytu offline, ale nie podnosić go do statusu SUCCESS.
Dotychczasowy pozytywny scenariusz sukcesu pozostaje
regresją porównawczą. Dane wyłącznie syntetyczne; testy
nie używają prawdziwego modelu LLM ani prywatnego ECU411.

**Granice:** anulowanie nie cofa wcześniej wykonanych operacji
narzędzi, nie jest odwróceniem transakcji Apply i nie potwierdza
wykonania instrukcji MCU. ReAct/GA-15 i CI/GA-18 pozostają
PARTIAL do czasu testów dodatkowych klas narzędzi oraz
kontrolowanego wznowienia całej sesji modelu. Domyślną
ścieżką są GitHub Actions, bez starych lokalnych workerów,
Wyse/Precision i bez wznowienia Supervisora.

## GA-15 + GA-18 — pełny ReAct → HTTP JSON-RPC → CLI (2026-11-07)

**Baza:** zintegrowany PR #203 na `master`
`82169cbaf64c8ba255c8c141d566e7512f95b226` po **41/41
GitHub Actions SUCCESS** na testowanym HEAD
`c9e1dfd567e6f27ad567355fd848886b9ad79153`.

**GA-15 — PARTIAL, test end-to-end:** nowa izolowana regresja
uruchamia **rzeczywisty** `ReActOrchestrator` w pełnym
CodeBrowserze Ghidry 12.1.4 PUBLIC, z uprzednio zatwierdzonym
syntetycznym planem i restrykcyjną `ToolExecutionPolicy`.
ReAct wykonuje rzeczywiste, tylko-odczytowe narzędzie
`ga_get_current_address` poprzez `ToolRegistry`; jego wynik
dotyczy statycznego adresu Listing `0x00000020`. Jedynie
odpowiedź LLM jest deterministyczną atrapą z katalogu
**testów**, nie wymaga sieci, tokenów modelu ani OAuth.
Rejestrowany jest faktyczny cache ReAct, a nie ręcznie
wygenerowane wyniki registry.

**GA-18 — PARTIAL, fizyczne granice procesu:** zewnętrzny
`ghidrassist-agent` korzysta z produkcyjnego, opt-in,
Bearer-authenticated `127.0.0.1` JSON-RPC. Testuje stan
RUNNING (bez fałszywej kompletności), stan SUCCESS i rzeczywiste
wyniki narzędzia, stronicowanie, odmowę dla złego tokenu,
run-id i rewizji programu, następnie atomowy lokalny checkpoint
oraz weryfikację i odczyt offline bez sesji Ghidry.
Przy każdym kroku porównuje SHA-256 źródła, brak zmiany
rewizji Program i liczbę faktycznie wykonanych narzędzi
z raportem ReAct. Wszystkie dowody CI mają pochodzić
z jednego syntetycznego przebiegu i dokładnego SHA commita.

**Granice dowodu:** to prawdziwy kod ReAct, narzędzie i sieć
loopback, ale **nie** rzeczywisty model LLM, nie wykonanie
kodu ECU411, nie potwierdzenie aktywnych IRQ i nie pełne
wznowienie sesji AI. Dane prywatnego firmware, projekty
produkcyjne, OAuth, Wyse/Precision i stary Supervisor
pozostają nietknięte. Testowe konstruktorowe wstrzyknięcie
sterownika LLM jest package-private i niedostępne przez API.

**Bramki:** pełne `buildExtension` Java25, Ghidra
12.1.4 PUBLIC + CodeBrowser/Xvfb i rzeczywisty JSON-RPC/CLI,
istniejące regresje Java21, deterministyczne JSON/JUnit
i artefakty. GA-15/GA-18 pozostają PARTIAL do czasu
objęcia kolejnych złożonych narzędzi i rozszerzenia
kontrolowanego wznowienia sesji.

## GA-12 + GA-15 — odczytowy handoff Agentic przez Automation API (2026-11-06)

**Baza:** scalony PR #202 na `master`
`3c1ca550ba2a52ddf99043f1ffcc2def4b63c86c`, po 32/32
GitHub Actions SUCCESS na dokładnym HEAD
`2962f4df3847ec9d7c1fae7f78892d67a2e3eb1f`.

**GA-15 — PARTIAL:** istniejący `ReActOrchestrator` udostępnia
własny, rzeczywisty (nie wygenerowany na potrzeby RPC) `FindingsCache`
do odczytu przez `agentic.findings.page`, z ograniczeniem do
konkretnego obiektu Ghidra Program, rewizji, SHA importu i unikalnego
przebiegu analizy. Porządek stron i kompletność źródeł opierają się
na wersjonowanej paginacji z #202; brak odczytu innych projektów
i mieszania dwóch przebiegów Agentic. Publiczna modyfikacja rankingu
oraz dopisywanie wyników unieważniają stare strony. RUNNING,
CANCELLED, ERROR, MAX_ITERATIONS i MAX_TOOLS nie dają potwierdzenia
ukończonej analizy. API jest lokalne, Bearer-authenticated i
`read_only`; nie uruchamia LLM ani Apply.

**Ochrona zmiany aktywnego Program (GA-12/15):** przełączenie
CodeBrowser na inny Program unieważnia wcześniejsze strony
Agentic. Nawet ponowne otwarcie pierwotnego Program z tym samym
SHA i rewizją nie przywraca starych wyników; konieczne jest
rozpoczęcie nowego przebiegu analizy. Obejmuje to również
zwalnianie wtyczki. Aktywny proces ReAct nie jest tym
mechanizmem przerywany, a jedynie przestaje być źródłem
dostępnych przez API dowodów dla starego Program.
Regresja powinna korzystać z rzeczywistego CodeBrowser/Xvfb
z dwoma izolowanymi syntetycznymi programami Ghidry.

**GA-12 — PARTIAL:** polecenie
`ghidrassist-agent agentic-checkpoint --output ...` pobiera
spójny komplet *zachowanych* stron rzeczywistego Agentic i
atomowo tworzy prywatny lokalny plik JSON (0600) z SHA-256,
licznikami utraty źródeł i jednoznacznym statusem.
Istniejących plików nie nadpisuje, nie wykonuje uploadu
i nie wznawia modelu. To trwały **handoff dowodów**,
nie pełny checkpoint LLM, sesji MCP ani uprawnienie do
odtworzenia narzędzi bez nowego Review. Zapisane dowody
można przeglądać offline poleceniem
`agentic-read --input PLIK --offset N --limit 1..100` po
sprawdzeniu SHA-256, bez działającego API i bez ponownej
analizy; status kompletności dotyczy tylko zachowanych źródeł. Dalsze zadania:
sterowana i bezpieczna kontynuacja pełnych sesji modelu,
przekazywanie wszystkich długo stronicowanych narzędzi
oraz weryfikacja kompletności planów poza cache ReAct.

**Bramki:** Java21 brak przecieków między Program, rewizją,
przebiegiem i ograniczeniem budżetu, Python3 atomowy eksport
bez nadpisywania i przy zmianie źródeł; pełny build Ghidra
12.1.4 PUBLIC/Java25 i rzeczywisty syntetyczny Program w
Ghidrze headless, bez modelu AI. Wyniki przypinać do
dokładnego commita SHA. Tylko izolowane dane syntetyczne,
bez Wyse/Precision, bez restartu zatrzymanego Supervisora.


## GA-12 + GA-15 — odrzucanie niepełnych checkpointów i stronicowanie Agentic (2026-11-06)

**Baza:** PR #201 scalony do chronionego `master`
`585b2efe450364b0e73fa17aa1ec8119ab102ecb`,
po 57/57 Actions SUCCESS na SHA
`1e9fc9a7127921043dd08fcd2bd1cfd8e0a15a4d`.
GA-06/11 pozostają PARTIAL: analiza VBR jest tylko statyczna.

**GA-12 — PARTIAL:** odczytowy, opt-in zapis raportu CFG jest
odtwarzalny tylko po dopasowaniu pełnej tożsamości programu
i po walidacji `HardwareDurableCfgReport.eligibleForCompletedRestore`.
Poprawny format/suma kontrolna NIE wystarcza: `limited`,
`!cfgReviewComplete`, `cfgOmitted>0`, `pointersOmitted>0`
albo przekroczony limit tekstu uniemożliwiają użycie
zapisanej migawki jako kompletnej. Zarówno ścieżka zapisu,
jak i przywrócenia egzekwuje tę samą politykę. Dekodowanie
historycznej niepełnej migawki nadal jest możliwe w testach;
nie daje uprawnienia do jej uznania za ukończoną analizę.
Dalsze prace: trwałość częściowych faz i pełnej sesji.

**GA-15 — PARTIAL:** `FindingsCache.page(offset,limit)`
udostępnia deterministyczne strony (maks. 100) zachowanych
źródłowych findings, z kopiami tylko-do-odczytu, wersją
migawki, pełnym licznikiem przyjętych i odrzuconych
przez budżet wyników oraz flagami `sourceIncomplete`,
`hasMore`, `complete`. `page(offset,limit,revision)`
odmawia łączenia stron z różnych wersji analizy.
`complete=true` jest dopuszczalne tylko gdy nie ma
pominiętych wyników, skróconego źródła ani ukrytej
części listy. Zachowana jest dotychczasowa kolejność
wg trafności i niezmieniona polityka redukcji kontekstu.
Dalsze prace: kontrolowane paginowanie wszystkich
złożonych narzędzi Agentic i trwałość sesji modelu.

**Wymagany odbiór:** Java21 regresja dekodowalnych lecz
nieuprawnionych snapshotów, granic paginacji, odrzucenia
starego tokenu wersji oraz brak fałszywego kompletnego
dowodu po evikcji; pełny Ghidra 12.1.4 PUBLIC Java25 build;
prawdziwa syntetyczna Ghidra headless (oddzielne JVM)
z zapisem i bezpiecznym przywróceniem ukończonego etapu
CFG. Wyniki GitHub Actions przypiąć do **dokładnego SHA**,
zamiast nadpisywać historyczne checkpointy. Tylko kopie
syntetyczne; bez Wyse/Precision i zatrzymanego Supervisora.

## GA-06 + GA-11 — jawna tożsamość MC68332 przy relokowanych wektorach (2026-11-06)

**Baza:** PR #200 scalony do `master`
`352af8aa742ebfcae7a37b13526438ef2fd991b8` z **45/45
GitHub Actions SUCCESS** na HEAD `16f1900f1d1e047a166ada4dfcf7d8f181980a76`.
GA-05/08 pozostają PARTIAL poza bezpiecznym nazewnictwem istniejących
typowanych wskaźników.

**GA-06 — PARTIAL, kontrola źródła urządzenia:** funkcja odczytu
relokowanych tablic VBR ma teraz **obowiązkowy argument profilu**
`HardwareProfiles.Profile` i odmawia bez jawnie wybranego, konkretnego
MC68332. Ogólna `CPU32` nie dziedziczy ograniczenia adresów MCU24
ani etykiet źródeł MC68332. Raport źródłowy wskazuje
`MC68332UM` (Motorola 1995), przypięty SHA-256 oryginalnego PDF
NXP `02c2cb99738dd45a785798bba3e7dcc34bb0d54fb5fba42900e6ecb8356bf28a`
i wyraźną granicę: lokalna kopia RAG nie jest uwierzytelniona.
Nie utożsamia to źródła z wykonaniem instrukcji lub fizycznym MCU.

**GA-11 — PARTIAL, klasyfikacja statycznych źródeł ISR:** w
odczytowych, jawnie wybranych tablicach MOVEC-to-VBR rozróżnia się
`OUTSIDE_SELECTED_MCU24_RANGE` i `UNMAPPED_TARGET`.
Wartości 32-bitowe poza `0x000000..0xFFFFFF` nie stają się
kandydatami funkcji/ISR, ale w generycznej tablicy CPU32
pozostają danymi 32-bitowymi. Nie zmieniono interpretacji obrazowej
tablicy spod adresu zero. Raport zachowuje liczniki adresów spoza
MCU24 oraz `runtime VBR UNKNOWN`.

**Bramki odbioru:** Java21 rozdzielone liczniki/negatywne przypadki;
pełny build Ghidra 12.1.4 PUBLIC / Java25; rzeczywisty
syntetyczny program w Ghidrze z `MOVEC D0,VBR`, tablicą pod
`0x800`, wskaźnikiem poza MCU24 `0x01000000`,
odmową dla `cpu32Family()`, rozpoznaniem exact-entry,
interior i odd, bez modyfikacji bazy podczas raportowania;
pełne GitHub Actions przypisane do dokładnego SHA. Brak
dowodu wykonania MOVEC, aktywnej tablicy VBR/IRQ, działania ISR,
zatrzaśniętego MM czy fizycznej mapy magistrali.
Nie uruchamiać lokalnych testów Wyse/Precision i Supervisora.
GA-06/11 pozostają PARTIAL do czasu dalszej walidacji profili,
pośrednich celów ISR i ścieżek rozruchowych.

## GA-05 / GA-08 — istniejące wskaźniki w rzeczywistej Ghidrze (2026-11-06)

**Baza:** scalony [PR #199](https://github.com/bogkom/GhidrAssist/pull/199)
na `master` `a820736ce660a96208b0860fb8fdb6ff12cef9d7`,
po 43/43 GitHub Actions PASS na HEAD
`fd818241ba13c9e93d34094dc4c1a67e384dbe71`. GA-13
nadal PARTIAL (odczytowy audyt rekordów Apply, bez pełnej
historii decyzji i autora).

**GA-05 — rozszerzony zakres Review/Apply/Undo, PARTIAL:**
oddzielny `Review pointers...` wyświetla wyłącznie rzeczywiste
`Function.getParameters` i `getLocalVariables` Ghidry; każda
pozycja domyślnie *niezaznaczona*, dwa jawne potwierdzenia.
Apply dopuszczalny tylko przy spójnej rewizji, tożsamości Program
i wybranym MC68332; rewaliduje komplet listy i adres/ordinal/storage
pola w jednej transakcji z możliwością Undo/Redo. Konflikty
i zmiana/zanik zmiennej powodują pełny rollback.

**GA-08 — rozszerzony zakres, PARTIAL:** niezależnie od
czysto statycznych ról rejestrów A0–A7 możliwe są neutralne,
tylko typowane podpowiedzi dla **istniejących** zmiennych
wskaźnikowych i argumentów, o nazwach domyślnych Ghidry.
Nie są to dowody semantyki MMIO ani automatycznie utworzone
Decompiler HighVariable; nazwy ręczne, nieznane storage,
auto-parametry i typy niewskaźnikowe pozostają nietknięte.
Nadal brakuje analizy zakresów życia wskaźników, ustalenia
HighVariable identity, semantycznych nazw parametrów i
zmiennych bez pewnego typu.

**Bramki CI:** Java21 deterministyczna polityka,
pełny build Ghidra 12.1.4 PUBLIC/Java25 i rzeczywisty
syntetyczny Function DB z dwiema zmiennymi wskaźnikowymi,
zatwierdzony Apply, Undo, Redo oraz odmowa przy nieaktualnej
rewizji, błędnym storage i kolizjach. Test ma działać wyłącznie
w GitHub Actions na izolowanych projektach; bez Wyse/Precision
i zatrzymanego Supervisora. Wyniki przypiąć do dokładnego HEAD
jednego PR. **Nie oznaczać GA-05 ani GA-08 jako DONE**
przed domknięciem ich pełnych wymagań.

## GA-13 — przegląd i audyt potwierdzonych operacji (2026-11-06)

**Baza:** scalenie [PR #198](https://github.com/bogkom/GhidrAssist/pull/198)
do chronionego `master` `b66d0b33b0611a29ea895385b713831a0db2728b`.
Dokładny HEAD PR #198 `7d3721aea072a76b3fa49fa4b7dad658daca024e`
zaliczył **41/41 GitHub Actions SUCCESS**, w tym
Ghidra 12.1.4 PUBLIC / Java25, rzeczywistego syntetycznego
CodeBrowsera i niezależny oficjalny MC68332UM PDF SHA-256.
GA-10/16 pozostają PARTIAL poza statycznym SIMCR/SYNCR
oraz autentycznością kopii z NXP.

**GA-13 — zakres pakietu do zatwierdzenia w CI:** zbiorczy,
w pełni odczytowy audyt wszystkich dotychczas zapamiętanych
wersjonowanych rekordów zatwierdzonego Rename, bez importu/
edycji firmware. Rekordy Ghidra Program Options są korelowane
z aktualnymi Function, Name, SourceType, oryginalnym SHA
i rewizją Program. Wynik wprost odróżnia
`CURRENT_APPROVED_NAME`, `NAME_CHANGED_AFTER_APPROVAL`,
`FUNCTION_MISSING`, `SOURCE_CHANGED`, `SOURCE_UNVERIFIED`
oraz `SOURCE_TYPE_CHANGED`.
Uszkodzony lub nierozpoznany rekord, duplikat albo nadmiar
nie mogą tworzyć pozornego kompletnego audytu.
GUI dodaje `Rename audit CSV...` niezależnie od Analyze;
po dialogu Save/Overwrite następuje ponowna kontrola
Program i całej migawki. CSV ma ochronę formuł Unicode
i ograniczenia rozmiaru zgodne z istniejącym GA-13.

**Kryteria CI:** Java21 kodek potwierdzeń i eksport CSV,
pełny build Ghidra **12.1.4 PUBLIC / Java25**,
rzeczywisty syntetyczny test dwóch FunctionManager nazw
i źródeł w ramach jednej transakcji Apply/Undo/Redo,
oraz dwuprocesowy restart Ghidry (zapis/odczyt Options)
z asercjami audytu i braku zmiany rewizji podczas odczytu.
Dokładne HEAD SHA, ci PASS/FAILED i ograniczenia publikować
w jednym PR. Nie wykonywać testów Wyse/Precision ani
zatrzymanego Supervisora. Ochrona Review/Apply/Undo bez zmian.

**GA-13 — nadal PARTIAL:** odczyt zatwierdzonych wpisów
nie jest niezależną, nieusuwalną historią odrzuconych
propozycji, operacji Undo ani autorstwa człowieka/AI.
Zwykłe Ghidra Undo usuwa także rekord; bez osobnego
mechanizmu autoryzowanego journalingu nie można twierdzić
inaczej. Nowy CSV nie jest wejściem do Apply.

## Obowiązujący checkpoint — GA-10/16 źródłowe SIMCR/SYNCR i PDF (2026-11-06)

**Baza:** [`master` po PR #197](https://github.com/bogkom/GhidrAssist/commit/d401e42178d88a7fe98f77dee8791aeddfabec0f).
Poprzedni [#196](https://github.com/bogkom/GhidrAssist/pull/196)
(HEAD `499fda6ffc621ec6acb8e58f758a6cababea62c7`: **35/35 CI PASS**)
domknął statyczny GA-04, a [#197](https://github.com/bogkom/GhidrAssist/pull/197)
(HEAD `c728bd0b91b30f1afd07fcf2dd2690fd20f3ec29`:
**42/42 CI PASS**, real CodeBrowser/Xvfb) domknął przyjęte
zakresy GA-07 i GA-09. Osobnych Actions PASS na SHA merge nie
stwierdzono; dowody pozostają na dokładnych HEAD PR.

**GA-10 — PARTIAL:** rozszerzenie odczytowego dekodera MC68332
o **5 dodatkowych SIMCR** (EXOFF, FRZSW, FRZBM, SLVEN, SHEN) obok
MM, SUPV, IARB oraz 7 pól SYNCR; tylko pełny, dosłowny `MOVE.W`,
bez reset-state i aktywnego MCU. Rejestry bez wiarygodnych masek
i pola statusowe SLIMP/SLOCK nadal są UNKNOWN. Fizyczne strony
D-5=219, D-6=220, D-7=221 są identyfikowane jawnie.

**GA-16 — PARTIAL:** `HardwareBitfieldSourceLedger` zawiera
15 ograniczonych wierszy *claim-only* rejestr/pole/maska/strona,
z URL dokumentu, deklaracją wydania Motorola 1995, przypiętym
SHA-256 oficjalnego PDF (`02c2cb99738dd45a785798bba3e7dcc34bb0d54fb5fba42900e6ecb8356bf28a`)
i wyraźną granicą **niezweryfikowanej lokalnej kopii RAG**.
Wiersze są częścią Full Evidence, Markdown eksportu i aktualnego
kontekstu RAG, który oznacza pominięte odsyłacze. Dedykowana
[bramka PDF Actions #42233819507](https://github.com/bogkom/GhidrAssist/actions/runs/42233819507)
przeszła porównanie SHA-256 bajtów z NXP, 265 stron i ekstrakcję
D-5/D-6/D-7 (fizyczne 219/220/221) na publicznym runnerze.
Sam parser etykiet nadal nie uwierzytelnia dowolnego lokalnego PDF;
pełny import i ekstrakcja innych tabel nie są gotowe.

**Kryteria odbioru pakietu:** Java21 regresje masek/UNKNOWN,
physical-range parser, stały field ledger i RAG; rzeczywisty
izolowany CodeBrowser/Xvfb z potwierdzeniem widoczności pól
oraz przekazania cytowań do RAG; pełny build Ghidra
**12.1.4 PUBLIC / Java25**; niezależny hash-pinned
publiczny PDF (jeśli pobranie dostępne); dokładny HEAD SHA,
raport CI i checkpoint w tym samym PR. GA-10/16 nie otrzymają
DONE za pokrycie tylko SIMCR/SYNCR lub parsowanie stron.
Nie używać prywatnych firmware, projektu ECU411, lokalnych
testów Wyse/Precision ani zatrzymanego Supervisora.

## GA-07 / GA-09 — pakiet odbiorowy: spójny report, MMIO GUI i Automation API (2026-11-06)

**Baza:** `master` `16635c85dce136bf3902ad22bab01c080cf84d06`,
po zintegrowanym [PR #196](https://github.com/bogkom/GhidrAssist/pull/196)
(na HEAD `499fda6ffc621ec6acb8e58f758a6cababea62c7`:
35/35 Actions SUCCESS). GA-04 w przyjętym statycznym zakresie
MC68332 jest **DONE**; fizyczna mapa i wykonanie pozostają UNKNOWN.

**GA-07 — kandydat do DONE po dowodach CI:** raport 3-częściowy
i Full Evidence składają się teraz w jeden walidowany kanoniczny
Markdown używany przez GUI/eksport i pamięć podręczną AI/RAG.
Brak którejkolwiek części musi zablokować publikację. Eksport ponownie
sprawdza rewizję Program po modalnym wyborze i potwierdzeniu nadpisania
pliku, aby nie zapisać starego raportu. Rzeczywista izolowana Ghidra
w GitHub Actions ma sprawdzić identyczność widocznego Overview,
Full Evidence i opublikowanego Markdown oraz faktyczne dołączenie
źródeł SIMCR do kontekstu RAG. Przepływ pozostaje statyczny i
odczytowy; brak dowodów fizycznego MM/CS/ISR i wykonania.

**GA-09 — kandydat do DONE po dowodach CI:** jeden deterministyczny
algorytm filtrowania i limitowanej paginacji źródłowych rekordów
MMIO zasila zarówno sortowalny explorer Swing, jak i JSON-RPC
Automation API. Wybór w sortowanej tabeli musi być przeliczany
z indeksu widoku na indeks modelu przed Go To Listing. Filtr
pozostaje niezależny od wielkości liter, zachowuje całkowitą liczbę
dopasowań, obsługuje stronę poza końcem oraz odrzuca nieprawidłowe
limity. Przejście do Listing nadal wymaga tej samej rewizji i
tego samego Program. Test rzeczywistego CodeBrowsera/Xvfb powinien
potwierdzić nawigację, odmowę po zmianie programu i zgodność
MMIO Automation API z widocznym wierszem. Nie uruchamiać
historycznych testów Wyse/Precision ani Supervisora.

**Kryteria zamknięcia GA-07/09:** deterministyczne regresje Java21,
pełna kompilacja rozszerzenia Ghidra 12.1.4 PUBLIC / Java25,
odrębny rzeczywisty syntetyczny CodeBrowser/Xvfb, brak FAILED CI,
zapisane dokładne HEAD SHA i ograniczenia w PR.
GA-07/09 otrzymają DONE dopiero po weryfikacji tych dowodów;
oryginalny firmware ECU411, projekt użytkownika i autoryzacja
Review/Apply/Undo pozostają nienaruszone.

## GA-04 / GA-07 — pakiet odbiorowy: kompletna tabela źródłowa CS (2026-11-06)

**GA-04 — zakres odbiorowy DONE po zaliczeniu pełnego CI na HEAD pakietu:** dla
jawnie wybranego MC68332 raport przedstawia dwanaście odrębnych pozycji
CSBOOT i CS0–CS10; tabela warunkowa pokazuje zakres START/END/SIZE lub
`UNKNOWN`, niezależne CSBAR/CSOR i współdzielone CSPAR0/1 oraz stan
kwalifikacji wyłącznie dla lokalnych dowodów funkcji i okna MM.
Sprzeczne literały CSBAR, zapisy o nieznanej wartości i same CSPAR
nie mogą tworzyć okien; mimo to obecność źródeł CS zachowuje dwanaście
wierszy `UNKNOWN`. Wszystkie słowa wejściowe muszą być pełnymi wartościami
16-bitowymi (0..0xFFFF), bez cichego maskowania. Dla CPU32 bez jawnego
modelu MC68332 nie ma dekodowania tych okien. Brak dowodu rzeczywistego
wykonania, MM latch, fizycznej mapy, pinu ani uprawnień Apply/Undo
nie jest błędem zakresu: nie należą do statycznego kryterium GA-04.

**GA-07 — nadal PARTIAL:** trójczęściowy Overview zachowuje podział
inicjalizacja / historia rejestrów / Chip Select i dodatkowo prezentuje
dwanaście wierszy wyłącznie **liczby źródeł zapisów** CSBAR, CSOR oraz
współdzielonych CSPAR; wynik 0/0 oznacza brak obserwacji w Listing/XREF,
nie nieobecność układu. Zestawienie nie łączy wartości z różnych funkcji,
gałęzi i MM; szczegółowe raporty, eksport Markdown i RAG otrzymują
tę samą parę `overviewMarkdown + detailsMarkdown` bieżącej rewizji.
Przed formalnym DONE GA-07 nadal wymagane są odrębne testy spójności
rzeczywistego GUI, eksportu i RAG w zakresie pełnych dowodów.

**Dowody do odbioru:** `ChipSelectTableSelfTest` (12 wierszy,
CSBAR/CSOR/CSPAR, zakresy, brak danych, konflikt, niepoprawne słowa),
`HardwareReportOverviewSelfTest` (12 wierszy źródeł, brak dziedziczenia
MC68332 przez CPU32), wspólne GitHub Actions Java21, pełny build
Ghidry 12.1.4 PUBLIC / Java25 i rzeczywiste syntetyczne testy Ghidry.
Dokładny HEAD, statusy CI oraz merge SHA muszą zostać zapisane w PR
po wynikach. Brak lokalnych testów Wyse/Precision i starego Supervisora.

## Obowiązujący checkpoint — 2026-11-06 (GA-02/03/11 CALL target validation)

**Chroniony `master`:** [`e3c01d8af52509118d27de6588c4607d220122ba`](https://github.com/bogkom/GhidrAssist/commit/e3c01d8af52509118d27de6588c4607d220122ba), po scaleniu [PR #194](https://github.com/bogkom/GhidrAssist/pull/194). Poprzednie checkpointy poniżej są historyczne.

**GA-02/03/11 — CZĘŚCIOWO.** `HardwareCallEffects.FunctionNode` odrzuca teraz ujemne i `null` bezpośrednie cele CALL tak samo jak wadliwe wejścia funkcji. Poprawny nieujemny, ale nierozpoznany cel pozostaje `UNKNOWN`, bez tworzenia globalnej osiągalności RESET/ISR ani negatywnego dowodu braku STORE/VBR.

**Testowany HEAD #194:** `bd9aacefdc93a24b129a5fafa3a92d9c5193ca6e` — **28/28 GitHub Actions SUCCESS**: Java21 source regression, pełna kompilacja Ghidry **12.1.4 PUBLIC / Java25**, rzeczywista izolowana syntetyczna Ghidra i bramki bezpieczeństwa. **Merge SHA:** `e3c01d8af52509118d27de6588c4607d220122ba`; brak odrębnego CI PASS przypisanego do merge SHA w momencie checkpointu. Dowody i ograniczenia zapisano w PR #194.

Issue [#106](https://github.com/bogkom/GhidrAssist/issues/106) OPEN (0 zgłoszeń); #98 pozostaje osobnym zadaniem migracji CodeBrowser. Nie uruchomiono Wyse/Precision, zatrzymanego Supervisora ani prywatnych projektów/firmware ECU411. Statyczne MAY, MM0/MM1, aktywne VBR/IRQ, fizyczne CS i prawa Review/Apply/Undo pozostają rozdzielone.

**Wszystkie GA-01–GA-18 nadal W ROZWOJU; GA-14 ODŁOŻONE.** Następne: GA-01/02/03/11 — konserwatywna obsługa nieznanych wywołań i skutków RESET/VBR/ISR; GA-06/10/16 — weryfikowalne PDF/edycja/digest/strona; GA-12/15 — kompletność dowodów i trwałość checkpointów; GA-17/18 — CI/Automation API.

## Obowiązujący checkpoint — 2026-11-06 (GA-01/02/03/11 report and vector source guards)

**Chroniony `master`:** [`41f42238a9dbe79c23959b533492be9c8dd20377`](https://github.com/bogkom/GhidrAssist/commit/41f42238a9dbe79c23959b533492be9c8dd20377), po scaleniu #192.
Starsze sekcje są zachowanymi historycznymi checkpointami, nie aktualnym HEAD.

| Pakiet | Dokładny HEAD PR | Actions na HEAD | Merge SHA |
|---|---|---|---|
| [#190](https://github.com/bogkom/GhidrAssist/pull/190) — walidacja niekompletnych rekordów SIMCR/MM MAY | `6afc2ce0016f44673e3db56ffadfcef450347494` | **25/25 SUCCESS** | `62ea1c9a23e51525ef401649622239f58615e8cb` |
| [#191](https://github.com/bogkom/GhidrAssist/pull/191) — odrzucenie wskaźników wektorów poprzedzających zadeklarowaną funkcję | `e0d53cd0cfd97c7b1482331f7f83a1bfa2e3f626` | **25/25 SUCCESS po retry** | `dfb989c5b3545a55d4dcbfa87930cd5cf52a7f97` |
| [#192](https://github.com/bogkom/GhidrAssist/pull/192) — walidacja liczników i źródeł STORE/VBR MAY | `41d020bb135de37a1f05a02bb06e5ada72440da0` | **25/25 SUCCESS** | `41f42238a9dbe79c23959b533492be9c8dd20377` |

Wszystkie trzy HEAD PR przeszły deterministyczne regresje Java21, pełne
buildy rozszerzenia Ghidra **12.1.4 PUBLIC / Java25** i inne przypisane
workflow rzeczywistej syntetycznej Ghidry. Na osobnych SHA merge #191
i #192 nie zarejestrowano odrębnych przebiegów Actions — nie oznaczamy
więc ich jako dodatkowego CI PASS. #191 miał pierwotnie 24/25 SUCCESS:
jedyny błąd pochodził z **HTTP 429 Maven Central**, przed uruchomieniem
syntetycznej Ghidry. Ponowiono wyłącznie nieudany job na niezmienionym
SHA, zakończony SUCCESS. Przyczyna i wynik zapisane w PR.

**Status funkcjonalny: CZĘŚCIOWO.** Sprzeczne rekordy dowodów MAY
nie są tolerowane; wskazanie wektora do wnętrza funkcji nie może
poprzedzać jej wejścia. Nie tworzy to nowej krawędzi bezpośredniego
CALL ani rzeczywistej osiągalności RESET/ISR. Wartości MM0/MM1,
aktywne VBR/IRQ, wykonanie STORE i fizyczne CS pozostają nieznane.
Review/Apply/Undo nadal wymagają oddzielnej autoryzacji.

[Issue #106](https://github.com/bogkom/GhidrAssist/issues/106) jest
OPEN (0 zgłoszeń), #98 pozostaje osobną luką CodeBrowsera.
Nie wznowiono lokalnych testów Wyse/Precision ani starego Supervisora,
nie modyfikowano prywatnego firmware ani projektu ECU411.

**GA-01–GA-18 nadal W ROZWOJU; GA-14 ODŁOŻONE.** Dalsze priorytety:
GA-01/02/03/11 — rozdzielanie lokalnych MAY od dowodów statycznego RESET,
niepewnych CALL, VBR i ISR; GA-06/10/16 — autentyczna edycja, strona i
SHA-256 lokalnej kopii PDF; GA-12/15 — kompletność dowodów i checkpointy;
GA-17/18 — CI i Automation API.

## Obowiązujący checkpoint — 2026-11-06 (GA-02/03/11 computed JSR MAY)

**Chroniony `master`:**
[`ff7f831f8576794ad89d14047b81cda3a939a371`](https://github.com/bogkom/GhidrAssist/commit/ff7f831f8576794ad89d14047b81cda3a939a371).
Poprzednie wpisy są historycznymi checkpointami, nie bieżącym HEAD.

**GA-02/03/11 (CZĘŚCIOWO):** Po zintegrowanych #185 i
[#187](https://github.com/bogkom/GhidrAssist/pull/187)
potwierdzone instrukcjami CPU32 pośrednie `MOVEA.L #imm,An`
+ `JSR (An)` nie są bezpośrednimi krawędziami grafu
RESET/ISR. #187 pokazuje oddzielnie ogólne możliwe skutki
pamięci/VBR dla celu takiego wywołania, zachowując
`UNKNOWN` i limit źródeł.

**Zweryfikowana integracja #187:** HEAD
`c908bab9c673166c0ac2b619aad2af3e23fa72f6`,
**52/52 GitHub Actions SUCCESS**; merge
`8fcf2abeddf11b9982061bed8f957d466df45033`,
**15/15 SUCCESS**, identyczne drzewo
`77ea168b8479d6e0f69f80dc3638239e50378b60`.
Oba commity przeszły pełną kompilację
Ghidry **12.1.4 PUBLIC / Java25**; HEAD również realną
syntetyczną Ghidrę CPU32 i Java21.

**Nowa integracja [#188](https://github.com/bogkom/GhidrAssist/pull/188):**
odróżnia ogólny P-code/Listing `STORE` od osobnego
`STATIC_MAY_MM_LOW_BYTE`, `UNKNOWN` lub
`NOT_OBSERVED_IN_BOUNDED_SOURCE` w ścieżce
bajtowo potwierdzonego pośredniego JSR do MC68332.
Ponownie wykorzystuje istniejący transytywny,
ograniczony graf `HardwareInterproceduralMmEffects`.
Brak przypisania wykonania, aktywnego `MM`,
bezpośredniego CALL, RESET/ISR, VBR, fizycznej mapy CS
czy praw do Review/Apply/Undo. Limit 16 źródeł
jest jawny, pominięcia i niepewność zachowane.

**Dokładny HEAD #188:**
`2aba6d4d1542a843cfd7e6c303e532badd1a0d3a`,
**66/66 GitHub Actions SUCCESS**, Java21, pełny build
Ghidry 12.1.4 PUBLIC/Java25 i rzeczywiste izolowane
testy `indirect-adjacent` i `indirect-bounded`.
**Merge SHA:** `ff7f831f8576794ad89d14047b81cda3a939a371`,
**16/16 GitHub Actions SUCCESS**, w tym pełna kompilacja
oraz testy CPU32, RESET i computed CALL. Drzewo Git
HEAD/merge **identyczne**:
`640be531ae7bae27d0ec90603b8cbf197174c659`.

Issue [#106](https://github.com/bogkom/GhidrAssist/issues/106)
pozostaje OPEN (0 nowych wpisów), #98 osobno.
Nie wznowiono Wyse/Precision, starego Supervisora/timerów,
nie używano prywatnego firmware/projektów ECU411.
**Wszystkie GA-01–GA-18 nadal W ROZWOJU; GA-14 ODŁOŻONE.**
Kolejne: GA-01/02/03/11 — konserwatywne dowody
RESET/VBR/ISR przy nieznanych CALL; GA-06/10/16 —
weryfikowalne wydanie, digest i fizyczna strona
konkretnej kopii PDF; GA-12/15 — trwałość
i kompletność źródeł; GA-17/18 — dalszy CI.

## Obowiązujący checkpoint — 2026-11-06 (GA-01/02/03/11 computed CALL XREF)

**Aktualny chroniony `master`:**
[`da88e9b6ea1ff1d04c34910f19d109c6577c0af8`](https://github.com/bogkom/GhidrAssist/commit/da88e9b6ea1ff1d04c34910f19d109c6577c0af8)
po scaleniu [PR #185](https://github.com/bogkom/GhidrAssist/pull/185).
Poprzednie checkpointy zachowane niżej są historią ukończonych
prac, nie bieżącą listą otwartych PR-ów.

**GA-01/02/03/11 — CZĘŚCIOWO:** W Ghidra 12.1.4
`Instruction.getFlows()` może odzwierciedlać odsyłacz
`RefType.COMPUTED_CALL`, w tym ręcznie dodany przez użytkownika.
Poprzednia analiza mogła zinterpretować jeden taki odsyłacz
na instrukcji `JSR (An)` jako krawędź bezpośredniego CALL,
mimo równoległej flagi niepewności. Dawało to fałszywą
**pozytywną statyczną osiągalność** od RESET oraz pozorne
kandydaty skutków MMIO/SIMCR, VBR i ISR.

Nowa bramka `HardwareDirectCallGate` dopuszcza
do grafu bezpośrednich CALL wyłącznie **zdekodowaną instrukcję
CALL bez cechy `computed`**, z jednym celem przepływu
i dokładnie rozpoznanym wejściem funkcji. Obliczany CALL
pozostaje `UNKNOWN`, widoczny w raporcie
`HardwareInterproceduralMmEffects`, nawet jeśli ma jeden
odsyłacz do prawdziwej funkcji. Istniejące ograniczone,
potwierdzane bajtowo możliwości `MOVEA/JSR (An)`
pozostają **osobnymi kandydatami tylko do odczytu**:
nie tworzą globalnej krawędzi, checkpointu ani uprawnienia
Review/Apply.

**Dokładne dowody:** przetestowany HEAD
`a55f3308de67122aecd0a35120092db1abf18125`
([PR #185](https://github.com/bogkom/GhidrAssist/pull/185))
**62/62 GitHub Actions SUCCESS**, Java21, pełna kompilacja
Ghidry **12.1.4 PUBLIC / Java25** oraz rzeczywista
syntetyczna Ghidra (CPU32 `JSR absolute` kontra
`JSR (A1)` + ręczny `COMPUTED_CALL` XREF, wektor
RESET i tablica kandydatów ISR). Po scaleniu
`da88e9b6ea1ff1d04c34910f19d109c6577c0af8`
**14/14 GitHub Actions SUCCESS**, również pełny build
i rzeczywisty test Ghidry. Drzewo Git HEAD i merge
**identyczne:** `570c9ca51da758066485953102e3aa18ae26080d`.

**Niepotwierdzone:** to nadal tylko analiza statyczna,
nie dowód wykonania CALL/RESET, rzeczywistego zapisu SIMCR,
aktywnego MM, VBR/ISR ani fizycznej mapy CS. Brak
niezależnie uwierzytelnionego wydania/strony PDF i pełnej
analizy pośrednich MAY-ścieżek pozostają lukami.
Issue [#106](https://github.com/bogkom/GhidrAssist/issues/106)
otwarte, bez nowych wpisów; #98 osobna migracja CodeBrowsera.
Nie uruchomiono Wyse/Precision, zatrzymanego Supervisora,
timerów, workerów, prywatnego firmware ani testów AI.

**GA-01–GA-18 nadal W ROZWOJU; GA-14 ODŁOŻONE.**
Dalej: kontrolowana, odrębna prezentacja MAY-skutków
wiarygodnie ograniczonych pośrednich CALL, bez fałszywej
osiągalności RESET/ISR; następnie GA-06/10/16 powiązanie
deklarowanego hash/edycji i stron z konkretną kopią PDF;
GA-12/15 zachowanie niekompletnych dowodów.

## Obowiązujący checkpoint — 2026-11-06 (GA-01/11 RESET exact-entry)

**Aktualny chroniony `master`:**
[`cedc0b8aee8f64a48390bae6dbc9e5be3743a030`](https://github.com/bogkom/GhidrAssist/commit/cedc0b8aee8f64a48390bae6dbc9e5be3743a030)
po scaleniu [PR #183](https://github.com/bogkom/GhidrAssist/pull/183).
Poprzednie checkpointy #180–#182 poniżej pozostają historią,
a nie informacją o otwartych gałęziach.

**GA-01/02/03/11 (CZĘŚCIOWO):** Przed poprawką
`GhidraHardwareFlowService.resetStaticCandidates` traktował funkcję
**zawierającą** adres wektora RESET tak samo jak funkcję, której
**wejście** jest dokładnie równe temu adresowi. Wektor wewnątrz
funkcji mógł wskutek tego błędnie dziedziczyć CALL, STORE/MMIO
i kandydatów VBR/ISR z instrukcji poprzedzających RESET PC.
Obecnie tylko dokładne wejście jest źródłowym korzeniem
ograniczonego grafu CALL; przy PC w środku funkcji wynik
`UNKNOWN RESET ROOT — INTERIOR FUNCTION POINTER`, zbiór
`resetCandidateFunctions` pusty, relacje wektorów
`RESET_ROOT_UNKNOWN` i `resetGraphIncomplete=true`.
Nie modyfikuje to projektu Ghidry ani uprawnień Review/Apply/Undo.

**Dokładne wyniki:** HEAD [PR #183](https://github.com/bogkom/GhidrAssist/pull/183)
`904f478c7749c5c98722bc083e429fd873626aa3`:
**104/104 GitHub Actions SUCCESS**; pełna kompilacja rozszerzenia
**Ghidra 12.1.4 PUBLIC / Java25**, Java21 i rzeczywista
syntetyczna Ghidra headless sprawdzająca CPU32 JSR przed
RESET PC oraz bezpieczną zmianę wektora i cache.
Scalony commit `master`:
`cedc0b8aee8f64a48390bae6dbc9e5be3743a030`,
**15/15 GitHub Actions SUCCESS**, łącznie z pełnym buildem
i realnym testem `reset-interior`. Drzewo Git na HEAD
oraz merge SHA jest **identyczne**:
`a6c4211cde462745c564a3e29acc301e3f78aa79`.

**Rozróżnienie wcześniejszego błędu testu:** stary kandydat
`3fb948f7d553e39d37a2d388c0910f05f1366d76`
miał dwa FAILED w nowym teście GUI/headless przez
porównywanie całych raportów, podczas gdy legalne liczniki
computed/reused GA-12 zmieniają się między przebiegami.
Zmiana testu na asercje trwałych faktów RESET/osiągalności
została wykonana przed ostatecznym 104/104 PASS.
Nie uznawano starego SHA za PASS.

**Ograniczenia:** to nadal analiza **statycznych kandydatów**,
nie dowód wykonania RESET, realnego MM/CS, aktywnego ISR/VBR
czy możliwego przebiegu każdej gałęzi. Dla PC wskazującego
środek funkcji ewentualny faktyczny kod od tego PC wymaga
osobnego, bezpiecznego grafu ograniczonego do poprawnego wejścia.
Issue [#106](https://github.com/bogkom/GhidrAssist/issues/106)
otwarte (0 nowych wpisów produktu), osobno #98. Bez Wyse,
Precision, zatrzymanego Supervisora, prywatnego ECU411 ani
testów AI. **GA-01–GA-18 nadal W ROZWOJU; GA-14 ODŁOŻONE.**
Kolejne priorytety: bezpieczny pośredni CALL/MMIO i niepewność
RESET/VBR/ISR (GA-01/02/03/11), weryfikowane wydania i
SHA-256 dokumentacji (GA-06/10/16), trwałe checkpointy
i kompletność dowodów (GA-12/15), ciągły CI (GA-17/18).

## Obowiązujący checkpoint — 2026-11-06 (aktualizacja po PR #181)

Chroniony `master`:
[`f78478ea837f732bf75e0681599cf36ea16f4bd3`](https://github.com/bogkom/GhidrAssist/commit/f78478ea837f732bf75e0681599cf36ea16f4bd3).
Poprzednie checkpointy zachowane niżej są **historią**, nie listą
otwartych zadań ani bieżącego HEAD.

| Pakiet | Dokładny HEAD PR | GitHub Actions na HEAD | Merge SHA `master` | Actions na merge SHA |
|---|---|---|---|---|
| [#180](https://github.com/bogkom/GhidrAssist/pull/180) — GA-02/03/06: odczytowa klasyfikacja bajtów zapisów CALL względem profilu MCU | `cbd8ab1945bff07cd0aede9a7802497a2a4d0d20` | **58/58 SUCCESS** | `28392aaf0526d37d9656f19a2effd3a35028ee78` | **12/12 SUCCESS** |
| [#181](https://github.com/bogkom/GhidrAssist/pull/181) — GA-06/10/16: właściwe folia MC68332UM D-4/D-5 dla CSBAR/CSOR | `b974b006efc3f39b00b8a9807857f8dae9595746` | **30/30 SUCCESS** | `f78478ea837f732bf75e0681599cf36ea16f4bd3` | **4/4 SUCCESS** |

Dla #180 oraz #181 drzewo Git na przetestowanym PR HEAD
jest **identyczne** z drzewem scalonego commita
(odpowiednio `480498b188547b440627ee9e9d4aa3784d907cd2`
oraz `98a8181f1c8af1e4a35e8fcbc86b2a63f09bb40c`).
Oba pakiety na własnych HEAD przeszły Java21, pełny build
**Ghidry 12.1.4 PUBLIC / Java25** i rzeczywistą syntetyczną
Ghidrę headless; osobne testy `master` potwierdziły ponownie
pełny build na dokładnych merge SHA.

**GA-02/03 — CZĘŚCIOWO.** Dla już pokazanych kandydatów STORE
w kontekście jednego lub dwóch bezpośrednich CALL rozróżniamy
`EXACT_BYTE_RANGE`, `PARTIAL_REGISTER` i
`SPANNING_WHOLE_REGISTER`, łącznie z MM0/MM1 jako
alternatywnymi mapami. Liczba miejsc STORE i ograniczenia dowodów
nie uległy rozszerzeniu. Pełne pokrycie bajtów **nie jest**
dowodem znanej wartości rejestru, aktywnego MM, rzeczywistego
wykonania ani fizycznej mapy CS. Nie uprawnia do Review/Apply.

**GA-06/10/16 — CZĘŚCIOWO.** W oficjalnym MC68332UM, © Motorola
1995, NXP/Freescale-hosted PDF, źródłowa tabela D-2 zawiera
CSBAR0..4 na drukowanej D-4 (fizyczna PDF 218), a CSOR4..10
oraz CSBAR5..10 na drukowanej D-5 (PDF 219). Precyzyjny podział
CSBAR4/CSOR4 potwierdzają testy wszystkich 22 rejestrów.
Odsyłacze w kodzie nadal są **deklaracjami metadanych**:
nie uwierzytelniono żadnej osobno zaimportowanej kopii PDF
ani jej SHA/edycji, nie rozpoznano stanu układu ani wartości reset.

Issue [#106](https://github.com/bogkom/GhidrAssist/issues/106)
pozostaje otwarte bez nowych wpisów produktu;
[#98](https://github.com/bogkom/GhidrAssist/issues/98)
to osobna luka migracji historycznego CodeBrowsera.
Nie wznowiono lokalnych testów Wyse/Precision, timerów,
workerów lub starego Supervisora. Nie zmieniano firmware ECU411,
oryginalnego projektu Ghidry, OAuth ani profili użytkownika.

**GA-01–GA-18: nadal W ROZWOJU; GA-14: ODŁOŻONE.**
Dalsze zależności: GA-01/02/03/11 — ograniczone źródła CALL/RESET;
GA-06/10/16 — weryfikowalna edycja/strona i digest wybranej
kopii PDF; GA-08/12/13/15 — bezpieczne decyzje, checkpointy
i kontrola niepełnych dowodów; GA-17/18 — CI + Automation API v3.

## Obowiązujący checkpoint — 2026-11-06 (GitHub)

**Chroniony `master`:**
[`70a9deeceb029379b21b7be7244051959568f81d`](https://github.com/bogkom/GhidrAssist/commit/70a9deeceb029379b21b7be7244051959568f81d),
po standardowym scaleniu [PR #178](https://github.com/bogkom/GhidrAssist/pull/178).
Poprzednie checkpointy i kandydaci poniżej są **historią**, nie aktualnym
stanem otwartych PR-ów. Nie nadpisywano ich dowodów ani SHA.

| Pakiet | Dokładny HEAD PR | Actions na HEAD PR | Merge SHA `master` | Actions na merge SHA |
|---|---|---|---|---|
| [#177](https://github.com/bogkom/GhidrAssist/pull/177) — GA-02/03: 8/16/32-bit STORE obejmujący bazę śledzonego MMIO, także z zawinięciem MCU24; jeden/dwa CALL | `4afa69aaba9b13c67abcb3c0f1d850be2793848a` | **37/37 SUCCESS** | `a94c11a3f164524c74230dfc09d62cb67ae34070` | **3/3 SUCCESS** |
| [#178](https://github.com/bogkom/GhidrAssist/pull/178) — GA-06/10/16: odrzucanie niewidocznych znaków w deklaracjach fizycznych stron PDF | `e1c725192e8d9e4b00d5a4b1e4cba10b312f7e11` | **28/28 SUCCESS** | `70a9deeceb029379b21b7be7244051959568f81d` | **4/4 SUCCESS** |

W obu przypadkach drzewo Git kandydata i scalonego commita jest
**identyczne** (odpowiednio `0bbb826142f4855395f42ac3888021c32549b7a1`
oraz `d7e6a97926967a1b452d0090273599dc63803da5`).
Na HEAD PR i osobnych SHA `master` przeszły pełne kompilacje
GhidrAssist dla **Ghidry 12.1.4 PUBLIC / Java 25**; na HEAD również
Java 21 oraz istniejące rzeczywiste, izolowane testy syntetycznej
Ghidry headless. Checkpointy szczegółowe zachowano w komentarzach PR.

Od ostatniego checkpointu #170 do obecnego `master` scalono również
[#171](https://github.com/bogkom/GhidrAssist/pull/171) (roadmapa),
[#172](https://github.com/bogkom/GhidrAssist/pull/172) (pośredni JSR,
źródło bajtowe bez promocji CALL),
[#173](https://github.com/bogkom/GhidrAssist/pull/173) (źródłowe
MC68332 SYNCR),
[#174](https://github.com/bogkom/GhidrAssist/pull/174) (ograniczony
NOP/MOVEQ → pośredni JSR),
[#175](https://github.com/bogkom/GhidrAssist/pull/175) (obcy XREF
nie zamyka wyliczanego JSR) i
[#176](https://github.com/bogkom/GhidrAssist/pull/176) (XREF z instrukcji
nie-CALL nie tworzy osiągalności CALL).
Wszystkie są `merged=true`; nie należy ich traktować jako nadal
oczekujących gałęzi produktu.

**Dowody pozostają statyczne / CZĘŚCIOWE:**
GA-02/03 wykazuje tylko potencjalne aliasy zapisów MMIO w wybranych
kontekstach funkcji i CALL — nie wykonany RESET, przyjęty bit MM,
przypisany rozmiar rejestru z samych granic STORE ani fizyczną mapę CS.
GA-06/10/16 weryfikuje składnię **deklaracji** strony, nie stronę
konkretnego wydania manuala czy autentyczność PDF. Nie modyfikowano
oryginalnego firmware ECU411 ani projektu Ghidry. Zachowano
Review/Apply/Undo i ochronę źródeł.

Issue [#106](https://github.com/bogkom/GhidrAssist/issues/106)
otwarte, **0 nowych komentarzy produktu** przy rozpoczęciu tury;
[#98](https://github.com/bogkom/GhidrAssist/issues/98)
pozostaje osobną luką migracji historycznego profilu CodeBrowser.
Nie uruchomiono lokalnych Wyse/Precision, zatrzymanych timerów,
starego Supervisora, sesji workerów ani testów modeli AI.

**GA-01–GA-18 to nadal rozwijane obszary; GA-14 ODŁOŻONE.**
Najbliższe zależności: GA-01/02/03/11 (bounded CALL/RESET, MMIO alias
i formalne granice wiedzy), GA-06/10/16 (wydanie i dokładna strona
manuala), GA-08/12/13 (Review/Apply/Undo, trwałe checkpointy),
GA-15 (kompletność kontekstu/dowodów) oraz GA-17/18 (deterministyczne
Ghidra Actions i zintegrowane Automation API v3).

## Obowiązujący checkpoint — 2026-11-05 (odczyt GitHuba)

Chroniony `master`: `aca665f84144cdd9b057a3968a9d1867f52f701c`,
po scaleniu [PR #170](https://github.com/bogkom/GhidrAssist/pull/170).
**GA-01–GA-18 to 18 nadal rozwijanych obszarów**, nie lista
zaliczonych pojedynczych przypadków; **GA-14 pozostaje ODŁOŻONE**.
Starsze sekcje opisujące „kandydatów”, stan z 4.11 albo
„otwarte PR-y” poniżej zachowano jako **historyczny zapis**,
nie bieżący status tych gałęzi. Wszystkie wyniki odnoszą się do
dokładnych SHA GitHuba, a nie do sesji Wyse/Precision.

| Zmiana | Przetestowany HEAD PR | GitHub Actions na HEAD | Scalone do master |
|---|---|---|---|
| [#168](https://github.com/bogkom/GhidrAssist/pull/168) — prawdziwa CPU32 składnia `D1w*0x1` i `MOVEQ -0x1` w kontekście dwóch CALL | `11df091e886ea0f4a647772b85995b95da249ae2` | **47/47 SUCCESS** | `5e7c3fcbda89ef1e3ba78b53fbfcbf0676885d6b` |
| [#169](https://github.com/bogkom/GhidrAssist/pull/169) — granice indeksowanego przesunięcia 32-bit przed maskowaniem MCU24 | `c58a1579fe7da500490dd141066ebe86eda7b3e7` | **34/34 SUCCESS** | `9e84d8e7208922dd9fb02ca163f000603b20cdf1` |
| [#170](https://github.com/bogkom/GhidrAssist/pull/170) — real CPU32 `D1.W*2`, sign extension, zawijanie 24-bit po dwóch JSR | `6a5973f08566eec837484c7b7df5a17acba88e3b` | **23/23 SUCCESS** | `aca665f84144cdd9b057a3968a9d1867f52f701c` |

Po scaleniu: na osobnych SHA `master` #168 **12/12 SUCCESS**,
#169 **4/4 SUCCESS** i #170 **2/2 SUCCESS** (w każdym pełna
kompilacja rozszerzenia Ghidry 12.1.4 PUBLIC/Java25; liczby dotyczą
jedynie uruchomionych workflow danego merge SHA).
PR-y zawierają trwałe checkpointy wyników i ograniczeń;
nie należy zastępować ich pojedynczym syntetycznym PASS.

**GA-02/03 (CZĘŚCIOWO):** statyczny indeksowany adres MCU24
i przekazanie A0/D0/D1 przez dokładnie dwa bezpośrednie JSR
przetestowano na rzeczywistej izolowanej Ghidrze. Niedostępny
D1 to nieznany alias; adresy SIMCR/CSBAR pozostają tylko
możliwymi źródłami STORE. Nie dowiedziono wykonanego RESET,
write-once MM, aktywnego VBR/ISR, pośrednich celów CALL ani
fizycznej mapy CS. Trwałe Review/Apply/Undo pozostaje
odrębną, zatwierdzaną ścieżką.

**GA-17/18 (CZĘŚCIOWO):** wyznacznikiem są regresje Java21,
pełny build Ghidry 12.1.4 PUBLIC/Java25 oraz rzeczywista
syntetyczna Ghidra headless/CI; Automation API v3 pozostaje
zintegrowanym torem produktu. Historyczne testy
Wyse/Precision/legacy Supervisor pozostają zatrzymane.
Issue [#106](https://github.com/bogkom/GhidrAssist/issues/106)
otwarte, bez nowych komentarzy produktu. Issue #98
utrzymuje osobną lukę migracji starego CodeBrowsera.

**Następne kryteria:** GA-01/02/03/11 — większe, bezpiecznie
ograniczone statyczne ścieżki i pośrednie aliasy MMIO,
wciąż bez twierdzeń o runtime. GA-06/10/16 —
wydanie/strona dokumentacji sprzętowej. GA-08/12/13 —
bezpieczna edycja i trwałość decyzji. GA-15 —
długie przebiegi i kompletność dowodów. GA-17/18 —
dalsze regresje w Actions i przez Automation API.

## GA-01/11 — kandydat 2026-11-05: niepewność RESET w korelacji wektorów

W `HardwareVectorResetCorrelation` istniejące `flowUncertain` musi
uwzględniać również brak rozpoznanego korzenia RESET lub niekompletny
graf połączeń, nawet gdy lokalne poddrzewo wektora jest domknięte.
Zachowujemy adresy, relacje statyczne i niezależne kandydaty STORE/VBR.
Java21 i pełny build Ghidry 12.1.4 PUBLIC / Java25 wymagają PASS na
dokładnym SHA. Nie jest to dowód wykonania RESET/ISR.

## GA-01 — kandydat 2026-11-05: kolejka RESET i cykle CALL

Statyczny graf wywołań RESET ma odrzucać eksplozję powtórzonych ścieżek:
kolejka BFS harmonogramuje każdy bezpośredni cel tylko raz i pozostaje
ograniczona liczbą węzłów. Wykrywanie cykli jest niezależne od drzewa
najkrótszych ścieżek (Kahn); zbieżność ani zdublowana krawędź nie oznacza
rekurencji. Przekroczenie rozmiaru grafu lub kolejki oznacza
`TRUNCATED/UNKNOWN`, nie dowód braku SIMCR/VBR. Java21 i pełny build
Ghidry 12.1.4 PUBLIC / Java25 wymagają osobnego PASS na SHA PR.
Nie oznacza to wykonania RESET ani aktywnych przerwań.

## GA-12 — kandydat 2026-11-05: tożsamość właściciela epoki CFG

Odczytowe generacje unieważniania checkpointów mają być izolowane na
**konkretny obiekt Ghidra Program**, nie przez `equals()` współdzielony
przez dwa odrębne obiekty. `WeakHashMap` zastąpiono słabymi kluczami
identyczności z `ReferenceQueue`. Java21 testuje kolidujące `equals`,
niezależne unieważnienia oraz niezarejestrowanego właściciela. Czas życia
programu i wersja analizy nadal są weryfikowane osobno. CI i pełny
build Ghidry 12.1.4 wymagają odrębnego PASS na SHA PR. Nie oznacza
to wznowienia obliczeń między różnymi Program/JVM.

## GA-06 — kandydat 2026-11-05: źródła HTTPS w manifestach

Ograniczenie strukturalnego podglądu zewnętrznych profilów: zewnętrzny
`DOCUMENT` wymaga jednoznacznego URI HTTPS z hostem, bez userinfo,
Unicode bidi/niewidocznych znaków i osadzonych CR. Standardowy CRLF,
ścieżki kodowane procentowo i zapytania są zachowane. Nie jest to
weryfikacja źródła PDF ani wydania i nie wykonuje importu. Wymagane
Java21 regresje parsera i pełny build Ghidry 12.1.4 na własnym SHA.

## GA-02/03 — kandydat 2026-11-05: wspólny budżet CALL i memoizacja

Nowa, niezależna gałąź po scalonym #148: memoizacja odczytowych podsumowań
konkretnego celu CALL w obrębie jednego przebiegu oraz wspólny limit
**16 384 zaplanowanych adresów** obejmujący także nieznane cele. Wyniki
po wyczerpaniu budżetu pozostają jawnie `LIMITED/UNKNOWN`; nie są
negatywnym dowodem braku SIMCR/MM ani zgodą Review/Apply. Przewidziane
regresje Java21: współdzielone cele, dwa duże grafy z nieznanymi
krawędziami, utrata budżetu przed znanym MM, porządek deterministyczny,
niepoprawni callerzy. Wymagany odrębny PASS CI i pełna kompilacja
Ghidry 12.1.4 PUBLIC / Java25 na dokładnym SHA. Bez testów lokalnych
Wyse/Precision i zatrzymanego Supervisora.

## GA-13 — aktualizacja 2026-11-04 po scaleniu PR #146

Chroniony `master` po [PR #146](https://github.com/bogkom/GhidrAssist/pull/146):
`ab0c61afac00e164c9b5ce2916444e3c297c451b`.
Dokładny HEAD pakietu:
`873eccb278f635c7882617574a3bc3625bc9ff6d`,
**22/22 GitHub Actions SUCCESS**, w tym Ghidra 12.1.4 PUBLIC / Java25
z prawdziwym syntetycznym `FunctionManager`, transakcyjnym
GhidrAssist Apply/Undo/Redo i testem Java 21. Identyczne drzewa Git
przed i po scaleniu:
`687c1122c84480b03029b155c5e218e31378520d`.
Na osobnym SHA scalonego `master` zakończyły się
**3/3 GitHub Actions SUCCESS**, w tym pełna kompilacja rozszerzenia,
GA-12 rewizje i źródłowy test GA-13.

Dla GA-13 zaimplementowano w Program Options **wersjonowaną
informację o zatwierdzonej przez GUI operacji zmiany nazwy funkcji**,
zapisując ją w tej samej transakcji co `setName`; Undo/Redo
przywraca zarówno nazwę, jak i rekord. To **częściowe**
pochodzenie operacji, nie ustalenie autorstwa ani audyt wszystkich
edycji Ghidry, a hash jest kontrolą integralności, nie podpisem.

**Nowy kandydat testowy:** weryfikacja trwałości rzeczywistych
danych Program po **zapisie i niezależnym uruchomieniu Ghidry w
drugim JVM**, na tej samej syntetycznej bazie. Jeden przebieg
tworzy i zapisuje zatwierdzoną nazwę z rekordem, drugi bez
ponownego importu odczytuje Function/Options i sprawdza
brak skutków ubocznych odczytu. Testy `ga13-receipt-restart-headless`
wymagają własnego PASS na dokładnym SHA; nie traktować starego
Undo/Redo PASS jako dowodu trwałości po restarcie.

Issue #106 pozostaje otwarte bez komentarzy wymagających poprawy;
#98 jest osobną migracją CodeBrowser. Bez Wyse/Precision/legacy
Supervisor; wyłącznie syntetyczne dane Ghidry na Actions.
GA-01–GA-18 nadal rozwijane; GA-14 odłożone.

## Aktualny stan — 2026-11-04, scalony PR #145 i rozwój GA-13

GitHub `master` po właścicielsko zatwierdzonym [PR #145](https://github.com/bogkom/GhidrAssist/pull/145):
[`d77f679977645961673c7727074df105c027cd49`](https://github.com/bogkom/GhidrAssist/commit/d77f679977645961673c7727074df105c027cd49),
drzewo `07ae919f359abf3c928f7bc4db94e87875143ba1`
**identyczne** z przetestowanym PR HEAD
`9e1eec99d28919f8da2b9f3abafc6b901c2cb2de`.
Na HEAD **21/21 GitHub Actions SUCCESS**, w tym Java21, pełna
kompilacja Ghidry 12.1.4 PUBLIC / Java25 i rzeczywista syntetyczna
Ghidra headless; **na dokładnym scalonym master 2/2 GitHub Actions
SUCCESS**, osobno Java21 nazw/CSV i pełny build.

**Priorytet następny GA-13:** oparta na istniejącym `Review names…`
trwała, wersjonowana informacja o **konkretnej operacji nazwania
funkcji**, przechowywana w Ghidra Program Options i zapisywana
**w tej samej transakcji** co zaakceptowane `setName`.
Zawiera Function entry, przed/po, źródłowy import SHA (nie SHA
nowszego programu), rewizję przeglądu, statyczną rolę, zebrane
rejestry i licznik unikalnych miejsc zapisu. Odporny na niepełne
pola i zmianę formatu odczyt ma umożliwiać powiązanie Undo/Redo
z usunięciem/przywróceniem rekordu. Wpis przypisuje operację
GhidrAssist, **NIE** potwierdza autora ludzkiego/AI; hash jest
kontrolą spójności, nie uwierzytelnieniem.

Wymagane testy: Java21 deterministyczny codec i limit pól;
rzeczywista izolowana Ghidra 12.1.4 PUBLIC z dwufunkcyjnym
Apply, rollback, Undo, Redo i ponownym Undo; pełna kompilacja
rozszerzenia na **dokładnym nowym SHA**. Ten pakiet pozostaje
kandydatem do czasu weryfikacji CI. Nie rozszerza Review/Apply
uprawnień ani nie twierdzi o wykonaniu ECU411.

Issue #106 nadal otwarte (zero nowych komentarzy); Issue #98
osobna luka migracji starego CodeBrowser. Wszystkie GA-01–GA-18
pozostają rozwojowe, GA-14 odłożone. Wyse/Precision/legacy
Supervisor nie uruchomiono.

## GA-02/03 oraz GA-08/13 — 2026-11-04, po scaleniu PR #144

Na wyraźnej wcześniejszej zgodzie właściciela na bezpieczne scalanie
przetestowanych pakietów zamknięto
[PR #144](https://github.com/bogkom/GhidrAssist/pull/144)
z `merged=true`. Chroniony `master`:
[`30b1a9146b19939d884200648d545fb45797620c`](https://github.com/bogkom/GhidrAssist/commit/30b1a9146b19939d884200648d545fb45797620c).
Dokładny, przetestowany PR HEAD:
`406d4464efaf3ccf3ef55064b4244c46909ffe67`;
**20/20 GitHub Actions SUCCESS** (Java21, Ghidra
12.1.4 PUBLIC / Java25 i rzeczywista syntetyczna Ghidra headless).
Drzewa Git PR HEAD / merge są identyczne:
`cb7b23d97a20f46c4167847be0daf3d8979b37ac`.
Po scaleniu osobna pełna kompilacja na dokładnym merge SHA
**1/1 GitHub Actions SUCCESS** ([41885764324](https://github.com/bogkom/GhidrAssist/actions/runs/41885764324)).
GA-02/03 pozostają **CZĘŚCIOWO**: kolejka transytywnego grafu CALL
jest teraz limitowana również liczbą zaplanowanych i nierozpoznanych
węzłów; głęboka detekcja cykli nie przepełnia stosu Javy.
Wynik `LIMITED/UNKNOWN` nie wyklucza późniejszego STORE SIMCR/MM.

**Nowy, niezależny pakiet GA-08/13:** zabezpieczenie trzeciego
(starszego) eksportu CSV z podpowiedziami **ról wskaźników** przez
wspólny encoder komórek Review (limit 512 znaków, maskowanie
formuł/Unicode) oraz osobny limit 5000 wierszy z licznikiem
`OMITTED_ROWS` i znacznikiem `INCOMPLETE_EXPORT_NEVER_AUTO_APPLY`.
Nie tworzy automatycznych nazw, zatwierdzeń, rzeczywistej historii
autorów ani trwałego dziennika Undo; wymaga własnych nowych
regresji Java21/Ghidra 12.1.4 i **PASS na dokładnym SHA** przed
scaleniem.

Issue #106 nadal otwarte bez nowych problemów; Issue #98 pozostaje
osobną luką migracji starego CodeBrowser. Wszystkie 18 obszarów
nadal rozwojowe, GA-14 odłożone. Nie uruchomiono zatrzymanych
testów Wyse/Precision, timerów, sesji ani Supervisora.

## Aktualizacja GA-02/03 — 2026-11-04, po scaleniu #142 i #143

**Źródło stanu: GitHub.** Właściciel wcześniej zatwierdził scalanie
przetestowanych pakietów. [PR #142](https://github.com/bogkom/GhidrAssist/pull/142)
dotyczący ograniczonych wejść one-hop/two-hop został scalony do chronionego
`master` jako `98be5608eac121e1dcd141fb6db651724e5172ef`.
Zachowano identyczne drzewo Git PR i merge SHA
`394e47d945524bfb5291b677333d6e388bf05cf8`.
Dokładny PR HEAD: `e3384ed94940c781ac788feb5e04fe773d9cb89e`,
**21/21 GitHub Actions SUCCESS**, w tym Java21, pełny build
Ghidry 12.1.4 PUBLIC / Java25 i syntetyczna Ghidra headless.
Na dokładnym merge SHA: osobny **1/1 CI SUCCESS** (pełny build).

[PR #143](https://github.com/bogkom/GhidrAssist/pull/143)
zabezpiecza starsze eksporty CSV propozycji nazw rejestrów/funkcji
przed formułami ukrytymi znakami Unicode. Przeszedł **21/21 GitHub
Actions SUCCESS** na dokładnym HEAD
`935fa6b9efc6e6dc8470f10d06f0533512ae95b9` i został scalony
jako `4664e4d3e3a33ccf9b52c24a89d5a42533d6066d`.
Drugi merge dodaje tylko sześć plików PR #143 do #142; kontrola
blobów potwierdziła brak nadpisania plików źródłowych obu pakietów.
Po scaleniu końcowy SHA uzyskał oddzielny **2/2 CI SUCCESS**
(pełny build + Java21 nazwy/CSV). Te kontrole nie dowodzą
ruchu na ECU411 ani prawdziwego autorstwa zmian.

**Bieżący następny pakiet GA-02/03:** rozwiązać ryzyko nieograniczonej
kolejki transytywnego CALL w `HardwareInterproceduralMmEffects` przez
deduplikację i `maxCount` także dla zaplanowanych/nieznanych adresów,
oraz zastąpić rekurencyjne wykrywanie cykli iteracyjnym DFS.
Przekroczenie budżetu pozostaje jawnie **LIMITED/UNKNOWN**, bez
fałszywego wniosku o braku zapisów SIMCR/MM. Deterministyczne testy
Java21 mają obejmować szeroki graf, głęboki ciąg krawędzi, prawdziwy
cykl, wielokrotne wspólne cele oraz nieznane węzły.
**Przyszłego CI PASS nie wolno zakładać przed wynikiem na dokładnym SHA.**

Issue #106 pozostaje otwarte bez nowych wpisów. PR #98 zachowuje
oddzielną lukę migracji profilu CodeBrowser. GA-01–GA-18 nadal
nieukończone; GA-14 odłożone. Testy lokalne Wyse/Precision i
stary Supervisor pozostają zatrzymane.

## Kontynuacja GA-02/03 — 2026-11-04, po scaleniu #141

Chroniony `master` po właścicielsko zatwierdzonym PR #140 i
niewielkim, przetestowanym PR #141: merge SHA
[`703693c52fee4e300e2a896dba4b475262672459`](https://github.com/bogkom/GhidrAssist/commit/703693c52fee4e300e2a896dba4b475262672459).
PR #141 zachował zgodne drzewo źródeł i uzyskał **25/25 GitHub
Actions SUCCESS** na dokładnym HEAD oraz **1/1 SUCCESS** (pełna
kompilacja Ghidry) po scaleniu na dokładnym merge SHA.
Zależne #133–#139 zostały zamknięte administracyjnie po sprawdzeniu,
że ich commity są przodkami `master`. Historia i dowody nie zostały
nadpisane, nie wykonywano drugiego scalania.

Nowy pakiet GA-02/03 na osobnej gałęzi dodaje walidację wejścia
dla `one-hop` / `two-hop`: maksymalnie 4096 źródłowych adresów
rejestrów MC68332, brak `null` i adresów spoza przestrzeni 24-bit;
dodatkowo w `one-hop` maksymalnie 96 opisów callee. To ochrona
odporności i kompletności **kontekstu źródłowego**, a nie nowe
twierdzenie o wykonaniu CALL, rzeczywistym SIMCR/MM, VBR czy
fizycznym CS. Regresje obejmują progi i izolację wyników; **PASS
dla nowego SHA należy potwierdzić osobno**, nie na podstawie master.

Zależności dalej rozwojowe: wielopoziomowy GA-02/03, trwałe
Review/Apply/Undo i pochodzenie decyzji GA-08/13 oraz PDF
GA-06/10/16. GA-14 nadal odłożone, Issue #106 otwarte bez nowych
problemów; Wyse/Precision/legacy Supervisor pozostają zatrzymane.

## Aktualizacja master — 2026-11-04, po zatwierdzonym scaleniu PR #140

Na wyraźne polecenie właściciela [PR #140](https://github.com/bogkom/GhidrAssist/pull/140)
został scalony standardowym merge do chronionego `master`.
Commit scalający: [`73363ccd881efb976b0690857acb6157398b20d2`](https://github.com/bogkom/GhidrAssist/commit/73363ccd881efb976b0690857acb6157398b20d2).
Dokładny HEAD kandydata:
[`eccdc7ac7743533c2df7a6f477fe33367f247572`](https://github.com/bogkom/GhidrAssist/commit/eccdc7ac7743533c2df7a6f477fe33367f247572).

- **55/55 GitHub Actions SUCCESS** na kandydata SHA, w tym Ghidra
  **12.1.4 PUBLIC / Java 25**, Java 21, rzeczywista syntetyczna
  Ghidra headless z CALL/VBR/ISR i trwałym checkpointem oraz
  deterministyczne testy bezpieczeństwa.
- **Identyczne drzewa Git** na kandydacie i commicie scalającym:
  `4b7f55449acf6de0552532d91bed6e71522319d9`.
  Odrębne workflow `master` na **dokładnym merge SHA**:
  **11/11 GitHub Actions SUCCESS**, w tym pełna kompilacja rozszerzenia.
- Historia oryginalnych PR-ów **#133–#139** została zachowana w
  dwurodzicowych commitach integracyjnych. #135 obejmuje GA-02/03
  jednopoziomowy CALL i GA-11 MOVEC/VBR; #136 dwa poziomy CALL;
  #137 podpis checkpointu rozróżniający `null` i `-1`;
  #138 eksport CSV odporny na niewidoczne prefiksy Unicode;
  #139 właściwe pochodzenie tabel VBR zamiast etykiety image-zero.
  W testowym pliku Ghidry zachowano obie regresje CALL/VBR.
- **Wszystkie 18 obszarów pozostają rozwojowe** według kryteriów z tabeli
  poniżej; to rozszerzenie bazy GA-02/03/11/12/13, a **nie** dowód
  wykonania kodu na ECU411, aktywnego MM/VBR, fizycznego dekodowania CS
  ani ukończenia GA-01–GA-18. GA-14 wciąż odłożone.
- Issue #106 nadal otwarte (brak nowych zgłoszeń); Issue #98 to
  niezależna luka migracji starego profilu CodeBrowser. Nie wznowiono
  lokalnych testów Wyse/Precision, zatrzymanych workerów, timerów
  ani Codex Supervisora. Testy kolejnych zmian pozostają CI-first.

Punkt kolejnej kontynuacji: pogłębianie GA-02/03 statycznych przepływów
pośrednich rejestrów, bezpieczne checkpointy GA-12 oraz pochodzenie
Review/Apply/Undo GA-08/13; dokumentacja profilowa GA-06/10/16 z
wydaniem i stroną PDF.

## Historyczny stan — 2026-11-04, po kontrolowanym scaleniu PR #131

**GitHub = źródło prawdy.** [PR #131](https://github.com/bogkom/GhidrAssist/pull/131)
został scalony standardowym merge przez chroniony `master`,
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
