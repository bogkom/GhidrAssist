# GhidrAssist — 18-track hardware-analysis development ledger

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
