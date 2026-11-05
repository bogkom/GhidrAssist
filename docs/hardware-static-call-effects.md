# Bounded transitive direct-call side-effect evidence (read-only)

Stage 2/4 incremental interprocedural *candidate* analysis. Previous
Hardware Analysis reported static callers but could not show whether
recognized callees contained memory writes or MOVEC-to-VBR operations.

The bridge now constructs an in-memory **static call graph** while iterating
Ghidra's decoded Function bodies. For each function it records:

- whether its decoded instructions contain any P-code `STORE`;
- whether a decoded instruction writes the VBR control register through MOVEC;
- direct call destinations whose Ghidra Functions are resolved;
- unknown computed flows, unknown call destinations, unsupported P-code
  CALLOTHER and partially decoded function bodies.

A new bounded pure-Java graph analyzer follows up to **4 call edges** or
**100 distinct functions** for the interesting hardware-evidence functions.
It reports transitive *possible* memory-store/VBR effects, unresolved call
targets and recursion. It never treats a missing or cyclic callee as a
harmless empty function. The Markdown report is limited to 60 roots.

**Important distinctions:** This is a *may-effect inventory*, not a dynamic
call graph, a boot-execution trace, a full memory map or proof that writes
execute. `memory_STORE_candidate=false` means only that no P-code STORE was
seen within a bounded, decoded static graph; asynchronous interrupts,
firmware mutation and unsupported paths remain outside the model. No
callee's pointer values, MM state or register values are propagated back
into callers. The existing CALL_BARRIER remains conservative.

Pure Java regressions cover direct-chain transitive writes, diamonds,
unknown/external callees, recursion, maximum depth and node count. GitHub
Actions compiles the complete extension with Ghidra 12.1.4.

This can later support *provably safe* call-summary effects once model
scope, missing code, bus function codes, and interrupt/exception ordering
are handled. It makes no Ghidra project changes, accesses no private BIN,
and never identifies MC68332 automatically.

## GA-02/03 — bounded CALL-site SIMCR/MM provenance

With an explicitly selected MC68332 profile, the report now correlates
individual decoded CALL PCs with bounded transitive candidate SIMCR low-byte
writes in their resolved callees. A STORE of 8/16/32 bits touching either
candidate SIMCR MM-low-byte address can contribute a possible site. Unknown
aliases, missing targets, truncated/incomplete functions, recursion and
call graph limits retain uncertainty. The display is capped with a count
of omitted rows.

The model is read-only and **does not transport register values, memory
states or the MM write-once latch across calls**. The existing conservative
CALL_BARRIER remains in force. No hardware first-write chronology, runtime
execution, bus mapping, or ISR activation is proven. Generic CPU32 never
inherits MC68332 register meanings.

**Unknown STORE width:** even a known destination is not a safe negative
SIMCR/MM effect if P-code identifies a memory mutation whose width the
source adapter cannot model. Such sites are reported as unresolved alias/width
effects for the transitive callee; they are never treated as a known full
16-bit SIMCR literal. This protects MC68332 evidence from unsafe no-MM
conclusions while leaving the original CALL_BARRIER unchanged.

## GA-02/03 — strictly verified callee-constant register returns

An explicitly selected MC68332 may now recover **input-independent register
constants** from a very narrow, fully decoded, straight-line function:
one or more `MOVE.L #imm,Dn` or `MOVEA.L #imm,An` assignments and exactly
one `RTS` return. Every instruction, byte, CFG successor and implicit A/D
side effect must pass strict validation; the source must be reached through
a unique direct Ghidra CALL target. The 68000 canonical immediate 6-byte
encoding is checked against the decoded body. Any branch, indirect call,
unmodeled output, memory mutation, RTE/RTR, additional instruction or
truncated body invalidates the summary.

At the caller, the existing `CALL_BARRIER` **still clears all previous
register/peripheral/VBR values and marks the call history uncertain**. Only
a proven constant assigned by the callee is then reintroduced into its
specific A/D register. For example, a subsequent `MOVE.W D0,(A0)` can
recover a *source-level* SIMCR candidate when both registers are proven
by an unconditional leaf; it is NOT evidence that the leaf executes at
runtime, that MM is available for a write-once latch, or that another
caller/different interrupt path executed. All unproven functions, uncertain
targets and unknown flows remain fully barred. No Review/Apply permissions
are relaxed.

The Ghidra CPU32 operand parser also handles exact size-qualified A/D source
views such as `D0w` for `MOVE.W D0,(A0)`, but only when that width
matches the mnemonic. A partial Dn destination still **clobbers** full
register provenance; a word view is not promoted to a full long pointer.
This distinction is asserted both in Java21 and in real Ghidra synthetic
CALL + indirect SIMCR STORE tests.

## 2026-11-04 — bounded queue and nonrecursive CALL-cycle audit (GA-02/03)

A transitive function-node budget alone did not constrain the **BFS
work queue**: convergent direct CALL sites could schedule the same target
repeatedly before that target was examined, and a wide set of unknown
destinations could consume excessive memory even at a small `maxCount`.

The SIMCR/MM CALL-site analyzer now maintains a **deduplicated
scheduled-PC set**, including unresolved callees. At most `maxCount`
distinct addresses are enqueued in one source-site inspection.
Discovering another address beyond this cap sets both `limited=true`
and `unknownControl=true`. Nothing is silently called "no MM effect";
the report's **cap** field identifies the incomplete horizon. When a
known node's edge target is already scheduled, it does not consume
additional queue space. Results of ordinary complete graphs stay
unchanged, including the existing `visited` count of *recognized*
functions (not unknown targets).

The cycle scan formerly used a **recursive** DFS over the inspected
subgraph. A graph with thousands of vertices can be reached in only
one BFS edge from a high-fanout root yet contain a long DFS chain of
cross-edges. That exceeded the Java call stack even though the
source-site's `maxCount` and `maxDepth` were valid. Cycle detection
now uses an explicit stack of vertex and edge iterators, with gray/black
sets; the same cycle/acyclic evidence is returned without risking Java
stack overflow.

Deterministic Java 21 tests cover: **6500** parallel descendants plus
a 6500-link chain (acyclic with a remote MM source); a long backedge
cycle; budget truncation hiding a later MM source; **12,000** duplicate
edges to one known leaf (no false cap); and 12,000 distinct missing
destinations with a three-node queue budget (explicit UNKNOWN and cap).
The same Ghidra 12.1.4 PUBLIC / Java 25 extension build and existing
synthetic-Ghidra hardware gates remain required on the **exact PR HEAD**.

**Static source only:** no runtime RESET/CALL, first executed SIMCR
write, write-once MM latch, physical CS address mapping or active ISR
is inferred. No result is used as a Review/Apply/Undo authorization,
a provenance receipt or an upgraded GA-12 cache. No original ECU411
files, user profiles, OAuth or stopped Wyse/Precision/Supervisor
testing are touched.

## GA-02/03 — shared CALL-root memoization and per-batch budget (2026-11-05)

A single Hardware Analysis report may contain multiple CALL PCs reaching the
same direct callee. The transitive SIMCR/MM candidate analyzer now memoizes
one source-only `Summary` for each exact target (including an unresolved
`null` target) within **this single analysis invocation**. Results are
not written to Program/GA-12 checkpoints and never shared between revisions.

The traversal now bounds the **aggregate number of distinct scheduled PCs**
(including unresolved destinations) over the entire batch to **16,384**.
Individual CALL roots retain their own existing depth and node caps. Once the
batch budget is exhausted, previously unseen roots and edges are explicitly
`unknownControl=true, limited=true` rather than being marked pure or free of
SIMCR/MM writes. Earlier cached summaries retain their first complete (or
locally limited) result and cannot degrade when a later CALL consumes the
budget. Roots are deterministically prioritized by caller entry, CALL PC and
nullable callee target; input ordering cannot change the report. Invalid
interesting callers are rejected rather than silently discarded.

Pure Java 21 tests cover distinct wide unresolved roots exhausting the shared
budget, a later known MM leaf omitted as UNKNOWN/LIMITED, repeated targets,
input reordering, equal-PC ties, and null/negative caller rejection. The
normal Ghidra 12.1.4 PUBLIC/Java25 extension build and synthetic regressions
are required on the **exact PR SHA** before integration. This is conservative
static source evidence, **not** executed CALL ordering, a physical MMIO map,
latched MM, a proven global negative, or a Review/Apply authorization.

## GA-02/03 — selected CALL-source budget priority (2026-11-05)

A finite 16,384-PC aggregate budget previously processed **all** CALL sites
in caller/PC order. A very large closed negative subgraph from unselected
callers could consume the budget *before* the selected functions were
inspected. Their real candidate sites were then reported
`LIMITED/UNKNOWN` even when they fit a small budget on their own.

The report now performs two deterministic passes: first selected
`interestingCallers`, then all other caller sites. Exact callee summaries
remain memoized within the report, and **selected rows also receive display
priority under `rowCap`**. Surviving rows are sorted by
caller/CALL-PC/nullable-target regardless of input order; omitted rows are
counted. Nonselected paths that run out of the budget explicitly stay
`LIMITED/UNKNOWN`. This improves relevance and bounded precision, not
execution feasibility, physical MM mapping, or permission to Apply.

The source CALL graph also enforces **200,000 total adjacency edges**
in addition to its earlier function and callsite bounds, preventing very
large per-function CALL lists from escaping global input limits.

The Java21 regression deliberately supplies 16,384 unrelated closed
callee roots *before* one selected SIMCR/MM root, then checks that the
selected root receives complete evidence and a visible row even when
`rowCap=1`. A reversed input order must produce the same report. A
200,001-edge graph is rejected before any traversal. Full Ghidra 12.1.4
PUBLIC/Java25 extension and isolated real synthetic-Ghidra CI must pass
on the **exact PR HEAD**.

This is static **source-only MAY evidence**; unknown other callers and
unvisited paths are never proof of the absence of writes.
