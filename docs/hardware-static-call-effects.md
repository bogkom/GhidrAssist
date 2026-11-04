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
