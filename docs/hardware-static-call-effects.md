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
