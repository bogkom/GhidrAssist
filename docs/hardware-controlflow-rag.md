# Hardware analysis: bounded CFG, indirect registers, CS epochs and AI/RAG context

**Status:** implementation completed for the four requested areas as a bounded, static-analysis foundation; Ghidra API compilation and pure-Java regression are automatic. **Not** a claim of full path-sensitive interprocedural emulation or hardware state.

## 1. CFG-aware function analysis

`HardwareDataflow` evaluates a per-function graph of disassembled instruction sites. `GhidraHardwareFlowService` constructs edges from Ghidra Listing's conditional flow, jump destinations and fallthrough. Constants are kept at a branch merge only if all *recognized, reached* predecessors agree.

- Repeated loops converge through a bounded worklist, with a truncation flag when the bound is reached.
- Unrecognized calls invalidate A/D pointer constants, chip-select configuration and VBR; the called function is never automatically treated as an inlined continuation.
- Static caller XREFs and calling function names are evidence of possible call order, **not** proof of runtime execution.
- Unknown indirect jumps, exception entry, interprocedural register values, condition-dependent branch pruning and the real reset path remain **unresolved**.
- The in-Ghidra Hardware Analysis report now includes this section after the existing per-function direct register inventory.

## 2. Indirect addressing and local P-code

The Ghidra bridge supports selected direct constant sources and transfers: immediate `MOVE.L`/`MOVEA`, `MOVEQ`, absolute `LEA`, A/D register copies, immediate `ADDA/SUBA/ADDQ/SUBQ` and simple indexed-free `displacement(An)` memory destinations.

It also considers constant STORE pointers produced by local P-code COPY/EXT/ADD/SUB operations when no directly resolvable destination is found. It deliberately rejects indexed addressing, postincrement/predecrement, unknown displacements, unsupported partial register writes and conflicting branch values. It is **not** a full SSA alias solver and must not be described as exhaustive.

Synthetic tests check agreeing and disagreeing branch predecessors, loop invalidation, call barriers, A-register arithmetic, D/A register copies, known peripheral writes, VBR sources and propagation timeouts.

## 3. Conditional memory-map epochs

Each candidate hardware-register write yields an abstract snapshot after that code site. For MC68332 **as a selected/hypothetical profile**, it can report known CSBAR, CSOR and CSPAR values, possible chip-select ranges, pin assignments, byte lanes, R/W and CPU/user/supervisor space. The report includes relevant alternatives after updates to any of those three registers. SIMCR-MM, TRAMBAR and MOVEC-VBR are separately reported.

**Important:** code-site snapshots are *not* measured hardware epochs. No statement such as “CS7 is enabled at runtime,” “flash is physically wired here” or “MM was successfully changed” is permitted. MM write-once after reset, current function code, CPU-space accesses and reset/interprocedural ordering remain to be resolved.

## 4. AI and RAG, safely

After a user runs **Hardware Analysis** on an open Ghidra program, `HardwareEvidenceCache` retains the local report **only for that exact program**. Relevant user questions in Query, Agentic planning and Explain Line receive a small, ranked excerpt. The query itself or `#hardware` controls relevance — a generic search-result snippet never triggers automatic hardware injection.

- Selectors cap evidence to 9,000 characters and explicitly warn that Ghidra findings are untrusted data and CPU type/runtime/physical memory are unverified.
- The cache does **not** automatically upload bytes, modify RAG indexes or send any data to cloud services by itself. If the user chooses a configured external AI provider, relevant evidence is included in that model request as normal query context.
- Existing PDF/manual RAG search still works independently. The user can export full Markdown for indexing in a chosen RAG library.
- Existing CSV review proposes labels only for a manually selected concrete profile, with evidence thresholds and existing-symbol collision checks. There is no automatic symbol applying, even if a label looks plausible.
- The cache is a snapshot. After firmware reanalysis or changes to the program, rerun Hardware Analysis; the report may otherwise become outdated.

## Automated validation

`hardware-profile-tests.yml` compiles/runs the pure-Java CFG and hardware-context regression suites. `hardware-extension-build.yml` builds the **entire** GhidrAssist extension against the checksum-verified official Ghidra 12.1.4 API.

The public project contains no binary `ECU_FLASH 512KB.bin` bytes. The real input image remains private in `bogkom/GhidrAssist-Firmware-Tests`, which prevents accidental disclosure in public CI logs.

## Continuation checkpoint

If work is interrupted, inspect branch `feature/hardware-controlflow-rag-integration`, the latest GitHub Actions results, and this file. An already merged PR should **never** be repeated. Outstanding future research beyond these four implemented foundations includes: interprocedural/exception-path state propagation, comparison against executed hardware traces, verified processor identity and source-page-perfect PDF table semantics.
