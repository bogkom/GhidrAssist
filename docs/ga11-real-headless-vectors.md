# GA-11: real Ghidra 12.1.4 headless vector integration (synthetic only)

This regression is an **independent, self-contained, real Ghidra**
acceptance slice. It creates a disposable Ghidra project from synthetic
big-endian 68000/CPU32 binaries, builds the **complete GhidrAssist extension**
using Ghidra 12.1.4 PUBLIC and executes
`GhidraInterruptVectorService.analyze(Program,TaskMonitor)` as well as
the actual `GhidraHardwareFlowService.analyze` production path.

The full fixture has 254 vector candidate slots, mapped recognized function
entry and pointer inside the same real Ghidra `FunctionManager` function
body, mapped non-function address, unmapped address, odd word, zero, erased
word and >32 source candidates to force truncated reporting. A separate
48-byte imported binary checks that 244 vector slots remain
`UNREADABLE`, not zero or erased. The real Ghidra
`FunctionManager.createFunction` adds a synthetic function at 0x400
with NOP/NOP/RTS instructions, and the test checks that its interior
0x402 is *not* an exact function entry.

PR #57's baseline service interprets a pointer into a function body as a
recognized containing-function candidate. PR #80's narrower semantics
require this to become `INTERIOR_FUNCTION_POINTER_CANDIDATE`
and count it separately. The same Java test supports either mode via
`--strict-entry`; the PR #57 workflow intentionally tests baseline mode
without pretending to have already verified PR #80.

The execution runs without a display or models. The source inputs contain
no ECU411 binaries, private manuals, real projects, OAuth configuration,
and no original firmware; program mutations are restricted to creating a
synthetic function within a temporary test project. The report confirms
analyze remained read-only after fixture setup and that the static report
retains runtime VBR/IRQ/ISR uncertainty. Downloaded Ghidra ZIP is verified
against a fixed SHA-256; the extension ZIP is self-built, rehashed and
its exact SHA-256 is enforced before installation.

The test publishes `summary.json`, `result.json` and read-only
Markdown samples as CI evidence, **not a Supervisor nonce/ACK**.
A synthetic headless CI PASS is not the same as full PR #57 or #80
original real-GUI acceptance and does not authorize merging those
original draft PRs or auto-approving their existing queued plans.
Only a separately reviewed scoped plan may later be declared headless-safe.
