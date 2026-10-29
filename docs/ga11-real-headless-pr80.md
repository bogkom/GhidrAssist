# GA-11 PR #80: strict function-entry versus interior-pointer headless regression

This test-only branch is based on the immutable PR #80 feature head
`dd0d003aac5b8a6300301b4bda7cdae7bfe3db27` and does not
modify the feature source. It duplicates the isolated real-Ghidra
headless synthetic harness of PR #94 with `--strict-entry` enabled.

The integration creates a 68000:BE:32:CPU32 disposable binary whose
image-zero vector #2 points exactly to a real Ghidra function entry
at 0x400, whereas vector #3 points into the same function at 0x402,
and verifies `FunctionManager.getFunctionContaining(0x402)` is
non-null while `getFunctionAt(0x402)` is null. It then calls the
**compiled production** `GhidraInterruptVectorService`, requires
`RECOGNIZED_FUNCTION_CANDIDATE` for #2 and
`INTERIOR_FUNCTION_POINTER_CANDIDATE` for #3, with a distinct
summary count of one interior pointer. It also validates mapped
nonfunction, unmapped, odd, null, erased, output truncation,
partial-import unreadable slots, no false runtime-VBR/ISR statements
and integration with `GhidraHardwareFlowService`.

The harness really opens Ghidra 12.1.4 PUBLIC Programs and creates
its function using Ghidra's FunctionManager under a transaction in
a **synthetic-only disposable project**. The production Analyze
runs read-only after test setup. All binary inputs are generated from
known non-sensitive bytes. The full extension is rebuilt by
Actions and SHA-256 checked before execution; no external model,
Codex, private firmware, RAG or OAuth is accessed.

A passing workflow is a deterministic **synthetic real-Ghidra
headless regression**, NOT an ACK/PASS for the original SHA-pinned
Supervisor GUI plan, nor proof of runtime ISR execution or actual
ECU411 MCU IRQ wiring. Keep PR #80 and this test-only dependent PR
draft until their independent acceptance gates have passed.
