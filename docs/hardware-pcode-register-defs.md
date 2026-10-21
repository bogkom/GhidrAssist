# CPU32 P-code register-definition invalidation

The CFG solver propagates constant A0–A7/D0–D7 register values to infer
candidate hardware addresses. A simple mnemonic parser previously modeled
selected `MOVE/LEA/ADDA/SUBA` instructions and recognized `(An)+`/
`-(An)`, but it could leave stale register values after other instruction
side effects, e.g. `EXG`, `SWAP`, `LINK/UNLK`, `MOVEM` register loads
or instruction-specific register output aliases.

The Ghidra bridge now scans P-code **output varnodes in the Register address
space** and resolves each to its base A/D register. Any unmodeled register
write clears the corresponding abstract constant **after** interpreting the
current instruction. A register with an explicitly modeled new value (e.g.
`MOVE.L #value,A0`) retains that modeled value; other side effects are
invalidated, not guessed. Operand-level auto-update invalidation remains a
fallback when P-code does not expose an expected register change.

The analysis is static and read-only, and this change intentionally reduces
false address matches. It does not prove execution paths, MCU identity,
hardware reset state, MM acceptance or external chip-select wiring. Some
partial/ambiguous P-code outputs may remain unrecognized; future dataflow
work should model source register aliases more precisely.

The pure Java policy is covered by tests for unrelated P-code A/D outputs,
known SET_POINTER operations, post-increment stores, and invalid IDs.
GitHub Actions compiles the complete extension against Ghidra 12.1.4.
