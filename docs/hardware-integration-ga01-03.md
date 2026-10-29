# Combined hardware-analysis integration — GA-01/02/03 and sibling features

This is an **integration draft** of PRs #54–#66, based on the
revision-safe PR #64. Existing user projects, MCU register names,
OAuth configuration and firmware bytes are not bundled in this repository.

The integrated report now distinguishes:
1. Image-zero 68000 big-endian RESET-vector *candidate* and a bounded
   direct-call graph of possible initialization functions.
2. Static MMIO word-write alternatives per function/register, unknown
   writes, and whether the function is only a **possible** candidate
   along that direct-call graph.
3. Conditional decoded Chip Select table and CFG/P-code evidence, without
   inferring active external memory chips or any temporal ordering.

Even one known SIMCR literal is not proof of the first successful
write to the write-once MM latch. No cross-function CSBAR/CSOR/CSPAR values
are combined into proven hardware register state.

Existing independent UI integrations: Overview and Full evidence tabs,
MMIO explorer, SourceType provenance review, external profile manifest
preview and local PDF checksum. Source-only A-register role hints have
`NEVER_AUTO_APPLY`. RAG PDF pages preserve physical page numbers and
uncertain printed labels. Full report export and RAG cache retain the
complete evidence.

Negative tests include missing reset root, truncated call graph,
cycle handling, conflicting SIMCR literals, unverified indirect writes
and generic CPU32. Full Ghidra 12.1.4 extension build is mandatory.
Actual Ghidra integration acceptance requires a *new* SHA/ZIP-pinned,
operator-approved Supervisor plan. No draft parent PR is auto-merged.
