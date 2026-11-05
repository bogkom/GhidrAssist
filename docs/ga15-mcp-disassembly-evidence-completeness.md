# GA-15 — MCP disassembly evidence completeness and bounded extraction

The read-only deterministic MCP `get_disassembly` evidence preview is a
**sample of matching static literal MOVE writes**, not an executable trace or
a proof of physical MC68332 register mapping.

Prior behavior retained the first 80 SIM-window writes and stopped matching
without disclosing whether a 81st write was present. A large response could
therefore look like the entire sample had been inspected.

The extractor now reports `INCOMPLETE_EVIDENCE` when an additional in-scope
write is encountered after 80 retained sites. It also treats any matched but
unrepresentable numeric literal as **unknown evidence**; a malformed MCP
response no longer aborts enrichment with a parsing exception. Source
addresses outside the selected SIM-window hypotheses do not consume the cap.
The retained writes and XOR arithmetic remain explicitly conditional and
cannot prove chronological execution, active MM, or the absence of other
sources. No binary, Ghidra Program, RAG store or configuration is modified.

Tests: deterministic Java21 cases for exactly 80 writes, 81 matching writes,
out-of-window lines, overflowed immediates and mixed valid/invalid responses;
CI also builds the complete extension with Ghidra 12.1.4 PUBLIC / Java25
on the exact PR SHA. No model judge, original ECU411, Wyse or Supervisor.
