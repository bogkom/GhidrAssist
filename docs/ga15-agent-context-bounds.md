# GA-15 — bounded agent findings and investigation history

The existing ReAct `FindingsCache` now has deterministic, **local**
limits independent of LLM/remote service behavior. This hardening is
stacked on immutable PR #49 and does not modify the tool registry,
approval policy or MCP server routing.

## Evidence limits and explicit truncation

- Retained findings are capped by constructor request, which must be in
  the range 1..1000 (default 100).
- A retained fact is at most 2048 characters; evidence at most 2048;
  tool provenance name at most 128 characters.
- Automatic text extraction inspects at most the first 128 Ki characters
  and first 2000 lines of a tool response. Skipped text is **not** treated
  as inspected: an explicit low-relevance `SOURCE INCOMPLETE` finding
  records the omission.
- Extraction retains the individual evidence line, not a full multi-MB
  tool transcript for every finding. This bounds prompt history growth
  while preserving the name of the originating tool.
- `formatForPrompt` and `formatDetailed` tolerate negative/zero limits
  without throwing, and 1–3 character limits do not construct a
  negative-length substring.
- At most 100 completed iteration summaries of up to 2048 characters
  remain. The oldest summaries are evicted, and displayed iteration
  ordinals remain monotonically consistent until explicit `clear()`.
- The complete original evidence MUST be retrieved separately from its
  source when exact instructions/values beyond the truncated text are
  needed. Incomplete or cached agent text cannot independently prove
  runtime firmware paths, physical MCU identity or current Ghidra state.

## Verification and integration gate

Java 21 standalone negative bounds tests run in GitHub Actions; the
full extension build uses Ghidra **12.1.4 PUBLIC**. Test the resulting
exact commit/ZIP on an isolated Ghidra project through the existing
GA-18 private Supervisor and the owner's standing test authorization.
A CI success is not a local real-Ghidra PASS. No second programming
Codex session, original firmware edits or OAuth changes are needed.
