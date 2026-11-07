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

## 2026-11-03 — sticky source-incompleteness receipt (GA-15)

The earlier source truncation receipt was a relevance-ranked `Finding`.
When `maxFindings=1`, an earlier score-10 finding can evict a later
score-10 `SOURCE INCOMPLETE` marker. That leaves the agent prompt with
no explicit warning even though the tool output was only partially read.

The cache now tracks `sourceIncomplete` independently of the findings
budget and prepends a fixed, trusted `SOURCE INCOMPLETE` message to prompt,
detailed summary and compact/progress views. User/tool text cannot set this
receipt through an ordinary `addFinding` call; it is set only when an
actual output extraction is capped by the byte/line budget and cleared
only by `clear()`. The original marker may still appear among retained
findings, but its eviction cannot create a false-complete context.
Java regression includes the score-10 tie under capacity 1, independent
summary views, reset behavior, and unchanged bounded finding count.
No remote model calls, firmware data, Supervisor plans, host or GUI tests.

## Real ReAct cache pages through Automation API (2026-11-06)

The actual `ReActOrchestrator` now publishes its existing findings
cache for read-only, authenticated loopback Automation paging. This is
not a separate cache with synthesized results: it is scoped to the
starting Ghidra Program **object identity**, revision and executable
source fingerprint, plus an opaque per-investigation run token.
Result status is captured after completion; a cancelled or unfinished
ReAct task cannot be represented as a completed analysis. A new
investigation replaces the previous in-memory read-only snapshot;
stale pages are rejected. Mutable relevance changes and concurrent
writes are serialized with read-only page capture.

Switching the live CodeBrowser to a different Program invalidates the
previous Program's published ReAct evidence, even when its source SHA
and revision remain unchanged. Returning to the original Program does
not revive an old run. This protects against mixed evidence when an
in-flight ReAct task could continue while the GUI switches programs.
Disposal of the plugin also invalidates the current Program entry.
A real two-Program CodeBrowser/Xvfb synthetic regression verifies
this behavior. Invalidation does not cancel a model task, so it is not
an execution or rollback guarantee.

The CLI's explicit `agentic-checkpoint --output` creates a local
mode-0600, SHA-256-identified evidence handoff from a coherent sequence
of retained pages. It is not an automatic background worker, an LLM
session restart, a full transcript, an authentication signature or
permission to Apply. Verified offline pages can be browsed with
`ghidrassist-agent agentic-read --input PATH --offset 0 --limit 25`
without a Ghidra session; every page rechecks the bounded file and
SHA-256 and retains incomplete-source counters. The complete flag only describes the source
coverage **within the retained cache** and the ReAct outcome; it
does not prove comprehensive analysis of a firmware image.
