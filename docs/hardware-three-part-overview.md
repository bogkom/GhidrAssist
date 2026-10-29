# GA-07 — Three-part Analyze overview with full source evidence

Source: PR #55 commit `f5b464f86cad8bc2703112e09505eb2501b9f1c7`. This PR is stacked on #55;
it does not change already verified/queued PR #55 files.

After Analyze a new read-only **Overview** tab shows precisely three
summary parts: (1) initialization candidates, (2) bounded static register
write history, and (3) conditional chip-select map. It counts references
and candidate writes from the same completed scan. Generic CPU32 never
implies the MC68332 map; the manually selected device is still a
hypothesis. No ordering, runtime execution, MM latch, VBR or physical
bus state is asserted.

A **Full evidence** tab contains the original detailed report (including
the MC68332 conditional CSBOOT–CS10 tables and CFG/P-code evidence).
The existing Find/Ctrl+F search operates on this complete report and
switches to its tab. The serialized Markdown export and RAG evidence
combine the identical overview with all full details in that order.
Review / Apply and undo are unchanged.

CI: deterministic overview model test and entire Ghidra 12.1.4
extension build. Isolated-Ghidra acceptance must confirm both tab
contents, the export/RAG parity, navigation and no database changes.
No CI success is a substitute for local GUI acceptance.

## 2026-10-29 — source-count fail-closed semantics

The compact three-part overview no longer silently ignores NULL,
unnamed or inconsistent observations (e.g. a known write literal on a
nonwrite source). Such data is rejected rather than rendered as an
apparently complete scan. Oversize input over 200,000 rows fails
closed instead of claiming a comprehensive compact view.

When bounded CFG/P-code propagation reached its cap, source coverage
is prominently marked `INCOMPLETE / TRUNCATED`, and unresolved
indirect store counts are described as **lower bounds**. A bounded
pass without truncation is not a runtime trace. The hidden row count
is explicitly `Other/omitted register references (including CSPAR)`,
not automatically unrelated peripherals.

These are data quality and presentation guards only. Physical MCU
selection, active MM/VBR, executed IRQs or chip-select wiring remain
unknown. All original Ghidra project data, Review/Apply and RAG indices
stay unchanged.
