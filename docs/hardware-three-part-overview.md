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
