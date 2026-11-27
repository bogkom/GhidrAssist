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

## 2026-11-27 — GA-07 ordered canonical publication gate

Overview/Full Evidence publication and Listing/CFG reconciliation now
require three **unique, exact, line-started** section headings in order:
initialization candidates, write history and conditional Chip Select map.
A missing, reordered, duplicated or partly altered heading fails closed,
including when all three loose substrings are still present. Source totals
are never inserted into an ambiguous pseudo-overview and cannot be
silently misrepresented in the GUI, exported Markdown or RAG payload.
Deterministic Java 21 regressions cover positive canonical/unified text
and adversarial duplicates, reordered/mid-line headings and suffix changes.
This is an integrity gate for static source reporting only, not firmware
execution, active SIMCR MM or physical CS evidence. GA-07 remains PARTIAL
until all roadmap acceptance tests are met.


## 2026-11-27 — GA-04 selected-MCU function-local conditional CS table

The 12-row `ChipSelectTable` decoder already existed and was tested,
but detailed Analyze previously emitted only per-write window bullets.
On explicitly selected MC68332 the detailed source report now includes
up to eight **function-local one-CFG-instruction snapshot tables**.
Each shows CSBOOT and CS0–CS10 as separate Start/End/Size, CSBAR, CSOR,
CSPAR, eligibility or UNKNOWN rows. All words come from the **same**
post-instruction joined `HardwareDataflow.Snapshot` and exactly one
chosen SIM MM0 or MM1 address bank. No register word is merged from
another function, source instruction or bus mapping. The bounded source
context with most full 16-bit CS words is selected, then smallest
instruction PC and MM0-first as deterministic ties; this ranking is
**not** execution likelihood, first/last successful write or active
hardware configuration. Additional contexts are NOT silently conflated.

Full evidence, exported Markdown and RAG reuse the same published
revision-bound report. Invalid/duplicate/out-of-budget source
snapshots fail closed to an explicit omission marker; beyond eight
source tables the report labels the omitted function count.
Java 21 tests cover exactly 12 rows, UNKNOWN, source isolation
between MM0 and MM1, tie ordering, immutable snapshots, invalid
register words, foreign PCs and caps. Real synthetic Ghidra/Java25
CI is required for integration; formal GA-04 reception still
depends on remaining roadmap witnesses. No original ECU411
firmware, production Program, physical CS map, active SIMCR/MM
or Review/Apply is affected.
