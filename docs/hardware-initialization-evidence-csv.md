# GA-01/02/03 — source-only hardware initialization evidence CSV

The Hardware Analysis UI includes **Evidence CSV...**, completely
separate from **Export CSV** (seven-column naming Review). This file
contains immutable source candidates of type `STORE` or `CFG_PATH`,
with function address, instruction PC, candidate peripheral address,
access mode, write width, 16-bit literal (only when complete),
possible prior SIMCR sites and modeled graph relation.

Each record carries a `NEVER_AUTO_APPLY` interpretation. The exporter
never creates a Ghidra transaction, renames a symbol, types data or
changes the original firmware. A CSV is a reviewable receipt only, not
a hardware configuration or executed instruction trace.

The exporter blocks stale revisions/profile selection, prompts before
overwriting, escapes CSV quotes and spreadsheet formula prefixes, and
caps the file at 5000 evidence rows with an explicit omission marker.
Generic CPU32 suppresses device-specific MC68332 labels and MM decoding.

This stage is stacked on PR #69 (CFG graph relations), #68 (P-code
candidate stores) and integration PR #67. Real Ghidra GUI acceptance
and a new operator-approved artifact-pinned Supervisor plan are still
required before merging.
