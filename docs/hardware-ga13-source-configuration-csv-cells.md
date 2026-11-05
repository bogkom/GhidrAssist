# GA-13 — bounded source-only configuration CSV cells

`HardwareConfigurationEvidenceCsv` exports static possible MMIO STORE,
SIMCR prefix and modeled CFG-path evidence for human review. The CSV is
**not Apply input**, does not establish firmware execution order, and
cannot identify the human/AI/script actor behind a Ghidra symbol.

Unlike the other read-only provenance/Review CSV encoders, its original
cell formatter only escaped formulas when `=+-@` occurred in the very
first UTF-16 code unit, and it accepted unbounded text before CSV
quoting. An imported label prefixed with zero-width/bidi format controls
could therefore be interpreted as a spreadsheet formula.

Generated cells now:
- truncate raw source text to 512 UTF-16 code units with a visible
  `[SOURCE_TRUNCATED]` marker, keeping surrogate pairs intact;
- normalize line breaks, U+2028/U+2029 and NUL to spaces;
- treat leading Unicode formatting controls and whitespace as transparent
  when detecting a formula prefix;
- prepend a literal apostrophe when `= + - @` is the first meaningful
  character, then quote and escape embedded CSV quotes.

The existing 14-column schema, row budgets, generic CPU32 suppression and
read-only evidence classifications are preserved. The public
`withUnifiedSources` method assumes its `rawCsv` argument is a trusted
earlier `serialize` output; this patch **does not authenticate or sanitize
an arbitrary caller-supplied raw CSV document**.

Java21 regression covers Unicode Cf-hidden formulas, 100k-character
labels and a surrogate-pair clipping boundary. Full Ghidra 12.1.4
PUBLIC / Java25 extension build and real isolated synthetic Ghidra
headless tests must pass on the exact PR SHA. No original ECU411
firmware, user project, Wyse/Precision or stopped Supervisor is touched.
