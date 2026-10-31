# GA-16 — printed folio / physical PDF sequence audit

RAG PDF pages already retain the **actual PDF page index** for opening the
original file. Printed labels such as D-1 or 5-20 are independently
extracted candidates; they can refer to different physical PDF pages
between manual editions or split appendices.

This change adds an optional, read-only sequence status alongside each
indexed page's provenance header: `SEQUENTIAL_CANDIDATE`, a
`PHYSICAL_GAP_CONSISTENT_CANDIDATE` (blank/unindexed pages between),
`SEQUENCE_CONFLICT_CANDIDATE`, `DUPLICATE_FOLIO`,
`SECTION_CHANGED`, `UNREADABLE_FOLIO`, or `NO_PREVIOUS_FOLIO`.

The status is *never* proof of printed page correctness and can never be
used to substitute or correct a physical PDF page index. It does not
reconstruct column alignments or automatically modify MCU register
definitions. The index still stores the actual PDF source and page,
and the browser link still uses that physical page number.

Only full text-layer pages yield folio observations. Blank/unindexed
pages count toward the physical page gap; a header with no folio
becomes UNKNOWN rather than an inferred next number. Chapter transitions
are reported without asserting continuity.

CI: deterministic negative folio sequence checks and full Ghidra 12.1.4
extension build. Actual RAG ingestion/source-page lookup must be tested
on a non-sensitive local PDF in an isolated Ghidra 12.1.4 session before
merging; no firmware or user documents are published.
