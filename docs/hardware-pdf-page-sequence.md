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

## 2026-10-29 — header-adjacent table/figure false-positive guard

Printed folio extraction now treats a page candidate in the same actual
`USER'S MANUAL` header/footer as a **text-layer candidate** only if it is
not directly qualified as a Table, Figure, Section, Chapter or Appendix label.
For the immediately preceding/following line, only a **standalone**
`D-1`, `5-20`, `Page: D-1` or `Folio D-1` form may count. A body
`Table D-1 Module Address Map` directly below the vendor header is not
a page folio. Multiple conflicting header/standalone candidates anywhere
in the page's considered header/footer regions yield
`UNKNOWN / AMBIGUOUS_HEADER` rather than the first lexical match.

No inferred physical page shift, printed-folio repair, automatic register
definition, hardware assertion or RAG page navigation change is permitted.
This is candidate extraction quality only. Dedicated Java negative tests
and a complete Ghidra 12.1.4 PUBLIC build are required; final acceptance
requires a separate immutable-artifact real Ghidra/RAG test.
