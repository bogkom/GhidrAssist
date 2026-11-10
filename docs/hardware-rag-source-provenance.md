# GA-06/10/16 — RAG indexed PDF source provenance and current-file pre-open check

The RAG index has always stored `sha256` of the document at import.
Previously the native `ga_search_documents` / `ga_get_document_page` paths
did not convey that digest, so a result with a familiar MC68332 filename
could be read as stronger manual evidence than the bytes actually warranted.
Opening the indexed PDF later also accepted a changed/replaced local document
without a pre-open comparison against the indexed file's SHA-256.

## New read-only source contract

- `SearchResult.indexedSha256` is propagated from the same stored Lucene
  document as its page number, source path and filename; the old constructors
  preserve missing legacy hashes as `UNKNOWN`, not guessed values.
- `RAGIndexedPdfPageEvidence` joins multiple chunks only when **every**
  source has the requested physical PDF page, the same indexed SHA-256,
  source path and library, a PDF document type and a distinct chunk ID.
  Conflicts, duplicates, wrong pages and overlarge page text **fail closed**;
  no arbitrary first or last chunk is chosen to fabricate a citation.
- The page tool reads the page text, digest and source library from **one
  Lucene snapshot**; the active-library filter now checks the returned
  page's own library, not a separate mutable metadata read.
- Both native RAG tool outputs carry `INDEXED_SHA256`, the clearly marked
  `PDF_PIN` classification and
  `INDEX_TIME_ONLY_CURRENT_FILE_UNVERIFIED`. The immutable public
  `MC68332UM.pdf` SHA pin remains the **same reviewed value** as the
  existing GA-10/16 bitfield source ledger and publisher-PDF Actions lane.
  `OFFICIAL_MC68332UM_SHA256_AT_INDEX` describes matching indexed bytes
  only; it does NOT silently select a device, verify arbitrary RAG text,
  establish the current file's contents or certify the manual edition,
  PDF folio, bitfield mask, physical mapping or runtime MCU state.
- The `RAGSourceOpener` checks the current local PDF with streaming bounded
  SHA-256, exact stored digest and PDF header before handing a source-page
  URI to an external viewer. A legacy/missing digest, stale file, symlink,
  digest mismatch, non-PDF header or oversize source is rejected with
  a reindex instruction. This does not guarantee a later external PDF viewer
  cannot race another modification; it is a read-only **pre-open check**,
  not an atomic OS lock or a notarized source signature.
- No firmware, Ghidra Program, local RAG index contents, MCU profile,
  Review/Apply/Undo state or PDF file is modified by the verification.

Deterministic Java21 tests verify mismatched page/source/library/digest
rows, duplicate chunk IDs, wrong document type, hard bounds, unchanged
current local PDF, changed file after index, symlinks, malformed/legacy
SHA, spoofed PDF magic and a correct digest without a reviewed publisher
pin. Full Ghidra 12.1.4 PUBLIC Java25 extension build and independent
headless/Xvfb CI remain required; no stopped Wyse/Precision/Supervisor
workloads are resumed.

GA-06/10/16 remain PARTIAL: this upgrade proves no actual manual content
semantics or MM/VBR/ISR execution.
