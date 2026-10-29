# GA-06 — local PDF SHA-256 comparison

When a structurally valid version-1 profile manifest supplies a 64-character
PDF SHA-256 claim, the **Preview profile...** dialog optionally offers
to select a local PDF and verify its bytes. This is **not** an automatic
download or a RAG import.

The verifier streams up to 128 MiB of bytes using a bounded buffer and
requires a PDF header (`%PDF-`). It reports `MATCH`, `MISMATCH`,
`INVALID_PDF`, `TOO_LARGE` or `CLAIM_UNKNOWN`. An absent hash cannot
be filled in automatically. An invalid manifest or failed checksum is
never promoted into active MCU definitions, firmware modifications,
Ghidra labels, data types or an asserted hardware configuration.

**Scope of MATCH**: actual bytes match the *provided* SHA-256 string. The
document's authenticity, revision/edition, physical PDF pages, register
addresses and hardware identity remain unverified. Future work may bind
official source checksums and reviewed page data into an approved catalog.

CI: deterministic streaming hash checks, bad-header/oversize/unknown cases,
and full Ghidra 12.1.4 extension build. Local PDF GUI acceptance requires
an isolated Ghidra project and explicit Supervisor approval.
