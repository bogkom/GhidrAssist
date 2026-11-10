# GA-06 — External profile manifest preview (version 1)

This is a **preview-only** input format. It never registers a new device,
edits a Ghidra Program, creates MCU registers, renames symbols, or adds data
to RAG. The official MCU model, PDF bytes, edition, checksum and page labels
are **NOT verified** merely because they appear in a manifest. Use an
isolated project for the eventual verified import/apply workflow.

In **Hardware Analysis**, click **Preview profile...** and select a local
UTF-8 TSV file (maximum 1 MiB). The parser is strict and rejects duplicate
registers, overlapping register/module apertures, out-of-range masks, bad
width/alignment and unknown references *before* displaying a preview.
Unsupported record kinds and schema versions are rejected. No network
requests are made from this feature.

Format (tabs between fields):

```text
GHIDRASSIST_PROFILE	1
DOCUMENT	MC68332	MC68332UM	https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf	UNKNOWN	UNKNOWN
MODULE	SIM	0x0A00	0x0080	D-1 PDF page 215
REGISTER	SIM	SIMCR	0x0A00	16	D-6 PDF page 220
FIELD	SIMCR	MM	0x0040	D-6 PDF page 220
```

The `DOCUMENT` line provides a **claimed** device ID, manual ID, HTTPS
URL, edition (`UNKNOWN` allowed) and PDF SHA-256 (`UNKNOWN` or 64
hex characters). MODULE and REGISTER offsets are relative to the 4 KiB
internal address aperture, not automatically absolute memory addresses.
The sample intentionally does not encode MM-specific absolute addresses or
claim active hardware state. REGISTER width must be 8, 16 or 32. FIELD
masks must be nonzero, within the width and non-overlapping.

The preview counts ambiguous physical-page references but does not access
the linked manual or verify its content. The current built-in MC68332
profile and safe Review/Apply policy remain unchanged. Full edition-aware
verified SVD/RDL import with manual provenance and user-approved changes
is still not implemented.

CI must pass both the strict parser tests and full Ghidra 12.1.4 extension
build. GUI preview on an isolated Ghidra project COPY remains a separate
user-approved Supervisor acceptance test. Do not merge on CI alone.

## 2026-11-03 — fail-closed numeric PDF page claims

GA-06 profile preview shares the `ManualPdfPageClaim` validator with
GA-10 field decoding. Invalid/reversed/out-of-bounds page ranges and
ambiguous or duplicate claims increase the preview's `ambiguousPages`
count rather than being promoted to a numbered citation. Structural
validation remains preview-only and cannot register MCU profiles or
mutate Ghidra. Numeric page syntax still is **unverified metadata**:
it proves neither the document edition nor any register meaning.

## 2026-11-05 — untrusted source URL hygiene (GA-06)

The claimed `DOCUMENT` source must be a syntactically valid **HTTPS URI**
with a recognized host, no embedded userinfo/credentials and no invisible,
non-ASCII or non-printable characters. Printable percent-encoded paths and
query strings remain accepted; none are decoded, resolved or fetched by the
preview. Unexpected carriage returns **inside** TSV records are rejected;
standard CRLF line endings remain supported. This prevents misleading host
labels in UI reports and silent record splicing, not validation of a PDF
edition, checksum or page contents. No profile is imported into Ghidra.

## 2026-11-10 — fail-closed public Preview/Comparison source boundary (GA-06)

`HardwareProfileManifestPreview.parse` already checked the untrusted
tab-delimited manifest, but its public `Source`, `Module`, `Register`,
`Field` and `Preview` Java records could be constructed directly
without parsing. The read-only two-profile comparator previously accepted
that forged `Preview` as a validated external inventory. A new *shared*
public-record structural gate now checks:

- document identifier, exact printable HTTPS URL without userinfo, bounded
  edition and claimed digest (still NOT authenticated);
- bounded 4 KiB module apertures, non-overlapping case-insensitive
  module and register namespaces, natural 8/16/32-bit register alignment,
  exact canonical module owner and collision-free register extents;
- case-insensitive field identity, mask width and overlap per register,
  explicit existing owner and bounded source label;
- total 1024-row budget, no null rows and a **recomputed** count of missing
  or ambiguous PDF page claims. Direct constructor callers can no longer
  invent a smaller uncertainty count or "VALIDATED STRUCTURE" from
  contradictory records.

`HardwareProfileManifestComparison.Report` now independently checks
bounded metadata, all five discrepancy-count categories, exact
retained+omitted findings accounting and duplicate/contradictory findings.
A report still contains **claims** about two supplied manifest inventories,
not verified hardware differences, PDF bytes or a trusted silicon profile.

Java 21 tests exercise the parser **and direct public construction**,
reordered/duplicate modules, overlapping registers, register/field ownership,
mask width and missing source pages, plus forged comparison totals, duplicate
details and output injection. Full Ghidra 12.1.4 PUBLIC / Java 25 extension
build and applicable isolated CI remain exact-SHA gates. These changes
are read-only: **no external profile is imported**, no active MCU inferred,
and no symbols/blocks/firmware/OAuth/production Ghidra project are modified.
GA-06 remains PARTIAL.
