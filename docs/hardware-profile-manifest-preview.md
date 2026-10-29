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
