# GA-10 — Sourced bitfield evidence (candidate implementation)

Source baseline: PR #53 (commit `bd0a0a60eaa610e19581bd67fd16d29c637bfb8e`).
The decoder is limited to *explicitly selected MC68332* and bitfield
definitions carrying a verified source-page marker in `HardwareProfiles`.

## Behavior

- The current integration annotates **only direct immediate `MOVE.W #...` to
  SIMCR** in Listing/XREF Analyze output, and only for the concrete selected
  device. The original read-only evidence rows remain visible for every site.
- SIMCR `MM` (mask 0x0040), `SUPV` (0x0080), and `IARB` (0x000F)
  are decoded as masked values using the existing MC68332 profile metadata,
  with the PDF physical-page references from those definitions.
- All other SIMCR bits remain `UNINTERPRETED`; other registers without
  sourced field definitions return `NO_SOURCED_FIELDS`.
- Unknown constants, wrong access width, out-of-range values, missing device,
  generic CPU32 and unrecognized registers do **not** produce device assertions.
- No claim is made that a code site was reached. This is **not** a reset/first
  successful write or a confirmed write-once MM latch state. The CFG/P-code
  path conditions and actual runtime hardware configuration remain unknown.
- No symbols, memory regions, types, Ghidra database, OAuth tokens or RAG
  documents are modified. Review / Apply is unchanged.

## Verification

GitHub Actions: standalone Java regression `hardware-bitfield-decoder-tests.yml`
and full Ghidra 12.1.4 extension build `hardware-extension-build.yml`.
The workflow result must be checked for the exact PR head before accepting.

Pending isolated real-Ghidra acceptance: on a project COPY of ECU411, select
MC68332 and verify a directly recognized `MOVE.W #0x40CA` SIMCR site
shows MM=1, SUPV=1 and IARB=0xA with PDF evidence; non-MOVE.W sites
must not gain synthetic bitfield values. In generic CPU32 survey mode
no MC68332 bitfield interpretation may be displayed. Ensure no write to
the project and compare with the existing CSBOOT table and RESET report.
No Supervisor plan is approved or submitted by this code change.
