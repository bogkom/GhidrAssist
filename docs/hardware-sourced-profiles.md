# Source-backed MC68332 profile metadata (incremental)

The selected MC68332 profile is an **explicit hardware hypothesis**, not processor identification from Ghidra's `68000:BE:32:CPU32` language. Generic CPU32 has no peripheral modules.

## Source and positions

Authoritative input: [MC68332 User's Manual](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf), **Appendix D**. Printed and physical PDF page numbers differ:
- Table D-1 on printed **D-1**, PDF **215**: module apertures, namely SIM 128, TPURAM control 64, QSM 512, TPU 512 bytes. All stored as module metadata; memory Review/Apply now reads these definitions, instead of maintaining independent size constants.
- Table D-2 on printed **D-4 / D-5**, PDF **218 / 219**: SIM registers and supervisor/S/U access. It contains `RSR` in the **low byte at `$YFFA07`**, not as a word at `$YFFA06`. `PICR` and `PITR` are catalogued at `$YFFA22` and `$YFFA24`.
- SIMCR printed D-5/D-6, PDF 219/220: `MM` bit 6 can be written only once after reset; `SUPV` bit 7 governs restricted S/U access; `IARB[3:0]` reset nibble is `0xF`. The **entire SIMCR reset value remains unknown** in the catalog.

The profile tracks register widths, module membership, access policy, write policy, reset values when known, field masks, exact/qualified source page, and write-once fields. An unknown reset is represented by `null`, **not** zero. Generic register references without verified page/semantics remain explicitly marked unverified. Factory-test registers and unused address holes are not auto-imported.

## Safe integration

- Review/Apply still requires user approval and a Ghidra undoable transaction; the source-backed module ranges are not treated as proof of MCU identity.
- Ghidra 8-bit data uses `ByteDataType`; 16-bit and 32-bit use their matching widths. Existing symbols/data are preserved.
- PDF-derived geometry candidates introduced in PR #19 remain **read-only RAG evidence**. They do not override the audited MC68332 profile.
- No extra hardware models are mapped by falling back to MC68332; additional devices need their own manuals and distinct module/bitfield definitions.
- Private firmware is never committed to public CI.

Tests verify register containment, module aperture arithmetic, `RSR` byte addressing and write policy, `MM` write-once metadata, and unknown reset handling. Full GitHub Actions must pass before merge.
