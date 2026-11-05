# GA-06/10/16 — MC68332 SYNCR source-backed configuration fields

**Source and edition claim:** MC68332 User's Manual, © Motorola, Inc.
1995, official NXP-hosted PDF:
https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf .
The document's Appendix D.2.3 diagram and field descriptions are on
**printed D-6 (physical PDF page 220)**; continuation descriptions are on
**printed D-7 (physical PDF page 221)**. The PDF cover identifies the
1995 copyright; this is not an authentication of any separately imported
user RAG copy or a proof of actual silicon revision.

## Verified diagram and conservative model

SYNCR is a 16-bit *clock synthesizer control register* at MC68332
module offset `0x0A04` (`$YFFA04`; the `Y` internal module base
depends on the SIMCR MM mapping bit). The following configuration fields
are interpreted only for a **complete, statically known 16-bit
source-side literal** with the explicit MC68332 profile:

| Field | Mask | Manual text/location | Type in GhidrAssist |
|---|---:|---|---|
| W | 0x8000 | Frequency control (VCO), D-6 / PDF 220 | Config value |
| X | 0x4000 | VCO prescale selection, D-6 / PDF 220 | Config value |
| Y[5:0] | 0x3F00 | Synthesizer modulus counter, D-6 / PDF 220 | Config value |
| EDIV | 0x0080 | ECLK divider selection, D-6 / PDF 220 | Config value |
| RSTEN | 0x0004 | Loss-of-reference reset enable, D-7 / PDF 221 | Config value |
| STSIM | 0x0002 | SIM clock selection during stop, D-7 / PDF 221 | Config value |
| STEXT | 0x0001 | CLKOUT source during stop, D-7 / PDF 221 | Config value |

**Intentionally not modeled from firmware WRITE constants:** SLIMP
(bit 4) and SLOCK (bit 3) are runtime status indicators. Reserved
bits 6 and 5 are also untyped. The decoder's
`unspecifiedMask == 0x0078` is a mandatory fail-closed assertion.
Register RESET is still `UNKNOWN` even when a particular firmware
source literal contains zero. No write-once SIMCR MM policy is imported
onto SYNCR.

The existing `HardwareBitfieldDecoder` prints
`source-page-claimed` and explicitly warns
`PDF edition/page claim UNVERIFIED`; these remain accurate because
manual bytes, page offsets and imported RAG resources are not
independently authenticated by the decoder. Page/edition/provenance
references are documented for operator audit.

Deterministic Java21 regressions inspect exact masks, shifted values,
all seven individual physical PDF-page references, remaining
UNINTERPRETED bits, unchanged register address and null reset, and
reject generic CPU32, partial byte writes or unknown values.
The full Ghidra 12.1.4 PUBLIC/Java25 extension and existing isolated
synthetic headless tests must pass on the **exact PR commit SHA**.

**Not proven:** executed hardware clock configuration, current SLIMP or
SLOCK, active MM bit, physical chip-select mapping, or actual ECU411
runtime states. No private firmware or user Program is touched.
