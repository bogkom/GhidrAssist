# GA-06/10/16 — MC68332 CSBAR/CSOR exact source-page claims

Status: **CI candidate**, 2026-11-06; previous integrated source baseline
`28392aaf0526d37d9656f19a2effd3a35028ee78`.

## Primary source inspected

- **MC68332 User's Manual**, Motorola ©1995; NXP/Freescale-hosted
  edition whose cover also carries Freescale ©2004.
- Official PDF:
  https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf
- **Printed D-4 = physical PDF page 218** (1-based): Appendix D,
  Table D-2 “SIM Address Map” contains `CSBAR0/CSOR0` through
  `CSBAR3/CSOR3` and `CSBAR4` at `$YFFA5C`, but not `CSOR4`.
- **Printed D-5 = physical PDF page 219** (1-based): same Table D-2
  continues with `CSOR4` at `$YFFA5E`, followed by
  `CSBAR5/CSOR5` ... `CSBAR10/CSOR10` at `$YFFA74/$YFFA76`.

The NXP-hosted PDF's table headings, printed footers, addresses and
8/16-bit layout have been inspected as a **human-auditable reference**.
This does **not** independently authenticate the edition, bytes, SHA-256
or page map of a separately selected user's RAG/manual copy.
In the plugin the strings remain **source-page claims**.

## Profile change

Only the already built-in, explicitly selected `MC68332` profile is
adjusted. For `CSBARi`, `i <= 4` claims D-4/PDF218 and `i >= 5`
D-5/PDF219. For `CSORi`, `i <= 3` claims D-4/PDF218 and `i >= 4`
D-5/PDF219. All 22 registers remain **16-bit**, in their existing
offsets. Source metadata explicitly identifies Motorola 1995 and the
MC68332UM family/manual.

No MC68332 register is inherited by generic CPU32.
The selected internal module base `$YFF000` is conditional on SIMCR
module mapping (MM0/MM1); `Y` must **not** be inferred from static
CSBAR/CSOR values or a detected source STORE.

No writeability, chip-select pin assignment, output enable, active
decode window, transaction ordering or physical external bus state
is inferred. The `WritePolicy` remains `UNKNOWN` and reset value
`null`. Width-aware GA-02/03 annotations classify static byte
overlap, not a known 16-bit written register value.

## CI and required evidence

Java21 regressions in `HardwareProfilesSelfTest` cover all 22
registers, their exact offsets/widths, printed folios/PDF indices,
claimed edition and unchanged UNKNOWN write policy. The
`HardwareRegisterByteCoverageSelfTest` separately checks that
`CSOR6` and `CSBAR7` render source claim D-5/PDF219 after a
spanning 32-bit CALL-site source STORE. Existing profile audit,
bitfield and real isolated Ghidra headless tests remain enabled by
Actions, with full Ghidra 12.1.4 PUBLIC/Java25 extension build
on the **exact PR SHA**.

No model-based test, local Wyse/Precision, original ECU411 firmware or
user project, disabled Supervisor or timer is involved.
