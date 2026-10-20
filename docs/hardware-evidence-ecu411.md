# ECU411: differentiating CPU32 devices and external CAN (working hypotheses)

**Last updated:** 2026-10-20. **Status:** preliminary, read-only, not a physical MCU identification. Do **not** use this report as u-Link NT write/flash configuration.

## Provenance / evidence levels

1. **Observed from user-supplied Ghidra script logs:** firmware program `ECU_FLASH 512KB.bin` disassembled as `68000:BE:32:CPU32`; static `MOVE.W` references to proposed MC68332 registers, including `SIMCR @ 0xFFFA00`, `TRAMBAR @ 0xFFFB04`, `CSBAR7 @ 0xFFFA68`, `CSOR7 @ 0xFFFA6A`. The same code constructs a candidate CS7 window `0xFF8800–0xFF8FFF`. Static sites and existing Ghidra function names do **not** prove execution.
2. **Reported by the user's Codex analysis, NOT independently inspected from its local files:** a RAM test at `0xFFF000–0xFFF7FF`, CAN accesses to `0xFF8800` that allegedly match 15 message objects of a Bosch CC770 / Intel 82527 compatible chip, and MC68332 as the leading MCU hypothesis. The named Codex files `MCU_MAP_RAM_TEST_775.md`, `STAGE_1268_CAN_MESSAGE_OBJECT_DIRECT_WRITE.md`, and `STAGE_1292_CC770_REGISTER_MAP_AND_CAN_OBJECT_LAYOUT.md` were not directly available for validation here.
3. **Verified from manufacturer documentation:** MC68332 has 2 KiB of TPURAM; MC68336/376 have 3.5 KiB; these devices share many SIM/CPU32 register addresses but do **not** have interchangeable full memory maps.
4. **Independent published implementation:** Linux `drivers/net/can/cc770/cc770.c` supports both Bosch CC770 and Intel AN82527, and notes their compatibility and differences; 15 message objects alone do not uniquely distinguish them.

## TPURAM: discriminating a concrete processor model

Observed code contains `MOVE.W #0xFFF0,(0xFFFB04).L`. With the MM=1 register-map hypothesis, this writes a candidate **TRAMBAR**. The corresponding potential RAM-base decoding is:

| Candidate device | TPURAM size | Window if TRAMBAR = `0xFFF0` | Interpretation |
|---|---:|---|---|
| MC68332 | 2048 bytes | `0xFFF000–0xFFF7FF` | Consistent with documented 2 KiB array; no overlap with its upper module-register locations |
| MC68336 / MC68376 | 3584 bytes | `0xFFF000–0xFFFDFF` | **Not a valid TPURAM placement** when MM=1: overlaps internal module control-register blocks; documentation says overlapping placement disables or prevents correct access |

The MC68336/376 module map at MM=1 includes TouCAN (`0xFFF080`, MC68376 only), QADC (`0xFFF200`), CTM4 (`0xFFF400`) and SIM (`0xFFFA00`). This does **not** mean MC68336/376 lack TPURAM: they contain a **larger** TPURAM. It does mean a required successful RAM test across `0xFFF000–0xFFF7FF`, after that remapping and with no other remap, is much more consistent with MC68332.

The firmware's **intent to test RAM is not proof that the test succeeds on hardware**. Establish actual boot paths, MM state and whether this is executed before eliminating alternative MCUs.

Source: [MC68332 User's Manual, section 8 and Appendix D](https://www.nxp.com/docs/en/user-guide/MC68332UM.pdf); [MC68336/376 User's Manual, section 12 and Appendix D](https://www.nxp.com/docs/en/user-guide/MC68336376UM.pdf).

## Distinguish an *external* CAN controller from integrated TouCAN

Existing CS7 register candidates:

| Register | Raw value in the three large init blocks |
|---|---|
| CSBAR7 | `0xFF88` |
| CSOR7 | `0x7BF0` |
| Candidate CS7 window | `0xFF8800–0xFF8FFF` |

The Codex report's putative external CAN base **`0xFF8800` matches the beginning of this CS7 window**. When CS7 is actually asserted for the appropriate space, R/W and byte-lane condition, accesses to this address could target an external controller. Note that `CSBAR7` alone is not evidence of physical connectivity or active CS pin assignment: include CSPAR1, CSOR7, access mode, function codes, pin multiplexing and reset order.

The *internal* TouCAN of MC68376 is in the MM-dependent module map at `YFF080` (with MM=1: `0xFFF080`). This is **different from `0xFF8800`** and must not be conflated with external CAN memory mapping. The MC68332 has no integrated TouCAN.

Bosch CC770 and Intel 82527 are closely register-compatible; a reported 15-object structure is a **strong controller-family clue, not an exact device identification**. Compare the complete fixed 16-byte-per-object layout, register directions, masks, controller reset semantics and any differentiating CC770 features. The physical transceiver is separate from controller protocol/message-object logic.

Reference: [Linux CC770/AN82527 driver](https://github.com/torvalds/linux/blob/master/drivers/net/can/cc770/cc770.c); [MC68336/376 User's Manual](https://www.nxp.com/docs/en/user-guide/MC68336376UM.pdf).

## How the Ghidra evidence script helps

`ghidra_scripts/GhidrAssist_MCU_Clues.java` runs independently of the extension. It reports the direct word writes to SIMCR, TRAMBAR, CSBAR7 and CSOR7, compares both TPURAM interpretations, tests whether CS7's **potential** address window includes `0xFF8800–0xFF88FF`, and groups direct Ghidra XREFs in 16-byte blocks at the proposed CAN base. There is **no MCU identification and no automatic renaming**. Indirect CAN accesses may produce zero hits even when a controller exists; no false-negative conclusion should be drawn from this.

### Next Ghidra investigations

- Inspect reset-to-application call paths linking `fun_reset`, `configure_sim_qsm_tpu_and_chip_selects`, `app_initialize_hardware`, and the RAM-test routines.
- Find whether the `0xFFF000–0xFFF7FF` test runs, and under what MM/TRAMBAR state. Recover the actual success/failure branch.
- Link controller register and object accesses at `0xFF8800` through CS7 and compare the **whole** CC770/82527 register layout, not just 15 object counts.
- Keep CPU32 as the generic ISA and MC68332 as a **strong candidate** until supported by physical marking, board traces, debugger identification or a convincingly exclusive executable behavior.
- For u-Link NT, document all active and alternative chip-select windows, ROM/flash/RAM assignments and the applicable execution epochs before any physical read/write addressing.

**No identification certainty or physical chip-select wiring is inferred in this document.**
