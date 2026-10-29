# GA-11 — Image-zero interrupt/exception vector candidates

Source: `9b8b871a10a506925963161dc86a8e14bc3d5a66` (PR #54). This draft extends the conservative
RESET-rooted report with a second, **static-data-only** vector inventory.

For `68000:BE:*` programs, Ghidra reads candidate vector slots 2..255,
each a big-endian 32-bit pointer at `slot = 4 * vectorNumber` in mapped
image-zero bytes. A separately available VBR setting is **not inferred**:
the current VBR may be relocated, and even a plausible vector table does
not prove that a vector was used. The first eight bytes remain handled by
the existing RESET model (initial SP/reset PC).

The report counts readable, null/erased, odd, unmapped and mapped values,
and resolves mapped even pointers to *recognized Ghidra functions* when
possible. It never creates code/functions, labels or memory, does not
assert any handler has run, does not infer IRQ enablement, and does not
identify an MCU-specific peripheral from generic 68000 vector numbers.
Slots 24 and 25–31 use standard spurious/autovector numbering only.
The table shows up to 32 nonempty candidates; counts cover all 254 slots.

CI checks the pure deterministic model and builds the entire Ghidra 12.1.4
extension. A separate, explicitly approved artifact-pinned Supervisor
plan must verify on an isolated Ghidra project COPY that the vector
inventory matches actual memory bytes, has no stale or false execution
claims, and leaves the user project unchanged. Unverified candidates
remain UNKNOWN. Do not merge based only on CI.
