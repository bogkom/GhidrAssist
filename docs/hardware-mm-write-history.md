# SIMCR/MM bounded write history through CFG (candidate-only)

An MC68332 SIMCR MM bit can be written only once after **hardware reset**
(MC68332 User's Manual, Appendix D.2.1, printed D-5, physical PDF page 219).
Simply finding multiple immediate stores to `0xFFFA00` does **not** mean
multiple successful MM relocations occurred.

`HardwareDataflow` now attaches to each candidate SIMCR site the minimum and
maximum **number of previously matched SIMCR writes along recognized paths
since entry to the analyzed Ghidra function**, saturated at `2+`. It joins
branch predecessor counts conservatively and acknowledges unknown called-code
effects, not just instruction address order.

- `0..0`: no prior *matched* local write on recognized paths. Still **not**
  necessarily the first write since hardware reset.
- `0..1`: earlier local candidate write appears on some branch, but not all.
- `1..1` or `2+..2+`: a matched local write precedes this site on the
  recognized path. MM hardware acceptance after reset remains unproven.
- Full 16-bit stores to `0x7FFA00`/`0xFFFA00` and 8-bit stores to the
  corresponding **low byte** can affect MM and are counted conservatively.
- Unknown register-indirect destinations, intervening calls, exceptions,
  interprocedural ordering and the actual reset-entry route are not solved.

No code analysis concludes that the address is currently mapped as SIMCR,
that the write executes, that MM is active or that external flash is at an
address. User-selected MC68332 remains a device **hypothesis**.

The report is read-only and can be used in the existing AI/RAG evidence cache.
Pure-Java tests check branch joins, previously matched writes, call barriers,
low-byte addresses and non-SIMCR stores. True reset-relative write-once state
and execution reachability remain outstanding.
