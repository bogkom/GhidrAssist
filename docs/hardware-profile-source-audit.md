# GA-06 — MC683xx profile source coverage and overlap audit

On this independent branch, the selected MC68332 profile remains
an explicit hypothesis, *not* a processor auto-detection. The read-only
Analyze report includes an audit of profile **citation metadata**,
counting register definitions, sources labeled with physical PDF pages,
ambiguous/unverified page labels, bitfield citations, and register range
collisions / module aperture inconsistencies.

This audit does **not** read physical PDFs and never calls a physical
page label proof that a source is correct. It does not add a different
Motorola MCU profile without official source validation. The generic
CPU32 profile has no MC68332 peripheral register table.

The catalog remains extendible in later work through an explicit
documented source/edition/version manifest and checked imports. Ghidra
Review / Apply, register names and memory definitions are unchanged.

Build gate: pure Java synthetic overlap/uncertainty tests and full
Ghidra 12.1.4 extension compile. Real-Ghidra acceptance on a
disposable project must confirm that the new source metadata audit
is non-mutating, does not crowd out the initialization evidence and
is not shown as evidence of an actual connected MCU. No local tests
are claimed by GitHub Actions.
