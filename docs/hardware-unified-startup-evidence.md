# GA-01/02/03 — unified startup register source evidence

This integration extension combines two independent **static evidence**
streams at the same function and source instruction:

- Ghidra Listing/XREF candidate register sites, including references
  that are *not* established as writes.
- Bounded CFG/P-code direct and address-register-indirect candidate
  STORE sites, including unknown-destination aliases.

The new reconciler groups exact function-entry/instruction-PC/target-
address identities so that a single instruction discovered twice is
not presented as two executed writes. The report lists independent
provenance flags for each merged site and counts unresolved aliases
separately. Conflicting full-word values, widths or register identities
fail closed to UNKNOWN, rather than producing an invented value.

The older startup table now consumes the merged site list. It retains
per-function alternatives and possible RESET direct-call ancestry
without synthesizing interprocedural register state or actual execution
order. Generic CPU32 does not give a confirmed MC68332 identity.

There is no reliable hardware MM latch state or physical chip-select
configuration inferred by this change. Unknown pointer destinations
might affect any tracked MMIO. Byte and long stores cannot become
known 16-bit words. No Review/Apply, Ghidra project or OAuth writes
are introduced.

CI must compile the full Ghidra 12.1.4 extension and run synthetic
conflict/alias/dedup regressions. On-host integration acceptance
requires an exact-head, SHA-pinned Supervisor plan and actual
isolated Ghidra project test. No prior artifact or test receipt is
silently reused.

Unknown-width P-code STORE operations (including unmodeled MOVEM and
unknown alias memory writes) are represented as `UNKNOWN` in reports
and CSV; they must not abort the entire analysis or become a 16-bit
literal. Only genuinely unsupported contradictory width codes fail
closed in the deterministic evidence validator.
