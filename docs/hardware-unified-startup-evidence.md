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

## 2026-11-27 — bounded source intake and display integrity (GA-01/02/03/07)

The read-only Listing/CFG reconciliation refuses more than 200,000 raw
observations rather than producing a partial count that looks complete.
The per-function startup alternatives model likewise refuses more than
200,000 sites and rejects malformed rows (missing, negative address or
blank register) instead of silently dropping source observations.

Both selected-MC68332 Markdown reports share a presentation-only,
64-Unicode-code-point register-label encoder. Special Unicode/control
code points, HTML delimiters and table separators are printed as
`[U+XXXX]` tokens; long names carry an explicit abbreviation marker.
Original register strings remain unchanged in the immutable source
records, and generic CPU32 output still suppresses MCU-specific names.

The alternatives report retains the complete sorted candidate-word list
in the data model but prints at most 16 words per register group, with
an exact omitted-alternatives count. All source sites and counts remain
static MAY evidence: no confirmed execution, first SIMCR/MM latch,
active VBR/ISR, or physical chip-select configuration is inferred.
Deterministic Java 21 positive/negative regressions, full Java 25
Ghidra 12.1.4 PUBLIC extension build and isolated synthetic Ghidra
checks must pass on the exact PR head before integration. GA-01/02/03/07
remain PARTIAL pending their full roadmap criteria.
