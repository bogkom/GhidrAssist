# GA-05 — CFG-aware CSBAR Review source gate

This is a safety follow-up to PR #73; its already-pinned test artifact
and prior Supervisor plan remain unchanged.

The earlier Review dialog generated CS-window candidates only from
direct Listing/XREF site observations. The same Analyze run separately
held P-code/CFG evidence, including indirect stores, incompatible
widths, unknown callees, and unresolved address-register aliases.
Ignoring those results in Review risked making speculative CS-window
proposals even when the report identified ambiguities.

The new pure-Java `HardwareCsbarUnifiedReview` consumes the
deduplicated **same-revision** Listing+CFG source report. It only
allows an MM1 CSBAR with a consistent 16-bit word *candidate* and
no path/call uncertainty. One unresolved pointer STORE address
can affect any CSBAR: Review suppresses **all** CS-window proposals
for that Analyze run, rather than assuming the pointer cannot alias
the register. It never infers actual execution or a chip-select state.

No Ghidra memory blocks or symbols are created by this source gate.
It preserves the earlier default-unchecked MANUAL_REVIEW behavior for
speculative CS windows, existing preflight checks, operator confirmation
and transactional Undo. Generic CPU32 remains unable to propose
MC68332-specific chip-select windows.

Pure-Java regressions cover agreeing Listing+P-code sources,
contradictory literals, mixed byte/word stores, wrong MM address,
unknown call effects, unresolved pointer aliases, generic CPU32 and
read-only sources. Exact Ghidra 12.1.4 build and actual GUI acceptance
on an isolated test project are still mandatory before merging.
