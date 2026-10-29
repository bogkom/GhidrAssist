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

## GA-13 — review provenance and final confirmation revision gates

The source-review dialog may stay open while a Program edit, Undo/Redo
or profile switch changes the original Analyze inputs. Guarding only
`program == activeProgram` allowed stale Review provenance to be
written after source data changed. The export now checks the complete
revision token (same Program object, modification number, language,
original executable SHA metadata and selected profile), and checks
again after the potentially long file chooser and overwrite prompt.

Likewise, the second final Apply confirmation can display while Ghidra
changes in another UI context. A final revision check occurs **after
the confirmation** and before starting an undoable transaction.
Neither stale export nor stale approval should be mistaken for
fresh user-reviewed evidence.
