# GA-08/13 — bounded function-role CSV review export

The function-name review candidate CSV shares the seven-column
read-only register review format. Each untrusted cell is already limited
and formula-safe, but the number of exported rows was not previously bounded.

`HardwareFunctionNamingReview.toCsvRows` now emits at most **5,000**
candidate rows. If additional proposals exist, exactly one final
seven-column sentinel row includes `OMITTED_ROWS=N` and
`INCOMPLETE_EXPORT_NEVER_AUTO_APPLY`. This row is *not* a function
proposal, does not contain a Ghidra address or a valid review status,
and cannot authorize Apply. The count refers to the omitted CSV rows
only; it does not assert completeness of source CFG/MC68332 evidence.

Existing review candidates and the verified Apply transaction are
unchanged; this modifies only the legacy CSV export. Java21 asserts
the exact threshold, omission marker, column count, bounded output
and rejection of null input. The extension must still build with real
Ghidra 12.1.4 PUBLIC / Java25 on the exact PR SHA.

No original firmware, real project, user preferences, live backend
model, local Wyse/Precision or stopped Supervisor is involved.
