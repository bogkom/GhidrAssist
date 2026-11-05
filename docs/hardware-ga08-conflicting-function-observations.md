# GA-08/13 — fail-closed conflicting function-name evidence

Function-role candidates are inferred **read-only** from direct hardware
register-write observations. Multiple observations for one function address
must come from the same analyzed Program revision. Previously, if two
observations disagreed about that function's current name, the last
observation silently won and the source could still become
`REVIEW_REQUIRED`. This made the candidate's displayed provenance depend
on iteration order.

A group now retains a `conflictingNames` flag. When any valid write
observation for one entry names a different function, the proposal remains
`EVIDENCE_TOO_WEAK`, `proposedName` is blank, and the CSV displays the
fixed `[CONFLICTING_SOURCE_NAMES]` marker rather than choosing either
name. This is a conservative source consistency check, not a rename or a
new approval path. The existing revision gate and transactional Ghidra
Apply/Undo remain mandatory.

A deterministic Java21 regression exercises three valid hardware writes,
a late user rename, reversed observation order, non-reviewable CSV and
generic CPU32. Full Ghidra 12.1.4 PUBLIC / Java25 extension build and
isolated real-synthetic Ghidra CI must pass on the exact PR SHA. No original
firmware, project, Wyse/Precision or stopped Supervisor is touched.
