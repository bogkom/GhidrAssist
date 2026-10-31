# GA-12 — memory-bounded CFG evidence and fail-closed Review

GhidrAssist traverses a bounded CFG per function, but until this change
its *global* arrays of MMIO and pointer role source candidates grew
without a shared cap. An unusually large binary could retain many
thousands of repeated sources despite a limited textual report.

`HardwareEvidenceBudget<T>` now caps retained source observations
and explicitly counts omissions. The bounds are 12,000 CFG MMIO store
candidates and 8,000 address-register role observations per Analyze.
The full report labels exact observations seen, retained and omitted.

**Crucial safety invariant:** A complete, confidence-eligible CSBAR
Review requires both a non-truncated modeled CFG walk and a non-
truncated MMIO evidence collector. If either is incomplete, Review
offers no speculative CS window, even if already observed values all
agree. A missing candidate in a truncated set cannot prove the
register was never written. Address-register role proposals are
marked path-uncertain after truncation.

For repeated P-code STORE observations at one PC and huge CFG
functions, pairwise source-PC ordering is reported as limited or
unresolved rather than throwing an exception. There remains no
proof of actual execution, write-once SIMCR MM state or physical CS
activation.

Pure-Java self-tests verify exact truncation accounting, fail-closed
review, immutable source snapshots and missing-evidence semantics.
A complete Ghidra 12.1.4 extension build and approved isolated
real-Ghidra test are required before any merge.
