# GA-12 — owner-identity scope for cancellable CFG stages

The process-local stage invalidation epoch is tied to the exact Java
`Program` owner object. An ordinary `WeakHashMap<Program,Long>` uses
`equals()/hashCode()`; a synthetic owner (or an API proxy) with value
equality could share the generation of another object, spuriously canceling
a different Program's pending analysis or treating its epoch as current.

`HardwareStageEpochs` now retains **weak identity keys**:
`System.identityHashCode` plus referent `==`; collected references are
removed with `ReferenceQueue`. Keys do not keep Ghidra projects alive.
An explicit clear increments only the exact owner's generation, never
another owner even if two owners have the same `equals()` result.
A brand-new equal-by-value owner is never considered already enrolled.

A deterministic Java21 regression checks two and three distinct
value-equal owners, independent invalidation and unseen owners alongside
existing cancellation/concurrency tests. The full Ghidra 12.1.4 PUBLIC /
Java25 extension build and synthetic Ghidra regressions must PASS on the
exact PR SHA. This does **not** extend durable checkpoint reuse across
program instances/JVMs, infer hardware execution, or change Review/Apply.
It does not touch ECU411, profiles or stopped local Supervisor workers.
