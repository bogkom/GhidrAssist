# GA-12 — bounded, no-follow durable checkpoint reads

The opt-in durable checkpoint store persists completed or partial CFG stages
in an isolated user-selected directory. It is a cache, not a trusted source
of executable evidence or an authorization mechanism. Its digest detects
accidental corruption but does not independently authenticate a writer.

Prior to this change, a successful size check was followed by
`Files.readAllBytes(path)`. A concurrently replaced or growing file could
become much larger than its pre-read length, allocating unbounded memory
before digest and schema validation.

Now, `load` reads a single `BasicFileAttributes` snapshot without following
a symbolic link, opens the final file component with `NOFOLLOW_LINKS`,
and decodes **at most `MAX_FILE_BYTES + 1` bytes** from the stream.
Any oversized, truncated, foreign-key, corrupt or schema-incompatible
content is an ordinary cache miss. This closes the time-of-check/time-of-use
**size-bound** gap and final-component symlink-follow risk; the directory
itself is still required to be an existing non-symlink location, and this
does not assert protection against a hostile process that can replace
ancestor directories concurrently.

The deterministic Java21 regression exercises a valid roundtrip through
small stream chunks, a synthetic unending source (exact byte budget),
a sparse oversized checkpoint, missing inputs and the existing symlink
destination guard. Independent full Ghidra 12.1.4 PUBLIC/Java25 extension
and isolated synthetic Ghidra workflows must PASS on the exact PR SHA.

This is not cross-project trust, a verified hardware profile, active
SIMCR/MM or VBR/ISR proof, and does not touch original ECU411 firmware,
user Ghidra projects or stopped Wyse/Precision/legacy Supervisor tests.
