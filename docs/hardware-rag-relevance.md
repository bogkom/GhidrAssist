# Local hardware evidence relevance safeguards

The Query/Agentic/Explain Line integration already adds a bounded, explicitly
untrusted report only after the user runs Hardware Analysis on that exact Ghidra
Program. This change narrows what is appended for specific hardware questions.

When the selector finds report sections matching user-derived hardware terms,
it **does not fill extra context budget with unrelated sections**. For example,
a request about SIMCR should not receive nearby unrelated telemetry functions
or every CSBAR observation merely because both appear in the same report.
Hardware evidence remains separated from instructions by explicit delimiters
and warnings that MCU model, MM state, boot reachability and physical wiring
are unverified.

A request with no matching terms retains the prior fallback, with the caveat
that a query must first qualify for the hardware cache. The selector never
reads the ECU outside the open Ghidra Program, uploads firmware by itself,
changes symbols, or auto-submits AI queries. No online LLM is used by the
pure-Java tests; measuring model answer correctness across providers is a
future validation task.
