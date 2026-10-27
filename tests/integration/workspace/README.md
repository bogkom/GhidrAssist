# Existing regression workspace bundle

These are versioned mirrors of the existing regression workspace scripts and checks.
Run them from the workspace containing repos/GhidrAssist, scripts/, tests/ and evidence/,
not from this bundle directory. The direct OAuth diagnostic runner checks that its
AgenticProbe, harness and real-model assertions match this bundle before making calls.

No credentials are included. Provider configuration is read privately from existing
Ghidra preferences and copied only into a temporary directory with 0700/0600 access.
The provider factory and OAuth implementation are unchanged. The offline visible GUI
audit uses dummy credentials and terminates its request before network access.
The server recovery diagnostic performs actual SDK initialize/discovery/tool calls,
not GET /mcp probes. Raw process logs and isolated preferences remain temporary.

AgenticProbe keeps fixture.get_task_status for deterministic in-process alias checks.
The real-model fixture inventory omits that invalid OpenAI function name by default;
the explicit negative case retains it to reproduce the server rejection.
The existing real-model assertions remain unchanged.

The final diagnostic-copy privacy check drops encrypted reasoning context as well as
protocol identifiers. ResponsesRedactionSelfTest exercises that observer offline,
retaining tool proposals, public answers, usage counters and union schemas.
