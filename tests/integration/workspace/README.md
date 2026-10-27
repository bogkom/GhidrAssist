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

The task-tool editor regression uses an actual resizable Swing window with 320
MCP-shaped tool definitions, provider-supplied descriptions and full names.
`test_task_tool_editor.py` checks search, provider filters, selections, budgets,
lifetimes, cancellation, defaults and separate history. The Ghidra GUI probe
also mounts the actual Query component in a 360-pixel-wide test window before
restoring it to the PluginTool and running the existing dispatcher scenarios.
This avoids treating the host docking window's minimum width as a narrow-Query
test. Screenshots and assertion evidence are written only to the current run.

Targeted UI/controller validation (no real model calls):

```
PYTHONPATH=.:/tmp/ghidrassist-test-deps python3 scripts/run_suite.py --allow-partial --without-mcp --test-path tests/test_task_tool_editor.py --test-path tests/test_gui_integration.py --test-path tests/test_production_selftests.py --test-path tests/test_agentic_cases.py
```
