# GUI versus automated Responses diagnostics

Evidence campaign: 20261027T140530.089088Z-dcef5d6e in the regression workspace.
The user-approved provider is ChatGPT Plus / OPENAI_OAUTH. The actual serialized
model identifier is codex-auto-review. No OAuth implementation or installed
extension was replaced.

## Installation provenance

The installed GhidrAssist source archive matches dfe3e75 exactly, while the
regression branch initially ended at 05a436b. Installed GhidrAssistMCP Java sources
match f47d6b0/58292f4; the regression branch ends at ea1ee4b. Installed and branch
OpenAIOAuthProvider, OpenAIOAuthTokenManager and MCPClientAdapter class bytes were
identical before the diagnostic fix. ReActOrchestrator/ToolRegistry and MCP
GetCodeTool differed as expected from the regression fixes.

Installed JAR SHA-256:
- GhidrAssist: 08b4ed7c32f39f5f886faa6bf964983e1f4086f4c11306f48b6310005d728a63
- GhidrAssistMCP: 97ec28f667f43b195f46ca2a2a24c671d77abb36e87e59d38909867c786acbf2

Compatibility version is 12.1.4; MCP implementation version is 3.0.0. Exact compile
time is not embedded: createdOn is empty, GhidrAssist's manifest has no version or
build date, and JAR entries use normalized 1980 timestamps. File mtimes describe
the installed files, not a proven compile time.

No user Ghidra JVM remained at audit start. A visible isolated PluginTool loaded
exact copies of the installed JARs; seven resolved class resources and their
CodeSource locations were checked against the installed hashes. This verifies the
installed binaries reproducibly, but cannot inspect memory of the closed manual
GUI process. Its historical HTTP bodies were not recorded.

## HTTP 400: confirmed fixture error

The reproduced server message was:
Invalid 'tools[19].name': string does not match pattern. Expected a string that
matches the pattern '^[a-zA-Z0-9_-]+$'.

The original harness exported 22 tools, with fixture.get_task_status at index 19.
The installed GUI exported 16 native tools; all 16 native definitions matched the
harness byte-for-structure. Endpoint, POST method, model, noncredential headers,
Responses format, required tool_choice, stream=true and store=false agreed.
GUI reasoning was high; old harness reasoning was omitted.

The real-model harness now exports 21 tools, omitting only the test-only dotted
alias. Deterministic in-process alias coverage retains it. The fixed end-to-end
case still omitted reasoning and passed, excluding reasoning=NONE as the cause.
No production tool names, policies or assertions were relaxed.

APIProvider previously sliced JSON message text using quote offsets, losing the
useful error. It now parses structured JSON errors, preserves status/API code and
message, redacts configured credentials/session identifiers, and avoids raw
unstructured response bodies. APIProviderDiagnosticsSelfTest checks nested JSON,
escapes, detail fields, error codes, redaction and safe fallbacks.

## Executed real-model checks

The single fixed end-to-end case executed ga_get_document_page once for
MC68332UM.pdf, page 256, scope all, offset 0, max_chars 600. It returned 600 characters,
and final execution_count=1 matched ToolExecutionJournal.

The unchanged seven real-model scenarios ran twice, serially, with reasoning high:
14/14 passed their existing controller/model/tool assertions. They made 48 accepted
model HTTP calls, reporting 211237 input and 7165 output tokens, 218402 total.
The separate end-to-end case made 3 accepted calls and reported 12546 tokens.
Counts are provider-reported token usage, not a computed bill.

Semantic pass stability was 2/2 for each case, a small sample. RAG_PAGE execution
counts varied from 1 to 3: the second run read the page once, then unnecessarily
called two fixture tools while trying to check execution_count. Its final count
was truthfully 3. The prompt had no exact-one constraint in this pre-existing
scenario, so this is recorded as model inefficiency rather than hidden by changing
assertions. The separate exact-once end-to-end check passed.

The deterministic Agentic and production contracts passed 33/33 in targeted run
20261027T142002.080404Z-0d25913a. Full MCP/GUI regression was not repeated.

## MCP initialization and restart

The historical manual failure was a 20-second official SDK initialization timeout
at 14:29 using SSE on localhost:8080. The same transport and URL succeeded at 14:37.
The server logged a successful bind at 14:26. There is no contemporaneous bind
conflict evidence, and historical multiple-JVM state cannot be reconstructed.
The underlying cause of that historical timeout remains unproven.

The targeted diagnostic exercised failure before server start, explicit cleanup,
reconnect, actual tool discovery/call, stop and restart on the same owned port.
Python Streamable HTTP and GhidrAssist Java SSE initialization both passed with
94 tools. A busy port was avoided. No browser GET was used as protocol evidence.

This diagnostic found a separate harness restart defect: PortLease treated a
closed listener's TIME_WAIT as an occupied server. SO_REUSEADDR fixes restart
reservation while the existing flock still prevents cooperating leases sharing a
port. A before-fix failure and 8/8 passing harness controls are preserved. This
does not establish the cause of the earlier manual timeout.
