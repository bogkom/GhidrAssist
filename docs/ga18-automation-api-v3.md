# GhidrAssist Automation API v3 — initial opt-in agent runtime

This branch depends on PR #114 and Ghidra **12.1.4 PUBLIC**. It is not integrated into master.

## Runtime

The GhidrAssist plugin starts a local loopback HTTP server only when explicitly
launched with JVM properties `ghidrassist.automation.enabled=true`,
environment variable `GHIDRASSIST_AUTOMATION_TOKEN=<64-char-random-token>` and optionally
`ghidrassist.automation.ready=<writable-new-file>`. The server reports its
ephemeral port in the session receipt. The token and session JSON are local-only;
never publish them as Actions artifacts or GitHub issue comments.

`tools/ghidrassist-agent-start --ghidra /path/ghidra_12.1.4_PUBLIC --project /path/project.gpr --mode trusted`
starts a separate GUI instance with these properties, and
`tools/ghidrassist-agent status` checks the session.
Use `--mode test` with an isolated synthetic project. This launcher and
project path handoff have not yet been validated on the Wyse workstation.
The GhidrAssist extension must already be installed in the Ghidra profile
used by the new process. The launcher does not modify the user's Ghidra
installation or automatically import firmware.

Currently accepted JSON methods (POST /rpc, Bearer token):
- `session.status`
- `ui.snapshot`
- `hardware.analyze` (initiates real Swing Analyze button on EDT; async result)
- `listing.snapshot`
- `listing.goto` (checks address belongs to active program memory)

`tools/ghidrassist-agent snapshot`, `analyze`, `listing`,
`goto 00000020` provide client entrypoints. No arbitrary Java/script execution,
no filesystem writes to a Ghidra project through this API. Review/Apply,
tables, cancel/tasks and Decompiler integration are future additions.

CI currently uses the existing isolated CodeBrowser Xvfb test and
a synthetic CPU32 fixture to probe the production HTTP `ui.snapshot`.
Existing file-based v2 automation remains separate, preserving legacy tests.

## Evidence boundary

This is a first end-to-end production **transport** slice, not a complete
agent automation API nor proof of functioning launcher on an interactive
workstation. Verify compilation, CI/real GUI, and exact commit before
claiming PASS. Do not conflate synthetic CI assertions with manual GUI
or formal Codex Supervisor acknowledgements.


## Writable CodeBrowser startup on Wyse

The prior GhidraGo local `ghidra:` URL opened a **read-only project view**.
Do not use that URL to claim writable active-project acceptance.

The new opt-in `AgentProjectOpenPlugin` loads in the *Ghidra Project Window*.
It matches the explicitly requested local `.gpr` path against the **active**
project, requires `DomainFile.canSave()` and `!DomainFile.isReadOnly()`,
then invokes native `Project.getToolServices().launchDefaultTool(List.of(file))`.
The GUI session launcher now starts the project **once** through `ghidraRun`
and passes the requested program to this project plugin via JVM properties.

One-time setup for the isolated test profile: in the **Project Window** open
File → Configure and enable **GhidrAssist Automation Project Opener**
(`AgentProjectOpenPlugin`). This plugin is inert unless
`ghidrassist.automation.project` and
`ghidrassist.automation.openProgram` are passed by the launcher.

`tools/ga18-wyse-test.sh start` uses only the synthetic
`AutomationFixture.gpr` and `synthetic-mmio.bin`. The launcher accepts READY
only after the HTTP API confirms the expected program and
`program_writable=true`. Never delete Ghidra project lock files.

This front-end integration needs both a successful exact-commit Ghidra 12.1.4
build and independent Wyse GUI acceptance. A syntax/contract test alone is
insufficient.
