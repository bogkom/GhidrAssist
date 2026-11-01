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

## Wyse automated CodeBrowser opening (GhidraGo)

Use the explicit `--program synthetic-mmio.bin` argument with the Ghidra project.
The launcher now sends a local GhidraGo project/program URL using the
`<ghidra>/support/GhidraGo/ghidraGo` executable and waits until the actual
Automation API reports `program=synthetic-mmio.bin` before reporting READY.
No screen-coordinate clicking or Supervisor is involved.

**One-time prerequisite for the isolated test profile:** open Ghidra's **Project
Window** → File → Configure → plug-in selector, enable **GhidraGoPlugin**,
then close only the test GUI and rerun the launcher. This is a built-in Ghidra
feature, not something installed into the user's ordinary Ghidra profile.
If GhidraGo is disabled or the project program is absent, startup must fail
rather than claim a false READY. Initial dispatch happens after a bounded
bootstrap interval; launcher must not invent a `READY` from frontend only.

Fixed-path test script: `tools/ga18-wyse-test.sh start`. The requested
program is the imported synthetic fixture, never an ECU411 program.

The GhidraGo launcher path is native to Ghidra 12.1.4; this host path must
be validated on Wyse before marking the autonomous GUI startup PASS.
