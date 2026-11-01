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

## GA-18 read-only Review Automation API (in development)

RPC `hardware.profile.select` takes a literal `profile` value:
`CPU32_SURVEY` or `MC68332_USER_SELECTED`. This selects the existing UI
profile only; it does not make the device identity a firmware fact and
does not edit Ghidra database content. Rerun `hardware.analyze` after
changing profiles. `hardware.review.preview` takes `offset` and
`limit` (1..100), requires a completed analysis from the same Ghidra
revision and an explicitly selected MC68332 profile, and returns
bounded Review preflight decisions. No modal, Apply, Undo or firmware
writes can be triggered by this endpoint.

`tools/ga18-wyse-review-smoke.py` is a one-shot Codex test on the
isolated synthetic `AutomationFixture` only. It checks that generic CPU32
cannot receive concrete Review proposals, selects MC68332 explicitly,
verifies read-only proposal rows, checks pagination/invalid bounds,
and restores CPU32 before exit. It writes one private (0600) JSON
report to `~/Projekty/Codex/ga-automation-test/reports/`.
It is separate from the historical GA-18 9/9 API smoke PASS; do not
retest those eight prior operations unnecessarily. This new feature
is **not a writable Apply or Undo endpoint**. Future implementation
requires a revision-bound, user-approved selection receipt and a
Ghidra transaction/Undo regression with unchanged firmware.

## Synthetic-only Apply / Undo pilot (not production access)

New RPC methods `hardware.apply.prepare`, `hardware.apply.commit`,
and `hardware.apply.undo` are **disabled by default**. They require the
separate JVM property `-Dghidrassist.automation.syntheticWrites=true`,
an active writable `synthetic-mmio.bin`, an explicit MC68332 selection,
and fresh completed analysis. Prepare accepts one exact proposal index
and returns a single-use unpredictable approval token with its name and
location. Commit requires that exact token and name, no intervening
revision change, and a fresh READY/default-safe preflight check. Only
non-speculative module MEMORY rows are eligible (no registers, candidate
memory, CS windows, annotations, or VBR). The existing
`HardwareApplyService.apply` runs one Ghidra transaction. Undo is limited
to the same program, the just-committed modification number, and a
single use; it refuses to undo intervening user changes.

The opt-in property must **never** be enabled for a normal Ghidra
profile, real firmware, or ECU411. The default API remains read-only.
Initial code and CodeBrowser/Xvfb regression are a test-only pilot,
not blanket authorization for automated edits to arbitrary projects.

## Read-only active function and entry XREFs

`function.snapshot` returns the current Ghidra Function containing the
active CodeBrowser location, including name, entry and body address count.
`function.xrefs` returns only references **to that function entry**,
with bounded `offset`/`limit` (1..200), type and source/destination
addresses. Neither endpoint mutates the database or consults an LLM.
They return an error when CodeBrowser has no active function.

This is intentionally narrower than all body-level XREFs and call-graph
analysis; distinguish incoming entry references from a complete
interprocedural flow graph. `tools/ga18-wyse-function-xrefs-smoke.py`
provides a separate one-shot host regression on `synthetic-mmio.bin`,
writing a private local JSON report under `reports/`. Existing host
24/24 PASS is unaffected and need not be repeated.

## Asynchronous read-only Decompiler pilot

`decompiler.start` captures the current CodeBrowser function and source
program revision and queues a background Ghidra `DecompInterface` job.
`decompiler.status` returns `task_id`, `state` (IDLE, RUNNING,
COMPLETED, FAILED, STALE), `entry`, `total_characters`, and a bounded
substring `text`. Request `offset` >= 0 and `limit` in 0..8192;
the server retains at most 262144 characters. No LLM or filesystem
output is necessary. The program revision is checked for staleness.
Only one job runs at a time for this server. No program database edits
are performed by the API.

The host-only, isolated regression is
`tools/ga18-wyse-decompiler-smoke.py`. It requires the existing
synthetic function `FUN_00000020`; the script does not create functions
or change the test project. It writes a private report to `reports/`.
Do not treat absence of a synthetic function as a product regression.

## Isolated Ghidra Project Manager

`bash "$HOME/Projekty/Codex/ga-automation-test/ga18-test.sh" manager`
launches only `ghidraRun` with the existing isolated test settings/cache/home.
It does not supply a project path, start the opt-in Automation API, open a
CodeBrowser, or enable synthetic writes. Use this mode to install extension
ZIPs through the Ghidra Project Manager (File -> Install Extensions). Close
that manager before `start` when updating the isolated test installation.

## Unified read-only function analysis

`analysis.bundle` captures the current CodeBrowser function, its source program revision, at most 100 entry XREFs, at most 100 possible MMIO references from the first 4096 body instructions, and starts a background Decompiler task. It returns `analysis.decompiler.task_id`; obtain pseudocode pages separately through `decompiler.status`. `mmio_reference_candidates` are static Ghidra references within the MC68332 peripheral address range `0xFFF000..0xFFFFFF`, not proof of executed writes, peripheral identity or physical CS mapping. `write_candidate` reflects Ghidra ReferenceType only. `incoming_total` and `mmio_candidates_total_scanned` allow detection of display truncation. The method is read-only and does not change the selected hardware profile or Ghidra project.

CLI: `bash "$HOME/Projekty/Codex/ga-automation-test/ga18-test.sh" bundle`, followed by `decompile-status --offset 0 --limit 512`. The synthetic function `FUN_00000020` must already exist in the test project.

## Second deterministic CPU32 call-graph fixture (preparatory stage)

The repository includes `tools/generate-synthetic-callgraph.py`. Run `python3 tools/generate-synthetic-callgraph.py --output /path/to/synthetic-callgraph.bin` to create a 4096-byte CPU32/68000-compatible synthetic input and adjacent JSON golden manifest with SHA-256, 20 function-entry **candidates**, 19 statically encoded absolute JSR edges, one cycle and 4 direct absolute-address MMIO write candidates. The manifest defines intended functions but does **not** claim Ghidra has automatically discovered their boundaries; separate Ghidra import/disassembly/function-creation and real-callgraph acceptance are still required. Disconnected nodes deliberately test reachability boundaries. No original ECU411 file is needed or modified. Golden generator unit tests run in `tests/automation/test_synthetic_callgraph.py`.

### Import/bootstrap requirement revealed by Wyse

The user observed **zero functions from Ghidra Auto Analyze** when opening the raw `synthetic-callgraph.bin`. This is a fixture setup gap, not evidence of a graph traversal regression: raw binary import has no guaranteed reset-entry/function seeds. Import at base `0x00000000`, language `68000:BE:32:CPU32`. To create known synthetic function seeds in an isolated *copy*, run `tools/ghidra_scripts/GA18BootstrapSyntheticCallgraph.py` from Script Manager. The script refuses all other program names/languages, uses a single undoable transaction and 20 planned entries. Ghidra function discovery still needs an independent real-Ghidra test. This bootstrap is not intended for ECU411.

### Native script correction

Ghidra 12.1.4 PUBLIC does not bundle an available Jython runtime by default. Use `tools/ghidra_scripts/GA18BootstrapSyntheticCallgraph.java` from Script Manager, not the historical `.py` prototype. The Java version is program/language guarded, uses Ghidra's standard Java scripting support, and does not require Jython or PyGhidra. The historical Python file remains only for audit; it is not the recommended execution path.
