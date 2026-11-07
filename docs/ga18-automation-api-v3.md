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


## Bounded interprocedural static paths (GA-01/GA-18)

New read-only RPC `analysis.paths` accepts `origin: "reset"|"entry"`,
`entry` (address when origin is entry), `max_depth` (0..32, default 8),
`offset` (0..50000), and `limit` (1..100, default 50).
For reset, the 32-bit big-endian reset PC at image offset 4 selects a
*function candidate*, not an observed boot. Entry mode resolves a requested
address to its containing Ghidra Function. All records come from a snapshot
of current Ghidra direct CALL and WRITE references.

The response `paths` contains `root`, `revision`,
`reachable_entries`, `unreachable_entries`, `total_paths`, and paginated
`paths` rows with ordered `functions`, `call_sites`, `write_site`,
`mmio_target` and `write_reference_type`. The MMIO candidate window is
`0xFFF000..0xFFFFFF` (CPU32 project policy). Functions not reached
*within the selected depth and graph budget* are marked unreachable **under
those search limits only**. `cycles_cut`, `depth_cut`,
`unresolved_calls`, `budget_exceeded`, and `complete` expose
truncation/uncertainty. `complete` never means complete executable coverage.

Traversal uses only exact function-entry direct CALL references. It does not
assume indirect calls, interrupts, exception dispatch, computed jumps, or
physical hardware mapping. A call path is **statically possible only**.
Indexing is limited to 10000 functions and 50000 decoded instructions total;
DFS is limited to 50000 visited path states, and response pages to 100 paths.
The endpoint cannot modify the Ghidra database and never starts Decompiler.

CLI: `ghidrassist-agent paths --origin reset --max-depth 8 --offset 0 --limit 50`
or `ghidrassist-agent paths 00000220 --origin entry --max-depth 20`.
The original `synthetic-callgraph.bin` golden fixture has a reset-rooted
chain ending at writer function 3; writer functions 8, 13 and 18 are in
disconnected components. Unit golden checks are in
`tests/automation/test_call_paths.py`. A fresh **real Ghidra 12.1.4**
end-to-end RPC traversal acceptance test must still be demonstrated before
calling this new endpoint functionally PASS; previous Wyse 110 assertions
validate the imported fixture, not this endpoint.

## Convergent CALL regression fixture

Generate a **separate** CPU32 synthetic program (do not overwrite the existing
20-function test fixture) with:
`python3 tools/generate-synthetic-convergent.py --output /isolated/path/synthetic-convergent.bin`.
The adjacent `synthetic-convergent.json` contains the file SHA-256, direct
CALL sites, four function entries, and expected ordered paths.

Its reset at 0x100 makes two calls: 0x100→0x130→0x190 and
0x106→0x160→0x190. The shared function writes the static MMIO candidate
at 0x190 to 0x00FFFA00. Both paths must be returned separately, each
with its distinct intermediate function and source CALL instruction.
No path deduplication by the terminal function or WRITE site is allowed.

Use native Ghidra Java scripts `GA18BootstrapSyntheticConvergent.java`
(fixture-only transaction) and `GA18VerifySyntheticConvergent.java`
(read-only verification against **production** `AutomationCallPaths`).
CI imports this separate raw binary in an isolated Ghidra 12.1.4
headless project, invokes the scripts and gates on their PASS markers;
the original synthetic-callgraph 110-assertion regression remains intact.
This is *static* reachability evidence, not hardware execution or
physical MMIO mapping. Do not import into ECU411 or use the synthetic
bootstrap on any nonmatching program.

## Register-indirect CALL: conservative first stage

The `analysis.paths` traversal reports instruction-level unresolved indirect
CALL evidence in `unresolved_call_sites`, and increments `unresolved_calls`.
It marks `complete=false` when traversal meets a CALL instruction without
a Ghidra-confirmed reference to a defined function. **No guessed target and no
fictitious path to a peripheral write are returned.** Reference-based direct
CALL traversal and previous results remain unchanged. This does not yet resolve
a register value, pointer-table target, or possible dynamic dispatch target.

The separate `synthetic-indirect.bin` fixture from
`tools/generate-synthetic-indirect.py` has two functions: reset at 0x100
contains JSR (A0), while a disconnected writer at 0x130 stores to 0xFFFA00.
Native Java scripts `GA18BootstrapSyntheticIndirect.java` and
`GA18VerifySyntheticIndirect.java` test the production Java implementation
in Ghidra 12.1.4 headless. The verifier requires one unresolved CALL,
one reachable function, no invented reset-to-MMIO paths, and an explicit
incomplete result. A separate explicit entry at the writer must still
find its direct WRITE evidence.

Further stages may resolve indirect calls *only with separately auditable
static evidence*, such as a proven constant target at an instruction,
and should retain distinct provenance and ambiguity flags. No runtime
execution, register contents, or physical MMIO mapping is verified.

### Proven adjacent register-indirect CALL (CPU32)

A narrowly bounded proof is now supported for immediately adjacent
`MOVEA.L #absolute,An; JSR (An)` instructions in the same decoded function
on CPU32, with no intervening instruction. This produces a path to a
**defined** target function with per-hop `call_evidence:
["adjacent_movea_immediate"]`; normal Ghidra CALL-reference hops carry
`ghidra_call_reference`. The byte pattern and destination function are
both verified; any other register-indirect CALL remains unknown,
included in `unresolved_call_sites`, and makes `complete=false`.
The new `synthetic-indirect-constant.bin` fixture and native Ghidra
verifier enforce this distinction. No generic register propagation,
pointer-table evaluation, interprocedural value inference, or proof
of runtime control flow is claimed.

### Bounded CPU32 register-flow proof (NOP-only)

`analysis.paths` now recognizes a bounded, straight-line pattern:
`MOVEA.L #absolute,An`, followed by up to four decoded intervening
`NOP` instructions and a matching `JSR (An)`, where the target is
already a defined function. Its per-hop provenance is
`bounded_movea_nop_chain`. Adjacent MOVEA/JSR retains the previous
`adjacent_movea_immediate` provenance. Preexisting Ghidra CALL
references retain `ghidra_call_reference`.

**This is deliberately not general register-value propagation.**
Unknown or register-writing intervening operations, missing decoded
instructions, branches, any cross-function gap, excessive distance,
or unresolved target functions invalidate the proof; they remain
`unresolved_call_sites` with `complete=false`. No instruction is
executed. A register value is never assumed across a control-flow
boundary or unverified instruction.

The isolated synthetic-register-flow.bin fixture generated by
`tools/generate-synthetic-register-flow.py` covers NOP preservation,
`MOVEA.L D0,A0` clobbering and a branch barrier. Native Java scripts
`GA18BootstrapSyntheticRegisterFlow.java` and
`GA18VerifySyntheticRegisterFlow.java` run real Ghidra 12.1.4
with temporary CALL references removed inside a rolled-back
fixture-only transaction, requiring proof from actual production
`AutomationCallPaths.query` rather than Ghidra's own CALL XREFs.


### MOVEQ-safe straight-line value preservation

The bounded CPU32 resolver now also permits `MOVEQ #signed8,Dn` between
`MOVEA.L #absolute,An` and the matching `JSR (An)`. MOVEQ changes a
data register and the CCR, **not the tracked address register**. The resolver
still stops at every conditional/unconditional branch, register-address
overwrite, unknown instruction, noncontiguous instruction, or when the
bounded lookback is exceeded. `bounded_movea_safe_chain` identifies
a path containing MOVEQ; the older NOP-only provenance remains
`bounded_movea_nop_chain` for API compatibility.

The distinct 4-function synthetic `synthetic-moveq-flow.bin` fixture
and `GA18VerifySyntheticMoveqFlow.java` test a safe
`MOVEA/MOVEQ/NOP/JSR` chain plus negative cases for a `BNE` boundary and
a following `MOVEA.L D0,A0` clobber. The verifier removes existing Ghidra
CALL references only in a temporary transaction rolled back at completion.
The native CI tests exercise the actual product implementation, not a
simulated interpreter. Results are static evidence only.


## API completion tranche — safe controls and evidence retrieval

Added four authenticated JSON-RPC methods in the existing CodeBrowser extension:

- `ui.tab.select`: `{"tab":"Hardware Analysis"}`. Selects one existing,
  enabled top-level GhidrAssist tab by exact title; returns an updated UI snapshot.
- `hardware.cancel`: requests cancellation through the original Swing Cancel
  Analyze button. Rejects requests unless a cancellable scan is active. Task
  state is read separately with `hardware.task`; cancellation acknowledgment
  is not proof that a background worker has already stopped.
- `analysis.report`: `{"format":"markdown","offset":0,"limit":4096}`.
  Returns revision-checked, bounded (maximum 8192 UTF-16 Java characters)
  evidence page with `text`, `total_characters`, `more`, and `revision`.
- `analysis.export`: uses the same bounded, revision-checked transfer. Formats
  are `markdown`, `config_csv`, `names_csv`. It **does not write a file on
  the server**: the authenticated caller may save the received pages itself
  after validating revision and completeness. This avoids arbitrary file-path
  execution or overwriting on the user's machine.

CLI: `ghidrassist-agent tab-select "Hardware Analysis"`,
`ghidrassist-agent cancel`, `ghidrassist-agent report --format markdown
--offset 0 --limit 4096`, and `ghidrassist-agent export --format config_csv
--offset 0 --limit 4096`.

The current tranche does **not** enable production Apply/Undo, automatic
program switch, or write-oriented GUI automation. Existing synthetic-only
Apply/Undo permissions and protections remain unchanged. These operations
require separate safety design and real-Ghidra verification.


### MMIO Explorer row selection (fifth completion method)

`ui.table.select` accepts `{"table":"hardware.mmio","row":0}`, where
`row` is a **zero-based index in the current visible, filtered MMIO
Explorer JTable**. If that modeless dialog is not open, the command opens
the existing read-only MMIO Explorer on the EDT. Requires a fresh completed
Analyze revision; unknown table IDs and out-of-range rows fail closed.
It returns selected row, PC and revision without navigating Listing or
changing the Ghidra database. The existing dialog's filter state is
preserved. CLI: `ghidrassist-agent table-select hardware.mmio --row 0`.
The current API intentionally does not expose arbitrary Swing tree/table
reflection or blanket UI control.


### Opt-in same-project program opening (sixth completion method)

`project.program.open` accepts `{"path":"/synthetic-mmio.bin"}` or an
exact existing Ghidra ProjectData domain-file path. It requires the JVM
`-Dghidrassist.automation.allowProgramSwitch=true`, normally supplied only
with launcher `--allow-program-switch --project ... --program ...`.
The server rejects URLs, host file paths, parent traversal, missing files,
read-only domain files and switching away from an unsaved active Program.
It never closes an existing Program, changes bytes, saves or imports a
file; it uses Ghidra `ProgramManager.openProgram(DomainFile)`. Opening the
already active Program is idempotent, including when it has unsaved edits.
CLI: `ghidrassist-agent program-open /synthetic-mmio.bin`.
The operation is disabled by default and restricted to the active
Ghidra project; opening arbitrary host paths is not supported.


## Write capability policy — stage 1 (no production writes)

The agent has a fail-closed write-mode vocabulary:

- `READ_ONLY`: default for normal launcher sessions, no API writes.
- `AUTO_SAFE`: currently authorizes **only the preexisting** isolated
  `synthetic-mmio.bin` Apply/Undo pilot when the separate
  `syntheticWrites=true` property is present. Its original preflight,
  exact Program/revision/token/transaction/Undo protections remain enforced.
- `FULL_CONTROL`: **declared but not enabled**. The launcher refuses
  this mode and API writes to actual firmware projects remain disabled.
  This name is not authorization to overwrite user names, memory blocks or
  other Ghidra changes.

Use `ghidrassist-agent-start --write-mode read-only` for ordinary work.
For the isolated test fixture only, use `--mode test --write-mode auto-safe
--synthetic-writes` with the exact known project and program. Query
`session.status` to see `write_mode`,
`production_writes_enabled: false`, and whether the synthetic pilot is
enabled. The synthetic pilot also accepts legacy direct JVM activation,
where `syntheticWrites=true` without an explicit mode maps to `AUTO_SAFE`
for existing CI compatibility.

Stage 2 requires a per-project allowlist/consent receipt, review of exact
proposals and full preflight after consent, and isolated-copy tests of the
actual transaction and Undo semantics. Until these checks are implemented
and verified, do not use `FULL_CONTROL` with real firmware.


## Copy-scoped AUTO_SAFE Review/Apply/Undo (second tranche)

Three distinct JSON-RPC methods `hardware.review.prepare`,
`hardware.review.apply`, and `hardware.review.undo` reuse the existing
single-item, conservative memory-region preflight and transaction. They are
**separate** from the older `hardware.apply.*` synthetic-only pilot.

Activation requires the operator to create and verify an **isolated copy of
the Ghidra project**, then explicitly launch:

```sh
ghidrassist-agent-start --mode test --write-mode auto-safe \
  --review-copy --ghidra /path/to/ghidra_12.1.4_PUBLIC \
  --project /absolute/path/to/ISOLATED_COPY.gpr \
  --program program-inside-project.bin \
  --expected-sha256 64_hex_digits
```

`--review-copy` is the operator's **attestation** that the project path is
a disposable working copy. It does not magically detect whether the user
provided an original project: inspect the path before enabling. The runtime
compares the active Ghidra Project locator to the exact selected `.gpr`,
the active DomainFile's full project-relative path, and the program's
original-import SHA-256 to that launch receipt **before every prepare,
commit and Undo**. Copy authorization is restricted to `AUTO_SAFE` and
cannot coexist with the older `syntheticWrites` privilege.

`hardware.review.prepare` takes `{"index":N}`, returns a one-use token,
name, location, project-relative program path, source SHA-256 and revision,
and does not modify the database. The caller must inspect this result
before `hardware.review.apply` with exactly the token and name.
Apply allows only a single default-safe, non-CS/non-candidate module MEMORY
proposal from a fresh user-selected MC68332 analysis. It rechecks
the source Program, revision and preflight after token consumption.
`hardware.review.undo` is one-shot and refuses if the active program,
source identity, modification count, or Ghidra Undo state changed. It
does not rewind intervening manual changes intentionally.

CLI commands: `ghidrassist-agent review-prepare --row N`,
`ghidrassist-agent review-apply --token TOKEN --name NAME`, and
`ghidrassist-agent review-undo`.

This does **not** authorize writing to the original ECU411 project,
physical firmware file, arbitrary register labels, Chip Select guesses,
function names or unbounded batches. `FULL_CONTROL` is still disabled.
The new separate `ga18-review-copy.yml` CI workflow executes this
path on a generated isolated fixture in real Ghidra CodeBrowser/Xvfb,
including failed approval and successful exact-transaction Undo. A PASS
on that synthetic copy is not a real-firmware acceptance.


### Audit receipts and fail-closed source mismatch

A working-copy `hardware.review.prepare` response now explicitly returns
the proposed single item, location, `preflight_state`,
`preflight_description`, `proposal_details`, `planned_changes=1`,
`applied=false`, source identity, revision and the consumed-on-use approval
token. Successful Apply returns the actual changed/skipped counts and the
before/after Ghidra modification numbers plus rechecked preflight rationale.
Undo returns the original transaction's modification number and its
post-Undo revision. These are **in-session** receipts, not an actor
attribution or a persistent Ghidra audit database.

`session.status.review_copy_enabled` indicates the feature flag was
requested. `review_copy_authorized` instead requires the **currently
active** project, program and SHA-256 to match the startup receipt.
The separate real-Ghidra copy regression also supplies an intentionally
incorrect SHA-256 and must obtain a 400 denial at Review Prepare, with no
transaction started. This validates the guard rather than just its presence
in the Java source.

The launcher also requires an actual `.gpr` file and a matching, real
`.rep` data directory and rejects symlinks at either top-level path.
Do not copy just the `.gpr`; close the source project and copy the
complete, independent project first. This is an extra guard, not a
cryptographic demonstration that a copy is independent.


## Critical startup regression — recursive CodeBrowser window launches

A Dell Precision test of the earlier build at `6bb2733950e35fb0cf56b2be5f2833f3b21719bb`
caused CodeBrowser windows to open repeatedly until the user logged out.
`AgentProjectOpenPlugin` had implemented `ApplicationLevelPlugin`, which
permits it in CodeBrowser and other child tools. Its constructor then
launched another CodeBrowser from every such instance.

**Do not use the original artifact/launcher for program auto-open.**
The fix marks the opener `ApplicationLevelOnlyPlugin`, explicitly checks
for `FrontEndTool`, and atomically consumes the process-wide open request
before launching a child. The real CodeBrowser harness constructs an opener
under the formerly triggering JVM properties and verifies it does not arm a
Timer. The launcher also fail-closes **before starting Ghidra** if the
isolated settings directory contains an old `GhidrAssist.jar` without all
three verified class markers. A normal manual Ghidra session with the
automation launcher properties cleared is not affected by this feature.

The guard is intended to prevent recursive spawning; end-to-end automatic
Project Window -> CodeBrowser acceptance on a clean, isolated project is a
separate test and should not be claimed based solely on the negative
CodeBrowser guard. Existing CPU32 CI and synthetic Apply/Undo evidence for
earlier SHAs remains valid only for those narrower assertions.

## Decompiler task and active-program isolation (GA-18)

`decompiler.status` remains read-only and accepts the optional
`{"task_id":"<id-from-decompiler.start>","offset":0,"limit":4096}`.
A wrong nonempty task ID is rejected, preventing an old polling loop from
reading pages of a newer task. The server also checks active Ghidra
**Program object identity**, not only its revision: if CodeBrowser changes
program, the prior task reports `STALE` with an error and **no pseudocode**.
Revision changes retain the previous `STALE` rule. Existing clients
without `task_id` remain supported but are also program-guarded.

CLI: `ghidrassist-agent decompile-status --task-id <id> --offset 0 --limit 4096`.
A native isolated Ghidra 12.1.4 synthetic CPU32 regression checks
task identity and a simulated changed active program; no project writes.

## Decoded Listing evidence in `listing.snapshot` (GA-18)

The preexisting top-level `address` remains unchanged. The read-only
response now also contains a nested `listing` object with `address`,
`revision`, `decoded`, and (only where a decoded Ghidra instruction is
present) `instruction_address`, `text`, `mnemonic`, `flow_type`,
`length`, up to 32 bytes in `bytes_hex`, `bytes_truncated`,
`function_entry` if known, `reference_total` and at most 16 outgoing
`references` with their source, destination and Ghidra reference kind.
The nested object is intentionally limited to **one** instruction at the
active CodeBrowser cursor; it is not a bulk disassembly export. It rejects
a stale Listing location from a different active Program and makes
undecoded address locations explicit (`decoded:false`).

All evidence reflects **static Ghidra Listing** and reference metadata.
Decoded instructions or reference types do not prove execution, live MMIO,
MC68332 device register identity or physical memory mapping. The
real-Ghidra 12.1.4 synthetic-callgraph CI verifies the production
snapshot logic without opening a second GUI or modifying a project.

## Bounded Listing pages and whole-function XREFs (GA-18)

New read-only RPC `listing.range` accepts optional `address` (otherwise the
active Listing location), `offset` in decoded instructions (0..4096),
`limit` (1..64, default 32), and optional `expected_revision` from the
first page. The result `listing_range` includes `start`, `revision`,
`offset`, `limit`, `returned`, `next_offset`, `has_more`,
`offset_unit`, and `rows` (each row uses the existing single-instruction
`listing.snapshot` schema, retaining bytes/ref caps). Use the **same
explicit start** with a new offset and the original revision on later pages.
Instructions are in Ghidra address order; they may be separated by gaps or
cross functions. This is not an execution trace or raw byte disassembly.
Bad bounds/start, changed program revision or mismatched active ProgramLocation
are rejected. The original `listing.snapshot` response is unchanged.

New read-only `function.xrefs.body` uses the current CodeBrowser function,
`direction` (`incoming`, `outgoing`, or `both`, default `both`),
`offset` (0..4096), `limit` (1..100, default 50), optional
`expected_revision` and `expected_entry`. Incoming uses all Ghidra
reference destinations in the body's AddressSet, including offcut targets;
outgoing uses reference sources in that set. `both` orders incoming then
outgoing; internal body references may appear twice with distinct direction.
Rows have `from`, `to`, `type`, `direction`, `source_in_body`,
`target_in_body`. The result reports `next_offset`, `has_more`,
`total_known` and `scan_truncated`; iteration never exceeds the bounded
8192-reference scan budget. This does not infer unresolved indirect calls.
The original `function.xrefs` remains incoming-entry-only and unchanged.

CLI examples (matching updated client required):

```sh
ghidrassist-agent listing-range 00000100 --offset 0 --limit 16
ghidrassist-agent listing-range 00000100 --offset 16 --limit 16 --expected-revision 7
ghidrassist-agent function-xrefs-body --direction both --offset 0 --limit 50
ghidrassist-agent function-xrefs-body --direction outgoing --expected-entry 00000100 --expected-revision 7
```

The RPC operations do not write Ghidra database content, enable
`FULL_CONTROL`, or establish physical MMIO/IRQ mapping. Native Ghidra
12.1.4 CI verifies packaged production classes on synthetic CPU32
functions, pagination and stale-guard failures.

## GA-15/18 — bounded cancellation and delayed model callbacks (2026-11-07)

Automation API `agentic.findings.page` remains strictly read-only.
No new endpoint for cancel or arbitrary ReAct execution is exposed.
Source invalidation through the existing Ghidra `ProgramPlugin`
activation event now *also* cancels the corresponding active ReAct
analysis, while retaining the existing fail-closed source and revision
checks. A manual ReAct cancellation may retain an incomplete
`CANCELLED` evidence snapshot; its actual Ghidra native tool calls
are accounted for, and a late model callback cannot promote its
state to `SUCCESS` or publish more rows. Switching back to the
previous CodeBrowser Program never revives an invalidated snapshot.

Real Ghidra 12.1.4 PUBLIC / Java25 CI drives two isolated scenarios
from a distinct external `ghidrassist-agent` process: direct
cancellation and GUI Program A→B→A switching, each after one
read-only native tool call and before releasing the scripted model
callback. The CI checks `RUNNING`, `CANCELLED`, HTTP denial of
stale evidence, actual source/tool-call counts, unchanged Ghidra
Program revision, safe read-only offline incomplete checkpoint and
no late UI updates or evidence resurrection. The tests do not use
a real LLM or local Wyse/Precision/Supervisor.

## GA-15/18 — real ReAct read-only tool → authenticated JSON-RPC → external CLI (2026-11-07)

The isolated CI end-to-end workflow runs actual **Ghidra 12.1.4
PUBLIC / Java25** CodeBrowser and the **real ReActOrchestrator**, not
only a manually populated FindingsCache. A strict read-only
`ToolExecutionPolicy` authorizes exactly one native
`ga_get_current_address` call through the real ToolRegistry.
Only the LLM responses are **scripted inside test sources**; no AI
provider, OAuth or external inference endpoint is contacted.
The production AutomationServer still runs on authenticated
`127.0.0.1`, and the external `ghidrassist-agent` is a distinct
OS process. No test hook allows RPC callers to start ReAct or
inject findings.

The external CI client checks unauthorized Bearer denial,
RUNNING source incompleteness, after-completion findings and page
stitching with exact run/program/cache revision, wrong-revision
refusals, atomic no-overwrite local checkpoint, and offline
`agentic-verify`/`agentic-read` without a Ghidra session.
All evidence is synthetic with static Listing PC 0x00000020;
no runtime execution, complete reverse engineering or real LLM
session recovery is claimed. Only real CI acceptance at exact
commit SHA may establish PASS.

## GA-12/15 — ReAct evidence read-only pages and explicit local checkpoint (2026-11-06)

`agentic.findings.page` exposes **only the real active/last completed
ReActOrchestrator FindingsCache** attached to the **same current Ghidra
Program object**. It never starts a model, executes a tool, modifies
Ghidra or accepts a client-provided finding. The authenticated loopback
server remains disabled unless Automation API is explicitly enabled.
No user credentials, original firmware or production project are
required by its deterministic regression tests.

JSON-RPC params: `offset` (0+), `limit` (1..100, default 25),
optional `expected_run`, `expected_findings_revision` and
`expected_program_revision`. A nonzero offset must bind to the first
page's `run` and `findings.revision`; clients should also bind
`expected_program_revision`. Invalid/stale run ID, active Program,
Program modification revision or import SHA causes a refusal, not a
partial, silently substituted page. Pages include an opaque per-analysis
run ID, Program revision, import SHA metadata, analysis state
(RUNNING/SUCCESS/CANCELLED/MAX_ITERATIONS/MAX_TOOLS/ERROR), immutable
retained finding rows, accepted/evicted counters, source-incomplete,
`hasMore` and `complete`. Completion is **false** during RUNNING or
cancelled/failed/budget-limited analysis even when all retained rows fit.
It remains false when evidence was pruned or original tool output was
truncated. It is *not* a claim of dynamic firmware execution or a
complete reverse engineering proof.

Switching to a different active CodeBrowser Program invalidates the
old Program's published Agentic pages immediately. Returning to a
previously opened Program does not revive the prior run: start a new
investigation to publish new evidence. This protects against linking
post-switch tool results to a pre-switch source while the real ReAct
background task is still executing. The switch invalidates the read-only
bridge, not the LLM task itself. The protection is also checked in
an isolated real CodeBrowser two-Program Xvfb regression.

CLI:

```sh
ghidrassist-agent agentic-findings --offset 0 --limit 25
ghidrassist-agent agentic-findings --offset 25 --limit 25 \
  --expected-run '<run from first page>' \
  --expected-findings-revision 3 --expected-revision 7

# Save a bounded, immutable, read-only evidence handoff locally;
# this file must not already exist. Never upload private evidence.
ghidrassist-agent agentic-checkpoint --limit 100 \
  --output /path/to/isolated/private/agentic-evidence.json

# Offline verification after reopening a terminal or restarting Ghidra;
# checks corruption only; does NOT restore a model or tool session.
ghidrassist-agent agentic-verify \\
  --input /path/to/isolated/private/agentic-evidence.json

# Browse already saved evidence pages offline after Ghidra closes.
# No token, ready session, model or project is needed.
ghidrassist-agent agentic-read --input /path/to/isolated/private/agentic-evidence.json --offset 0 --limit 25
```

The checkpoint command fetches **every retained page** with strict
run/Program/evidence-revision and count checks, refuses races/oversized
responses, emits a canonical SHA-256 digest of the bounded JSON payload,
and creates a local file atomically with mode 0600. It does not overwrite
existing files, upload data, create an AI task, re-run the model or write
anything into the Ghidra Program. The digest detects accidental local
file corruption, **not** malicious modification or authenticated
authorship. Omitted/pruned source is identified and never reconstructed.
A checkpoint is a durable **read-only evidence handoff**, not a
serializable/resumable model context or authority to Review/Apply/Undo.

Regressions: pure Java21 per-run/Program identity + stale refusal;
Python3 standard-library local SHA-256, atomic no-overwrite and
multi-page stitching; full Ghidra 12.1.4 PUBLIC/Java25 extension build;
actual isolated synthetic Ghidra Program object and its unchanged
revision. The synthetic bridge test does not perform model calls and
does not claim to test a real user investigation.
