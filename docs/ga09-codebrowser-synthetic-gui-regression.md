# GA-09 — isolated full CodeBrowser MMIO Listing GUI regression

This is a **standalone additional harness** for Ghidra 12.1.4 PUBLIC,
stacked on the immutable PR #56 source commit
`ed53849141141da7810736c61d8e8a7669aa8767`. It does not modify
that commit, the original owner firmware, project, local test profile,
OAuth or the private Supervisor.

## Scope

The existing isolated Query/policy harness in PR #89 creates its own
`PluginTool` and deliberately does **not** include CodeBrowser. Its
PASS proves Query/policy behavior, not CodeBrowser Listing navigation.
This harness instead loads the actual Ghidra `CodeBrowserPlugin`,
`GoToServicePlugin`, `ClipboardPlugin`, `ProgramManagerPlugin` and
production `GhidrAssistPlugin` into an isolated project and tests the
real `GoToService` / `CodeViewerService` path.

Two generated, nonsensitive 68000/CPU32 binary fixtures are imported
by Ghidra's `BinaryLoader`. One contains the **synthetic** instruction
`MOVE.W #$40CA,($00FFFA00).L` at PC `0x20`; the other contains no
MMIO accesses. Java disassembles **only** the new synthetic test project
and confirms the native Ghidra Listing instruction before any Analyze
operation. This test instruction is not evidence about ECU411.

The GUI driver exercises the production `HardwareAnalysisTab`
`Analyze`, `MMIO accesses...`, `SIMCR` search filter and actual
`Go To Listing` button, verifying that the Listing cursor moves to the
synthetic instruction. With the MMIO dialog still visible, it switches
the active Program to `guard-other.bin` and checks that button and
double-click both refuse stale navigation. ProgramManager's active
Program must remain the second fixture, and the user-visible warning
must say `Active program changed; rerun Analyze.`

The driver uses a real `GhidraTool` (not the generic `PluginTool` used
by Query-only harness #89). It verifies the saved `GhidraToolTemplate`
actually contains `<EXTENSIONS>` and `GhidrAssistPlugin` metadata,
restores this template into a fresh test-only tool instance, and checks
that the plugin remains enabled **without** another New Plugins prompt.
This is a same-process save/reload test, **not yet proof of persistence
across a full Ghidra application restart** or across the owner's CodeBrowser
profile migration. That remains a separately observable local gate.

## Reproducibility and isolation

Run from a GhidrAssist source checkout with a compiled extension ZIP:

```bash
xvfb-run -a python3 tests/codebrowser_harness/run.py \
  --ghidra /path/to/ghidra_12.1.4_PUBLIC \
  --java-home /path/to/jdk-25 \
  --extension-zip /path/to/GhidrAssist-12.1.4.zip \
  --extension-sha256 VERIFIED_SHA256 \
  --output /path/to/a-new-empty-output-directory
```

Temporary home/settings/index/project/cache and extracted extension
are destroyed on exit. ZIP members and exact extension version are
validated. Java exercises a genuine display with Xvfb/Openbox. A
failed, missing, or headless GUI is **BLOCKED**, not PASS.
Result JSON distinguishes `PASSED_SYNTHETIC_CODEBROWSER` from
formal host/owner CodeBrowser acceptance, and unconditionally contains
`supervisor_ack=false`. Neither synthetic smoke nor any log can
set a private Supervisor nonce/ACK. No remote model/API is used.

## Separate acceptance responsibilities

The owner has independently reported **MANUAL GUI PASS** for the
actual pinned PR #56: 1265 MMIO references, three SIMCR rows, target
0x00002BCA showing static 0x40CA write, and both stale-program
navigation guards working after switching to guard-other.bin.

The original private Supervisor workflow remains
**BLOCKED / INCONCLUSIVE, without ACK**. The old result must not be
changed or backfilled with this synthetic CI outcome.

Likewise, `Can't find plugin package for GhidrAssist! Creating
stub...` is addressed on an **independent forward-fix PR #92** that
registers the missing PluginPackage. The repeated CodeBrowser
extension-discovery dialog may require separate profile-save/reopen
investigation and is not automatically solved by the PluginPackage
registration. This test intentionally does not modify the user's
installed Ghidra profile or any of the above pinned commits.
