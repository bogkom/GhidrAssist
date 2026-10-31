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
The runner additionally saves `GhidraToolTemplate.saveToXml()` into
its synthetic-only output and launches a **second Java process** with a new
Ghidra application initialization. It must reload that exact tool template,
confirm CodeBrowser and GhidrAssist are enabled, and reject a repeated
`New Plugins Found!` dialog. The restart result is a separate
`restart-results.json`. This verifies process-restart persistence **for
the disposable test profile only**, not for the owner's migrated Wyse
CodeBrowser configuration, which remains a separate local gate.

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


## GA-18 — real X11 CodeBrowser screenshot proof (synthetic only)

In the existing isolated Xvfb/Openbox CodeBrowser regression, after verifying
actual `GoToService` navigation to the synthetic SIMCR Listing, Java checks
the visible Ghidra tool-frame identity, grabs the **real displayed X11 pixels**
with `java.awt.Robot.createScreenCapture` (not `JComponent.printAll`, a
rendered/mock PNG, or a generated image), and writes `codebrowser-x11.png`.
The Python runner separately validates PNG signature, IHDR/CRC, bounded width
and height, and exact SHA-256 against `gui-results.json`. The GitHub Actions
artifact contains the screenshot from this synthetic fixture along with
`result.json` and the Ghidra logs.

**Evidence levels intentionally separated:**

- `window_identity_verified=true`, `codebrowser_listing_verified=true`,
  `x11_capture_proof_verified=true`: programmatic checks against an actual
  Ghidra CodeBrowser and native X11 screenshot (the existing navigation and
  Ghidra Undo assertions remain mandatory).
- `x11_screenshot_sha256`: a digest of the captured PNG, independently
  checked by the Python runner; not proof that a human or Codex viewed it.
- `visual_readback_verified=false`,
  `human_visual_readback=NOT_PERFORMED`,
  `supervisor_ack=false`: no independent visual readback, authorized GUI
  worker, native Supervisor test turn or nonce ACK has occurred.

This **does not** qualify a `GUI_REQUIRED` or `LISTING_REQUIRED`
Supervisor plan as `HEADLESS_SAFE`. A genuine GUI/Listing plan still requires
a separately authorized operational GUI lane, actual visual inspection of
the matched captured PNG, target commit/window identity, and an authentic
completed Codex turn with nonce/ACK. Do not use the original Wyse project,
firmware, credentials or graphical display. An isolated disposable Xvfb
screen is sufficient for this automated regression, not for operator GUI
acceptance.


## GA-18 — in-process Listing/Decompiler and X11 report, PR #101

New isolated genuine Ghidra 12.1.4 CodeBrowser code reads active ProgramManager
and CodeViewerService location, actual containing Function and visible
DecompilerPlugin function (not inferred from the Listing or a title). It
navigates to the synthetic Function at 0x00000020 *after* closing the
MMIO modal dialog, so the original CodeBrowser window remains visible.
The synthetic Ghidra Program is disposable and never uses ECU411.

The harness queries the live X11 tree for the unique exact frame title,
XID, WM_CLASS and WM_NAME using xwininfo/xprop. Robot captures the actual
visible window into ghidra-window.png; codebrowser-x11.png is a byte-for-byte
compatibility copy, not printAll(), a mock or a transformed screenshot.

The same process emits codebrowser-assertions.json matching the structural
schema from Supervisor PR #90: schema=1,
kind=ga18-codebrowser-listing-assertions, source_kind=ghidra-inprocess-codebrowser,
case_id, run_id, window_id, window_class, window_title, program, address,
function, listing_verified, decompiler_verified, image_sha256 and dimensions.
It also reports decompiler_function, pre_capture and post_capture states
and capture timestamps to detect inconsistent in-process navigation.

The Python assertion_audit.py independently verifies the original PNG
signature, IHDR, all PNG chunk CRCs, the image SHA256 and dimensions,
fixed expected Program/address/function, complete report, matching
pre/post states, monotonic times, X11 window identity and false-only GUI
ACK, provenance and formal PASS fields. 21 positive/negative regression
tests cover wrong program/address/function, stale Listing, changed PNG,
wrong digest, corrupt PNG, bad time ordering and incomplete report.

**Important provenance limitation:** All Program state and time fields
are self-reported by the harness. A matching report and PNG do NOT prove
they came from a trusted instrumented Ghidra execution, or independently
bind actual pixels to semantic state at that time. The Supervisor PR #90
checker may only return STRUCTURAL_EVIDENCE_CONSISTENT_PROVENANCE_PENDING.
trusted_ghidra_provenance_verified=false, same_run_semantics_verified=false,
visual_readback_verified=false, native_nonce_ack=false,
supervisor_ack=false and formal_gui_pass=false remain mandatory.

**Supervisor handoff:** Before stronger acceptance, a trusted host must
independently pin the complete approved source/extension/harness SHA,
both original PNG and JSON file digests, original capture XID and title,
a fresh host challenge with an authenticated observer/chain of custody,
plus a genuine authorized native GUI worker receipt and semantic visual
inspection. Merely copying a host nonce into harness JSON or taking
another image-diff test does not establish independent provenance.
These stronger checks belong to bogkom/codex-supervisor, not to an
unapproved HEADLESS_SAFE queue or a new GUI Goal.

Dedicated CI uses the existing full-extension build and Xvfb/Openbox
CodeBrowser harness, bundles the report, original PNG, Java/Python source,
test cases and SHA256 manifests. Never retroactively alter older FAILED
or BLOCKED GUI Supervisor reports.
