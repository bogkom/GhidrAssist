# GhidrAssist package registry — Ghidra 12.1.4 (2026-10-29)

## Problem confirmed by source comparison

On the pinned PR #56 artifact, `GhidrAssistPlugin` uses
`@PluginInfo(packageName = "GhidrAssist")`, but no subclass of
`ghidra.framework.plugintool.util.PluginPackage` registers that name.

In Ghidra 12.1.4 `PluginPackage.getPluginPackage()` looks the name up in
a ClassSearcher-driven map. If absent, it logs
`Can't find plugin package for GhidrAssist! Creating stub...` and falls back
to the built-in Miscellaneous package. The warning **does not by itself
prove that the executable plug-in JAR is missing or that the plug-in failed
to load**. This distinction matters: the migrated Wyse test profile
initially did lack `lib/GhidrAssist.jar`, yet after installing the original
pinned artifact, the real Hardware Analysis panel was visible and the
warning persisted.

## Implementation and tests

Register `GhidrAssistPluginPackage` as a public zero-argument
`PluginPackage` extension point and use its `NAME` constant from
`@PluginInfo`. Its icon is a tiny built-in neutral bitmap, requiring no
private filesystem access or resource loading. Test its constructor,
package name, icon and runtime annotation in CI and assert that the
**compiled** extension ZIP includes both `GhidrAssistPluginPackage.class`
and `GhidrAssistPlugin.class` plus executable `lib/GhidrAssist.jar`.
CI builds against the exact SHA-pinned Ghidra 12.1.4 PUBLIC distribution.

This is a separate forward fix on `master`. It does **not** modify
PR #56 commit `ed53849141141da7810736c61d8e8a7669aa8767`,
its test plan, verified artifact `12874117245`, original firmware,
existing Ghidra projects, OAuth or private Supervisor reports. The
Java/ZIP structural CI cannot guarantee real CodeBrowser profile
persistence; an isolated host restart test is still needed.

## Distinct follow-up observations

The two observations in the Wyse continuation report have different
acceptance criteria:

1. **Package stub warning:** after a *new* properly built/tested package,
   observe `PluginPackage.exists("GhidrAssist")` through a real isolated
   Ghidra startup and absence of that warning. This does not retroactively
   change the original pinned PR #56 artifact.
2. **Repeated "New extension plugins detected":** independently verify
   save/close/reopen of the isolated CodeBrowser tool configuration and
   plugin enabled state. The observed `KNOWN_EXTENSIONS=[]` alone is
   not sufficient to infer why the dialog reappears. Do not overwrite
   the original migrated profile or alter tool configuration without a
   disposable copy and explicit authorization.
3. **Stale MMIO navigation guard:** old table rows exist only in the
   `HardwareAnalysisTab` instance, after that process ran Analyze. The
   table is not serialized into the Ghidra project; no row should be
   expected after a fresh application start. For a new test, use a small
   *synthetic* CPU32/68k fixture with a decoded known direct MMIO store,
   open in an isolated CodeBrowser, run the read-only Analyze on that
   synthetic program, open the MMIO explorer, retain the dialog, switch
   to a second synthetic program and press `Go To Listing` on the stale
   row. Navigation must refuse and must not modify any project or
   redirect to the previous program. This is a **separate CodeBrowser
   acceptance**, not covered by PR #89's standalone Query harness.
   If the synthetic fixture produces zero rows, record BLOCKED instead
   of fabricating a row or scanning the private ECU again.

No PASS/ACK is claimed for any of these host test cases. The original
PR #56 remains DRAFT pending a genuine and pinned acceptance result.

## 2026-10-29 — diagnosed extension-detection lifecycle (upstream Ghidra)

Further direct inspection of Ghidra's
`ToolExtensionsStatusManager` and `ToolExtensionsEnabledState` reveals
a **separate** built-in persistence mechanism:
`ToolExtensionsStatusManager.saveToXml()` writes an `<EXTENSIONS>`
element with the installed extension name and `<PLUGIN CLASS=...>`
records into **the tool's saved XML configuration**. On tool restore,
`restoreFromXml()` compares those records against current installed
extension plug-ins, removes already enabled classes and offers the
`New extension plugins detected` prompt only for remaining entries.
If a previously saved CodeBrowser configuration lacks the extension
record or contains stale plugin classes, the prompt may recur even
when the plug-in itself is working.

This is a **tool configuration persistence issue**, not a preference
that GhidrAssist should forcibly reset or an invitation to auto-edit
an original Wyse profile. Ghidra's documented safe operation for a
disposable CodeBrowser configuration is `File → Save Tool` after
accepting the plugin; on restart it should restore the saved
`<EXTENSIONS>` and enabled plug-in state. If it still prompts, inspect
only an exported disposable tool XML; do not change user settings,
configuration files or extensions on a live profile. The PR #93
synthetic full-CodeBrowser CI harness separately exercises
`saveToolToToolTemplate()` and the Listing path. In-memory tool
serialization alone is **not** proof of successful profile persistence
across a real application restart; this remains a local acceptance gate.

The upstream extension discovery and package registry are distinct.
Registering `GhidrAssistPluginPackage` prevents the "Creating stub..."
fallback, but does not by itself guarantee saving the current
CodeBrowser tool configuration. Do **not** call this prompt bug fixed
without an isolated save/close/reopen test on the corrected extension.
