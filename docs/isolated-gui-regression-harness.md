# GA-18 — isolated GhidrAssist GUI regression harness (Ghidra 12.1.4)

This is a **new implementation** derived from the reviewed 2026-10-29
historical reference under `docs/gui-regression-reference/` on branch
`reference/gui-harness-replay-20261029`. It is not an archived-source
copy and is not evidence of an acceptance of GhidrAssist PR #56.

## Design and isolation

The runner uses exactly one **synthetic 256-byte 68000 binary**, imports
it into a disposable project via Ghidra 12.1.4 `analyzeHeadless`, then
starts a standalone Java `PluginTool` with `ProgramManagerPlugin`
and `GhidrAssistPlugin` without the normal Project Manager/CodeBrowser
UI. The plug-in's Query component and normal Swing EDT are exercised.
Everything is under Python `TemporaryDirectory()`, including the
project, user.home, settings, cache, extension installation, and class
files. The runner never reads, clones, edits or copies the user's ECU411
firmware/project, any other private project, RAG catalog, OAuth or API
credentials. The supplied extension ZIP must have the correct version
and safe member paths; a requested SHA-256 must match actual bytes.
No external LLM endpoint is accepted: only an in-process
`127.0.0.1` fake streaming model exists in policy mode.

Unlike the historical `harness.py`, the runner needs **no real Ghidra
project, pre-existing Lucene index, private preferences, MCP extension,
hardcoded host paths or JDK install path**. It requires:
Ghidra 12.1.4 PUBLIC, a full JDK (25 in Actions), an existing build ZIP,
and X11 DISPLAY. Missing requirements are **BLOCKED**, not SKIPPED/PASS.

Smoke mode checks actual `PluginTool`, `ProgramManager`, installed
GhidrAssist Query, visible Swing window, EDT and synthetic import. Full
policy mode additionally tests narrow Query layout, detached policy
editor, conversation-scoped policy lifecycle, negative invalid budget,
allowed/blocked/duplicate tool call behavior, and async polling using
a deterministic localhost fake model. It tests real Query/Approve
Swing/dispatcher code, not real paid LLMs. Full mode deliberately omits
historic RAG page 256 data; synthetic fixture is not real CPU manual
source. No claims about MC68332 register semantics follow from it.

## Usage

Build the extension for the matching Ghidra first; **do not use a
private original Ghidra project**. From the GhidrAssist repository root:

```sh
python3 tests/gui_harness/runner.py \
  --ghidra /absolute/path/to/ghidra_12.1.4_PUBLIC \
  --java-home /absolute/path/to/jdk-25 \
  --extension-zip /absolute/path/to/ghidra_12.1.4_PUBLIC_*_GhidrAssist.zip \
  --extension-sha256 YOUR_VERIFIED_ZIP_SHA256 \
  --output /absolute/new/empty/dir \
  --mode smoke --capture-x11
```

Use `--mode policy` for the Query/policy test suite; it is a separate
isolated project and fresh fake model. A `--timeout` from 30–900
seconds is accepted. Each invocation is one-shot. The runner refuses
to erase a nonempty output directory or follow an output symlink.
On unexpected GUI exceptions it terminates only its own process group
and frees the temporary project; no scheduled background Codex runs.
Use the *actual* full extension ZIP, not an uncompiled jar.

## Evidence and quality gate

`gui-results.json` is the Java EDT/dispatcher report.
`swing-render.png` and case-specific PNGs are **only**
`Window.printAll()` Swing renderings. When `--capture-x11` is
requested, Python also finds the **named isolated** X11 window with
`xwininfo`, captures it using `import -window` and validates image
dimensions via `identify`. That additional `actual-x11.png`
demonstrates a pixel transfer from X11, **not human visual inspection**.
The receipt explicitly records `human_visual_readback=NOT_PERFORMED`.
No screenshot or metadata check is upgraded to a human visual PASS.
The assertion statuses `PASSED_SWING_SMOKE` /
`PASSED_SWING_AND_POLICY` are deliberately narrower than
`PASSED_FULL_GUI_ACCEPTANCE`. Screenshots are of a standalone
disposable test tool containing only synthetic data.

Strict negative tests check ZIP traversal, wrong version, output
preservation, bad/missing GUI evidence, policy journal contents, and
unapproved fake-model IDs. An isolated Ghidra Actions job downloads
the distribution with an exact SHA, builds the full extension, runs the
smoke and policy modes under Xvfb, and stores disposable-only evidence.
A failed fixture, missing X11 controller, incomplete policy journal
or failed source compile fails CI. The runner does **not** auto-ACK
the private Supervisor and does not interact with Codex.

## Explicit PR #56 separation

The standalone tool intentionally **does not install CodeBrowser or
navigate its Listing**. Therefore neither an Xvfb pass nor a real
Ghidra Query/policy pass can prove the MMIO table's selection/Listing
navigation behavior. PR #56 needs a **separate real CodeBrowser
Listing** acceptance on the exact pinned PR #56 artifact and on a
disposable Ghidra project. The old BLOCKED/INCONCLUSIVE
[Supervisor issue #31](https://github.com/bogkom/codex-supervisor/issues/31)
must not be modified, retried or marked PASS because this harness
exists. No existing source PR head, queued Supervisor test identity,
artifact SHA or nonce is changed by this implementation.

## Operational limitations

Ghidra API changes, missing X11, wrong extension, or new Query
control layout require focused updates to this harness and fail
closed. Runtime CI tests with Xvfb verify technical Swing visibility
and source execution; review of screenshots and actual on-Wyse GUI
acceptance remain separate steps. CI uses a downloaded, SHA-verified
public Ghidra installation and the currently built extension. The
synthetic CPU32 fixture is *not evidence* of real ECU execution,
physical CPU model or external hardware.

## 2026-10-29 — X11 blank-image regression

CI exposed a real limitation that could otherwise be misreported as GUI
visual acceptance: an early Xvfb capture returned a valid **1200×950 PNG
with only two colors** (mostly black body and gray border), even while
Swing/dispatcher assertions passed. That is an unpainted or inaccessible
X11 surface, **not** evidence that a reviewer saw GhidrAssist Query.

The runner now validates at least 16 distinct pixel colors in the
**specific mapped isolated tool window** selected by its X11 hierarchy
and geometry; a blank surface returns `BLOCKED_X11_READBACK`. It
rejects ambiguously equal windows instead of capturing the desktop.
The Java driver yields for Expose/paint after Query becomes visible,
and GitHub Actions starts Openbox on the disposable Xvfb server.
Synthetic safety regressions include a two-color X11 image. The
`X11_CAPTURED_NONBLANK_PIXEL_CHECKED` status means automated pixel
diversity only, and the human visual field **remains NOT_PERFORMED**.
Neither status can be substituted for real CodeBrowser/Listing PR #56
acceptance, nor for real interactive desktop-controller availability.
