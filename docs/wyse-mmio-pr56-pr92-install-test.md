# Wyse acceptance — MMIO Explorer PR #56 + registered PluginPackage PR #92

## Source identity and verification gates

This integration candidate inherits **exact** PR #56 commit
`ed53849141141da7810736c61d8e8a7669aa8767` as its sole base.
The original PR #56 head, base and prior distribution remain unchanged.
The `GhidrAssistPluginPackage` class and the one-line annotation change
are identical to the code reviewed in PR #92 head
`cb70ce89afb55844e50eb69a71d40b8802bf6e0a`.
The isolated real CodeBrowser/Listing regression is taken from PR #93
head `c1608e61a69773ca8380976d2f17453a3a99e329`.

**This is a separate build**, not a claim that any of the three
historical artifacts was re-tested under a new commit. The integration
CI must complete on one immutable source SHA before distributing it.
Use **only** the GitHub Actions artifact from the successful
`wyse-mmio-package-integration.yml` run for this candidate. A successful
build alone is insufficient: the runtime Ghidra `ClassSearcher`,
synthetic MMIO CodeBrowser + GoTo Listing + stale-row blocking, and
tool-template restore in a **second Java process** must all PASS.

The downloadable GitHub Actions artifact contains the **installable
Ghidra ZIP** plus `manifest.json` and `SHA256SUMS.txt`. The manifest
pins source commit, historical input commits, exact Ghidra version,
run ID and the **inner installable ZIP SHA-256**. The enclosing GitHub
Actions archive has its own provider-reported artifact ID and SHA256
which must also be independently checked by the local Supervisor.

## Safe verification and installation on Wyse

1. Read `manifest.json` from the pinned artifact and check its
   `source_commit`, Ghidra 12.1.4 PUBLIC, `ci_run_id` and
   `installable_zip_sha256`. Rehash the downloaded **outer** archive
   and the nested **installable** ZIP; the latter must agree with
   `SHA256SUMS.txt`. Check the extension ZIP's
   `GhidrAssist/extension.properties`, `GhidrAssist/lib/GhidrAssist.jar`
   and embedded plugin/package classes before installing anything.
2. Create an **entirely new, empty, isolated test-only Ghidra home and
   profile**. Do NOT install over or migrate the existing PR #56
   extension; do NOT reuse `~/.ghidra`, production OAuth preferences,
   RAG indexes or the ECU411 project. Use a dedicated profile path
   e.g. a disposable location under the authorized test workspace.
   Copy the installable ZIP's `GhidrAssist/` directory into that
   profile's own `ghidra_12.1.4_PUBLIC/Extensions` folder. Set
   `-Dapplication.settingsdir=...` and `-Duser.home=...` for
   *all* Ghidra processes; verify the running process actually uses
   the isolated location. Never change the original environment's
   profiles/extensions.
3. Open Ghidra 12.1.4 PUBLIC with Java 25 and import a safe **synthetic**
   68000/CPU32 test fixture into a disposable project. A single
   `MOVE.W #$40CA,($00FFFA00).L` at test PC `0x20` is sufficient.
   Check actual `PluginPackage.exists("GhidrAssist")`/registered
   metadata in the new app and absence of
   `Can't find plugin package for GhidrAssist! Creating stub...`.
4. Enable the real `GhidrAssistPlugin` in a real **CodeBrowser** and
   open Hardware Analysis. Choose the MC68332 profile (known profile
   used for interpreting the test address), perform Analyze on **only
   the disposable fixture**, open `MMIO accesses...`, filter
   `SIMCR`, verify expected row PC and actual static value.
   Use `Go To Listing` and assert the CodeBrowser cursor moves to
   the selected synthetic instruction.
5. Keep the MMIO dialog open, switch active Program to a *second*
   disposable test binary and click `Go To Listing`; then double-click
   the stale MMIO row. Both MUST reject navigation and the active
   Listing must remain on the second Program, displaying
   `Active program changed; rerun Analyze.` Do not edit symbols,
   registers, memory blocks, firmware or original Ghidra databases.
6. Save **only the disposable CodeBrowser tool** configuration,
   exit Ghidra completely, and start a **new Java/Ghidra process**
   with the **same isolated test profile**. The GhidrAssist and
   CodeBrowser plugins must persist, including saved
   `<EXTENSIONS>` metadata, without a recurring
   `New extension plugins detected` prompt. If the prompt returns,
   preserve redacted logs and return **BLOCKED/FAIL**, not PASS.
7. Record the exact code commit, downloaded artifact ID/run ID and
   SHA-256 (outer and inner), Ghidra/Java versions, launcher classpath,
   actual installed-extension path within the disposable profile,
   test source PC, actual UI navigation outcomes, XML extension
   persistence and screenshots of *synthetic-only* windows.
   Keep reports in the private authorized test workspace only.

## Hard fail / blocked conditions

- Any SHA, version or source commit mismatch; empty/missing
  `GhidrAssist.jar`; duplicate or ambiguous installed extension;
  no genuine CodeBrowser; wrong/missing test row; any unexpected
  real Ghidra project mutation; missing GUI controller; plugin
  registry stub; repeated extension prompt after full restart.
- Missing GUI evidence is **INCONCLUSIVE**, not evidence of success.
  Source instruction sites are **static firmware references**, not
  runtime CPU execution or hardware configuration.
- **No Codex programming**. Codex may only run the approved,
  artifact-pinned test via the existing Supervisor on Wyse. Do not
  create an additional Codex session or run a new plan merely because
  an artifact exists. Preserve the existing test-only authorization,
  manual approval restrictions, budget limits, and all older plans.
- **No false formal PASS or ACK**: original PR #56 had owner
  **MANUAL GUI PASS** on the real ECU Listing but its prior formal
  Supervisor workflow remains BLOCKED/INCONCLUSIVE without ACK.
  The new candidate gets its *own* separate report only after
  actual observed host test success.

## CI versus host acceptance

Passing GitHub Actions proves the combined plugin source compiles
and the synthetic full CodeBrowser regression works on an isolated
CI runner. It does not prove the migrated Wyse profile is repaired or
that local Codex desktop control is available. No original ECU411
firmware or project, credentials, OAuth or private reports belong in
this public documentation or artifacts.

The **private Supervisor's active plan queue is already full (30/30
at integration preparation)**. The candidate metadata and test plan
can be staged outside `test-plans/queue/`; do not insert an active
auto-discovered plan or invoke Codex before space/authorization and
actual artifact bytes are verified.
