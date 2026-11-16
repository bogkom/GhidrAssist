# GA-01/02/03/11 — isolated CPU32 Listing decoder acceptance fixture

This fixture is a **real Ghidra 12.1.4 PUBLIC** acceptance test, not a pure Java mock. The script `ghidra_scripts/GA18VerifyDecodedEffectSites.java` reads Ghidra-decoded instructions and invokes the production `HardwareGhidraEffectSiteDecoder`. The script is an **unexecuted candidate** until its output and exact source SHA are recorded.

## Prepare (disposable project only)

Generate the immutable synthetic input in an empty disposable directory using
`python3 scripts/create-ga01-cpu32-decoder-fixture.py /tmp/ga01-cpu32-decoder.bin`.
The generator uses exclusive creation and refuses to overwrite any existing file.
Record the printed SHA-256 and independently verify it using
`sha256sum /tmp/ga01-cpu32-decoder.bin`. The generator only checks bytes and
instruction offsets; **it does not run Ghidra or prove CPU32 decoding**.

Create a new isolated project with CPU32 language `68000:BE:32:CPU32`. Import the generated 18-byte **raw binary** at address `0x00000100` (not the production ECU411 firmware), using this exact hex payload:

```text
33 fc 40 ca 00 ff fa 00 4e 7b 08 01 4e 7a 08 01 70 01
```

For repeatable setup, import the raw bytes into a **new, not-yet-disassembled** disposable program and run `ghidra_scripts/GA18PrepareDecodedEffectSites.java` first. It refuses pre-existing functions/instructions, verifies all 18 bytes and CPU32 language, disassembles each of the four exact instruction boundaries, checks lengths, and creates one explicitly bounded function at `0x100`. Expect `GA18_PREPARE_DECODED_SITES_PASS`. Then run `GA18VerifyDecodedEffectSites.java` against the **same program**. Do not run the preparer twice. The preparer changes only the disposable test program, never the source firmware. Build/install the extension from the **same exact PR HEAD SHA** with Java 25 / Ghidra 12.1.4 PUBLIC so the script can import the production decoder classes. Run the verifier in the Ghidra Script Manager or isolated headless `-postScript` context, with this synthetic program open. Do not run it on ECU411 or a production project.

Expected instruction PCs: `0x100` MOVE.W immediate-to-memory (p-code STORE), `0x108` MOVEC D0,VBR, `0x10c` MOVEC VBR,D0, `0x110` MOVEQ #1,D0. The test **independently checks** Ghidra's p-code and both decoded MOVEC operand directions before checking the production decoder's result. It must return exactly two source sites: STORE at `0x100`, MOVEC-to-VBR at `0x108`. It must reject `0x10c` and `0x110` as effects.

Before checking decoder output, the verifier also reads all 18 bytes back from Ghidra memory, requires an exact match to the immutable fixture, and requires exactly one function with entry `0x100` whose body contains all four instruction PCs. A wrong load base, modified bytes, missing function or extra function is a hard failure, not an inconclusive PASS. These guards prevent accidental acceptance of a different imported program.

After verifying the positive fixture, the verifier clears the final MOVEQ instruction **only in the disposable program** and reruns the production decoder. It requires `incomplete=true` for the now-undefined two bytes while retaining independently observed STORE evidence. This tests the negative-evidence boundary: a function containing undefined/data bytes cannot be reported as a complete source-site inventory. The verifier then also clears MOVEC-to-VBR at `0x108` in the same disposable program and requires incomplete evidence, no stale `0x108` site, and retention of STORE at `0x100`. Finally it clears the remaining STORE and requires an empty source-site inventory with `incomplete=true`, rejecting stale cached evidence. The final PASS marker is emitted only after the positive phase, all four negative controls and both recovery checks succeed.

The test fails if Ghidra decodes the bytes or operand direction differently, if p-code STORE is absent, if the function inventory is incomplete, or if the production decoder misclassifies either negative control. A test failure is evidence to investigate, **not** permission to weaken the assertions.

## Evidence required before integration

Record both preparer and verifier logs from the same disposable project, source HEAD SHA, installed extension build SHA, Ghidra version and language, synthetic fixture SHA-256, Script Manager/headless log containing `GA18_DECODED_SITES_GHIDRA_PASS`, and the positive assertions and all four negative controls. Separately verify Java 21 regression and Java 25 extension build GitHub Actions **on that same HEAD**. Mark the PR accepted only after review and those controls succeed.

This is a static decoded-source test: CFG reachability is not execution, decoded MOVEC is not an active VBR/ISR, and STORE is not a physical hardware write. The verifier does not perform Review/Apply or change the source firmware.

## Repeatable isolated headless invocation

With a Ghidra 12.1.4 PUBLIC installation and the extension built/installed from the same full source commit, run:

```bash
python3 -m unittest discover -s tests -p test_ga01_cpu32_headless_runner.py
python3 scripts/run-ga01-cpu32-headless.py \
  --ghidra-home /path/to/ghidra_12.1.4_PUBLIC \
  --source-sha FULL_40_CHARACTER_HEAD_SHA \
  --timeout-seconds 600 \
  --evidence-log /path/to/new/ga01-cpu32-evidence.log
```

The first command tests only the launcher contract using a fake headless executable; it **does not** establish Ghidra decoding. The second creates a temporary 18-byte raw fixture and disposable project, disables automatic headless analysis with `-noanalysis` so the preparer sees the untouched raw binary, invokes the preparer and verifier in order, and deletes the project. The source-level launcher regression checks the actual command arguments and script order. The runner requires the **exact structured evidence lines** `GA18_PREPARE_DECODED_SITES_PASS instructions=4 function=0x100 bytes=18` and `GA18_DECODED_SITES_GHIDRA_PASS sites=2 positive=2 negative=4 recovery=2`, each exactly once (bare PASS tokens and mismatched counts are rejected), a zero exit code, and no reported exception/error; its final `GA01_CPU32_HEADLESS_PASS` is valid only with the genuine installed extension and matching source SHA. Save the full stdout, GitHub Actions URLs, installed extension SHA, fixture SHA-256 and exact Ghidra version for formal review. Do not run against an existing project or ECU411. If a headless import/loader flag differs, fix the launcher and rerun; never replace the actual decoder assertions with a mocked PASS.

The headless subprocess has a bounded runtime (default 600 seconds; accepted range 1–3600). A timeout is a hard FAIL even if the subprocess emitted partial PASS text; the disposable project is cleaned up. Mock-launcher regression covers timeout and invalid limits but is **not** a genuine Ghidra test. The launcher now independently compares `--source-sha` against the local Git `HEAD` and rejects any modified tracked file before launching Ghidra. It does **not** establish that the installed extension was built from that SHA: record and verify the extension artifact provenance separately. A checkout without Git metadata is rejected. The source-level regression includes a negative case proving that an incorrect SHA prevents even a fake headless process from starting.

## Conservative decoded-source coverage

An instruction with no p-code operations is **UNKNOWN**, not proof that no STORE occurred. An instruction whose address range crosses its owning function body likewise makes the scan incomplete. Coverage uses distinct decoded addresses rather than summing instruction lengths, so overlapping decoded instructions cannot mask undefined gaps; overlap makes the inventory incomplete. Independently decoded source sites may remain visible, but incomplete inventories must not be promoted to complete negative evidence or a verified RESET correlation. These are read-only static safeguards; the actual CPU32 headless positive/negative fixture and installed-extension provenance remain required for formal acceptance.

The fourth negative control deletes the sole synthetic function after clearing effect instructions. An empty recognized-function inventory is **UNKNOWN/incomplete**, not proof of no STORE/MOVEC. The `negative=4` marker is required for this acceptance revision. This remains static Listing evidence only.


### Recovery acceptance (PR #336 candidate)

After clearing both positive source instructions, the verifier re-disassembles STORE at 0x100 and MOVEC-to-VBR at 0x108 in the same disposable program. It requires both sites to reappear without spurious MOVEC-from-VBR or MOVEQ sites, while the undefined MOVEQ still forces `incomplete=true`. This is the **intermediate** recovery checkpoint, not a standalone PASS marker. The only final accepted marker, emitted after the complete round-trip below, is `GA18_DECODED_SITES_GHIDRA_PASS sites=2 positive=2 negative=4 recovery=2`. Mock launcher checks are source-level only; genuine Ghidra 12.1.4 PUBLIC execution and exact-head Java 21/25 CI remain required.

### Full Listing round-trip (candidate)

After the partial recovery of STORE and MOVEC, the verifier now re-disassembles the final MOVEQ and requires the decoder to return to **complete** coverage (`incomplete=false`, `omitted=0`) with exactly the original two effect sites. It then deletes the only function and checks the fourth negative gate. The evidence marker is now `GA18_DECODED_SITES_GHIDRA_PASS sites=2 positive=2 negative=4 recovery=2`. This is an unexecuted acceptance candidate until verified on real isolated Ghidra 12.1.4 PUBLIC; mocked runner assertions are not a substitute.

### Evidence-contract regression repair (2026-11-15)

The mocked launcher tests now pass actual newline-separated full preparer/verifier evidence to the subprocess, including count mutations, nonzero exit, near-matching markers and a failure after valid evidence. Previously several negative cases passed merely because their fake output contained a literal `\\n` rather than two log lines. This change strengthens **source-level** negative tests only; it does not prove real Ghidra execution, extension provenance or formal GA-01/11 acceptance. Re-run exact-HEAD Java 21 and Java 25 checks before merge.

### Pinned Ghidra release preflight

Before starting the disposable headless process, the runner reads `Ghidra/application.properties` and requires `application.version=12.1.4` and `application.release.name=PUBLIC`. Missing metadata, an older version, or another release name fails before import. Mock-launcher regression covers these cases, but does not attest installed extension provenance or replace real Ghidra execution.
The runner also rejects an out-of-order verifier PASS preceding the preparer PASS; this is a mock-runner contract check, not proof of a real Ghidra execution.

### Contradictory evidence lines

The runner fails closed if stdout contains any additional line beginning with either structured preparer/verifier marker, even if one valid marker of each kind also appears. The mock launcher regression checks contradictory preparer instruction counts and verifier recovery/negative counts. This is a source-level contract test only; genuine isolated Ghidra execution and installed-extension provenance remain required.

### Persisted evidence (candidate)

The optional `--evidence-log` writes the complete merged headless output and final PASS/FAIL verdict to an **exclusively created** file outside the disposable project. Existing files are never overwritten; preserve the original log and independently record its SHA-256 alongside the source/extension artifact hashes. This improves reviewability but does not attest extension provenance or substitute for a genuine Ghidra execution. The mock regression verifies preservation and overwrite refusal.
