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

The test fails if Ghidra decodes the bytes or operand direction differently, if p-code STORE is absent, if the function inventory is incomplete, or if the production decoder misclassifies either negative control. A test failure is evidence to investigate, **not** permission to weaken the assertions.

## Evidence required before integration

Record both preparer and verifier logs from the same disposable project, source HEAD SHA, installed extension build SHA, Ghidra version and language, synthetic fixture SHA-256, Script Manager/headless log containing `GA18_DECODED_SITES_GHIDRA_PASS`, and both positive and negative assertions. Separately verify Java 21 regression and Java 25 extension build GitHub Actions **on that same HEAD**. Mark the PR accepted only after review and those controls succeed.

This is a static decoded-source test: CFG reachability is not execution, decoded MOVEC is not an active VBR/ISR, and STORE is not a physical hardware write. The verifier does not perform Review/Apply or change the source firmware.

## Repeatable isolated headless invocation

With a Ghidra 12.1.4 PUBLIC installation and the extension built/installed from the same full source commit, run:

```bash
python3 -m unittest discover -s tests -p test_ga01_cpu32_headless_runner.py
python3 scripts/run-ga01-cpu32-headless.py \
  --ghidra-home /path/to/ghidra_12.1.4_PUBLIC \
  --source-sha FULL_40_CHARACTER_HEAD_SHA \
  --timeout-seconds 600
```

The first command tests only the launcher contract using a fake headless executable; it **does not** establish Ghidra decoding. The second creates a temporary 18-byte raw fixture and disposable project, disables automatic headless analysis with `-noanalysis` so the preparer sees the untouched raw binary, invokes the preparer and verifier in order, and deletes the project. The source-level launcher regression checks the actual command arguments and script order. The runner requires both PASS markers as separate complete output lines (not substrings in diagnostic text), a zero exit code, and no reported exception/error; its final `GA01_CPU32_HEADLESS_PASS` is valid only with the genuine installed extension and matching source SHA. Save the full stdout, GitHub Actions URLs, installed extension SHA, fixture SHA-256 and exact Ghidra version for formal review. Do not run against an existing project or ECU411. If a headless import/loader flag differs, fix the launcher and rerun; never replace the actual decoder assertions with a mocked PASS.

The headless subprocess has a bounded runtime (default 600 seconds; accepted range 1–3600). A timeout is a hard FAIL even if the subprocess emitted partial PASS text; the disposable project is cleaned up. Mock-launcher regression covers timeout and invalid limits but is **not** a genuine Ghidra test. The supplied `--source-sha` is an operator assertion, not independently verified by the launcher; retain the matching build/installation provenance separately.
