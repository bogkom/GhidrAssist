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

Disassemble from `0x100` through `0x111`, and create one function with entry `0x100` whose body includes all four instructions. Ensure there are **no additional recognized functions**. Build/install the extension from the **same exact PR HEAD SHA** with Java 25 / Ghidra 12.1.4 PUBLIC so the script can import the production decoder classes. Run the verifier in the Ghidra Script Manager or isolated headless `-postScript` context, with this synthetic program open. Do not run it on ECU411 or a production project.

Expected instruction PCs: `0x100` MOVE.W immediate-to-memory (p-code STORE), `0x108` MOVEC D0,VBR, `0x10c` MOVEC VBR,D0, `0x110` MOVEQ #1,D0. The test **independently checks** Ghidra's p-code and both decoded MOVEC operand directions before checking the production decoder's result. It must return exactly two source sites: STORE at `0x100`, MOVEC-to-VBR at `0x108`. It must reject `0x10c` and `0x110` as effects.

The test fails if Ghidra decodes the bytes or operand direction differently, if p-code STORE is absent, if the function inventory is incomplete, or if the production decoder misclassifies either negative control. A test failure is evidence to investigate, **not** permission to weaken the assertions.

## Evidence required before integration

Record source HEAD SHA, installed extension build SHA, Ghidra version and language, synthetic fixture SHA-256, Script Manager/headless log containing `GA18_DECODED_SITES_GHIDRA_PASS`, and both positive and negative assertions. Separately verify Java 21 regression and Java 25 extension build GitHub Actions **on that same HEAD**. Mark the PR accepted only after review and those controls succeed.

This is a static decoded-source test: CFG reachability is not execution, decoded MOVEC is not an active VBR/ISR, and STORE is not a physical hardware write. The verifier does not perform Review/Apply or change the source firmware.
