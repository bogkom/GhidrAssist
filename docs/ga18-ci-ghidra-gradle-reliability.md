# GA-17/18 — isolated Ghidra 12.1.4 Gradle wrapper download reliability

On 2026-11-05, several independent **real synthetic Ghidra** GitHub
Actions workflows failed during the Gradle 9.7.1 distribution download,
before compiling or running any product code. Failure evidence included
the Gradle Wrapper's 10,000 ms network timeout and HTTP 504 from the
redirected Gradle distribution host (for example workflow run
`41998282569`, an early attempt in PR #159). A successful rerun on
the **same product SHA** distinguishes this from a GhidrAssist regression,
but repeated manual reruns waste CI resources.

This *limited pilot* adds a shared, deterministic CI-only preparation
script and invokes it from the full extension build, GA-18 package A
and seven-gate synthetic hardware workflows. The Ghidra 12.1.4 PUBLIC
release ZIP is first downloaded and verified against the existing
pinned SHA-256. The script then edits **only the extracted throwaway
Gradle Wrapper properties file**, guarded by `GITHUB_ACTIONS=true`,
the expected `RUNNER_TEMP/ghidra/ghidra_12.1.4_PUBLIC*` prefix, a
regular nonsymlink file and an exact version-9.7.1
`services.gradle.org` distribution URL. No developer Ghidra
installation, repository's Gradle wrapper or original ZIP is altered.

The isolated CI wrapper network policy is **120,000 ms timeout,
2 retries and 1,000 ms exponential initial backoff**. Existing
distribution URL, version, checksums, wrapper JAR and Ghidra build
inputs are retained. This does not bypass SHA verification, silently
upgrade Gradle, disable TLS, or claim that every external-network
failure can be resolved.

`tests/ci/ghidra-gradle-ci-network-selftest.sh` asserts expected
settings, checksum/URL preservation, byte-for-byte idempotence and
refusal on an unexpected version, symlink target, non-CI context or
non-isolated path. Full Ghidra 12.1.4 PUBLIC/Java25 build plus the
selected genuine synthetic Ghidra suites verify the pilot on the
exact PR SHA. Expanding the policy to other workflows should follow
successful evidence and a scoped review, not a blind repository-wide
change. No Wyse/Precision/legacy Supervisor or original ECU411 data.
