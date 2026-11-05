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

The actual Ghidra 12.1.4 PUBLIC release uses the **flat**
`support/gradle/gradle-wrapper.properties` layout (not a conventional
`gradle/wrapper/` subdirectory). An early version of this pilot's
self-test used the wrong fixture layout: its shell test passed while all
three real CI jobs failed **before running Gradle**. The fixture and
helper were corrected together, retaining the failed job histories.

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

## 2026-11-05 — GA-02/03 real-headless rollout and Gradle ZIP pin

The initial pilot passed both the full extension and two real synthetic
Ghidra suites on exact SHA `674ad8cd57c446b35ac8ef5cff9bd470c3989785`,
then merged as PR #163. The next bounded rollout reuses the identical,
isolated wrapper policy in **four** additional real headless GA-02/03
workflows: direct-call argument provenance, branch-convergent returns,
strict leaf returns and two-hop direct CALL register flow.

The **Gradle 9.7.1 -bin ZIP SHA-256** is now additionally pinned to
`acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a`
(official source: https://gradle.org/release-checksums/).
If the Ghidra wrapper already contains this checksum, it is preserved;
if it is absent, the CI-only extracted copy receives it. A different,
duplicate, or ambiguous checksum refuses execution. The distribution
version, canonical URL, wrapper JAR and previously pinned Ghidra
PUBLIC ZIP SHA-256 are unchanged. Actual download checksum enforcement
belongs to the Gradle Wrapper and is exercised by the full real
Ghidra/Java25 CI build.

The shell regression covers official pin retention, insertion into
unpinned properties, idempotence, wrong pin, duplicated pin and all
earlier path/symlink/version checks. This is a security/reliability
improvement for **isolated GitHub Actions only**, not a production
firmware, MCU or user-environment change. All new tests must pass on the
exact PR commit before integration.
