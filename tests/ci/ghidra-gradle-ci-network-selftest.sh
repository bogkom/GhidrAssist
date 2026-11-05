#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
helper="$repo_root/tools/ci/ghidra-gradle-ci-network.sh"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT
export GITHUB_ACTIONS=true RUNNER_TEMP="$scratch"
root="$scratch/ghidra/ghidra_12.1.4_PUBLIC_20260921"
props="$root/support/gradle/gradle-wrapper.properties"
mkdir -p "$(dirname "$props")"
cat > "$props" <<'EOF'
distributionBase=GRADLE_USER_HOME
distributionUrl=https\://services.gradle.org/distributions/gradle-9.7.1-bin.zip
distributionSha256Sum=acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a
networkTimeout=10000
retries=0
retryBackOffMs=500
validateDistributionUrl=true
EOF
bash "$helper" "$root"
grep -Fxq 'networkTimeout=120000' "$props"
grep -Fxq 'retries=2' "$props"
grep -Fxq 'retryBackOffMs=1000' "$props"
grep -Fxq 'distributionUrl=https\://services.gradle.org/distributions/gradle-9.7.1-bin.zip' "$props"
grep -Fxq 'distributionSha256Sum=acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a' "$props"
grep -Fxq 'validateDistributionUrl=true' "$props"
[[ "$(grep -c '^networkTimeout=' "$props")" == 1 ]]
[[ "$(grep -c '^retries=' "$props")" == 1 ]]
[[ "$(grep -c '^retryBackOffMs=' "$props")" == 1 ]]

# Repeated isolated CI preparations are byte-for-byte idempotent.
sha_before="$(sha256sum "$props" | cut -d' ' -f1)"
bash "$helper" "$root"
sha_after="$(sha256sum "$props" | cut -d' ' -f1)"
[[ "$sha_before" == "$sha_after" ]]

# Missing checksum in the upstream 12.1.4 wrapper must be supplied by
# the isolated bootstrap and verified by Gradle on actual ZIP download.
sed -i '/^distributionSha256Sum=/d' "$props"
bash "$helper" "$root"
grep -Fxq 'distributionSha256Sum=acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a' "$props"
[[ "$(grep -c '^distributionSha256Sum=' "$props")" == 1 ]]
sha_before="$(sha256sum "$props" | cut -d' ' -f1)"
bash "$helper" "$root"
[[ "$(sha256sum "$props" | cut -d' ' -f1)" == "$sha_before" ]]

# An existing different checksum or duplicate checksum is not overwritten.
sed -i 's/acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/' "$props"
refused_sha="$(sha256sum "$props" | cut -d' ' -f1)"
if bash "$helper" "$root"; then
  echo "Unexpected Gradle digest must fail closed" >&2
  exit 1
fi
[[ "$(sha256sum "$props" | cut -d' ' -f1)" == "$refused_sha" ]]
sed -i 's/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a/' "$props"
printf 'distributionSha256Sum=acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a\n' >> "$props"
refused_sha="$(sha256sum "$props" | cut -d' ' -f1)"
if bash "$helper" "$root"; then
  echo "Duplicate Gradle checksum must fail closed" >&2
  exit 1
fi
[[ "$(sha256sum "$props" | cut -d' ' -f1)" == "$refused_sha" ]]
sed -i '$d' "$props"

# A future Ghidra release or unexpected URL must require a new review.
sed -i 's/gradle-9.7.1-bin.zip/gradle-9.8.0-bin.zip/' "$props"
refused_sha="$(sha256sum "$props" | cut -d' ' -f1)"
if bash "$helper" "$root";then
  echo "Unexpected distribution must not be rewritten" >&2
  exit 1
fi
[[ "$(sha256sum "$props" | cut -d' ' -f1)" == "$refused_sha" ]]
sed -i 's/gradle-9.8.0-bin.zip/gradle-9.7.1-bin.zip/' "$props"

# The final wrapper properties component must not be a symlink.
external="$scratch/external.properties"
cp "$props" "$external"
rm "$props"
ln -s "$external" "$props"
refused_sha="$(sha256sum "$external" | cut -d' ' -f1)"
if bash "$helper" "$root";then
  echo "Symlink wrapper target must fail closed" >&2
  exit 1
fi
[[ "$(sha256sum "$external" | cut -d' ' -f1)" == "$refused_sha" ]]
rm "$props"
mv "$external" "$props"

# This is CI-only; the helper must refuse developer installations.
if env GITHUB_ACTIONS=false bash "$helper" "$root";then
  echo "Non-CI installation must not be modified" >&2
  exit 1
fi
if bash "$helper" "$scratch/some-other-installation";then
  echo "Non-isolated path must not be modified" >&2
  exit 1
fi
echo "GA-17/18 isolated Gradle wrapper network bootstrap PASS"
