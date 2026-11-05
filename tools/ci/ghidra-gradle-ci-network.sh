#!/usr/bin/env bash
# GA-17/18: modify ONLY the extracted, SHA-verified CI copy of Ghidra's
# Gradle Wrapper network settings. Never modify a developer installation.
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != "true" || -z "${RUNNER_TEMP:-}" || $# -ne 1 ]]; then
  echo "Refusing Gradle wrapper modification outside isolated GitHub Actions" >&2
  exit 2
fi
root="${1%/}"
case "$root" in
  "${RUNNER_TEMP%/}"/ghidra/ghidra_12.1.4_PUBLIC*) ;;
  *) echo "Ghidra root is not a pinned isolated CI extraction" >&2; exit 2 ;;
esac
props="$root/support/gradle/gradle/wrapper/gradle-wrapper.properties"
if [[ ! -d "$root" || -L "$root" || ! -f "$props" || -L "$props" ]]; then
  echo "Missing or redirected isolated Ghidra Gradle wrapper properties" >&2
  exit 2
fi

# The wrapper JAR, distribution version, URL and any SHA pin must be retained.
# Reject unexpectedly changed Ghidra distributions instead of substituting
# a different Gradle release or silently accepting untrusted credentials.
if [[ "$(grep -c '^distributionUrl=' "$props" || true)" != "1" ]]; then
  echo "Ambiguous or missing Gradle distribution URL" >&2
  exit 2
fi
url="$(grep '^distributionUrl=' "$props")"
case "$url" in
  'distributionUrl=https\://services.gradle.org/distributions/gradle-9.7.1-bin.zip'|'distributionUrl=https://services.gradle.org/distributions/gradle-9.7.1-bin.zip') ;;
  *) echo "Unexpected Ghidra 12.1.4 Gradle distribution" >&2; exit 2 ;;
esac

tmp="$props.ga18-ci.$$"
trap 'rm -f "$tmp"' EXIT
sed -e '/^networkTimeout=/d' -e '/^retries=/d' -e '/^retryBackOffMs=/d' "$props" > "$tmp"
printf '\nnetworkTimeout=120000\nretries=2\nretryBackOffMs=1000\n' >> "$tmp"
mv -f "$tmp" "$props"
echo "Ghidra 12.1.4 isolated Gradle wrapper: timeout=120000ms retries=2 (URL/version unchanged)"
