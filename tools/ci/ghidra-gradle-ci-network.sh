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
props="$root/support/gradle/gradle-wrapper.properties"
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
# Replace the first timeout stanza in place, or append once if missing.
# Never grow the file with an extra blank line on a second invocation.
awk '
  /^networkTimeout=/ {
    if (!emitted) {
      print "networkTimeout=120000"
      print "retries=2"
      print "retryBackOffMs=1000"
      emitted=1
    }
    next
  }
  /^retries=/ || /^retryBackOffMs=/ { next }
  { print }
  END {
    if (!emitted) {
      print "networkTimeout=120000"
      print "retries=2"
      print "retryBackOffMs=1000"
    }
  }
' "$props" > "$tmp"
mv -f "$tmp" "$props"
echo "Ghidra 12.1.4 isolated Gradle wrapper: timeout=120000ms retries=2 (URL/version unchanged)"
