#!/usr/bin/env python3
"""Run GA-01 CPU32 decoding in a fresh, disposable Ghidra headless project.

Requires an installed Ghidra 12.1.4 PUBLIC and the extension built from the
same commit. Never points at an existing project or ECU411.
"""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

EXPECTED = bytes.fromhex("33fc40ca00fffa004e7b08014e7a08017001")
PREPARE = "GA18_PREPARE_DECODED_SITES_PASS"
VERIFY = "GA18_DECODED_SITES_GHIDRA_PASS"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-home", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=600,
                        help="Maximum time allowed for the isolated Ghidra process")
    parser.add_argument("--source-sha", required=True,
                        help="Full 40-character Git commit SHA of the extension and scripts")
    args = parser.parse_args()
    if len(args.source_sha) != 40 or any(c not in "0123456789abcdef" for c in args.source_sha):
        parser.error("--source-sha must be a lowercase full commit SHA")
    if args.timeout_seconds < 1 or args.timeout_seconds > 3600:
        parser.error("--timeout-seconds must be in 1..3600")
    root = Path(__file__).resolve().parents[1]
    headless = args.ghidra_home / "support" / "analyzeHeadless"
    scripts = root / "ghidra_scripts"
    for file in (headless, scripts / "GA18PrepareDecodedEffectSites.java",
                 scripts / "GA18VerifyDecodedEffectSites.java"):
        if not file.is_file():
            parser.error(f"missing required file: {file}")
    if not os.access(headless, os.X_OK):
        parser.error(f"not executable: {headless}")

    with tempfile.TemporaryDirectory(prefix="ga01-cpu32-isolated-") as directory:
        work = Path(directory)
        fixture = work / "ga01-cpu32.bin"
        fixture.write_bytes(EXPECTED)
        digest = hashlib.sha256(EXPECTED).hexdigest()
        command = [
            str(headless), str(work), "GA01_CPU32_ISOLATED",
            "-import", str(fixture),
            "-loader", "BinaryLoader",
            "-loader-baseAddr", "0x100",
            "-processor", "68000:BE:32:CPU32",
            # Headless auto-analysis runs before post-scripts by default. The
            # preparer must see raw bytes, not auto-created instructions.
            "-noanalysis",
            "-scriptPath", str(scripts),
            "-postScript", "GA18PrepareDecodedEffectSites.java",
            "-postScript", "GA18VerifyDecodedEffectSites.java",
            "-deleteProject",
        ]
        print(f"SOURCE_SHA={args.source_sha} FIXTURE_SHA256={digest}", flush=True)
        try:
            result = subprocess.run(command, cwd=work, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    errors="replace", timeout=args.timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            partial = exc.stdout or b""
            if isinstance(partial, bytes):
                partial = partial.decode("utf-8", errors="replace")
            print(partial, end="" if partial.endswith("\n") else "\n")
            print(f"GA01_CPU32_HEADLESS_FAIL timeout={args.timeout_seconds} "
                  f"source={args.source_sha} fixture={digest}", flush=True)
            return 1
        output = result.stdout
        print(output, end="" if output.endswith("
") else "
")
        # Both markers are necessary, and any failure must dominate even when
        # a stale or unrelated log line contains a PASS marker.
        failures = ("GA18_PREPARE_FAIL", "GA18_DECODED_SITES_FAIL",
                    "ERROR", "Exception", "AssertionError")
        passed = (result.returncode == 0 and sum(line.strip() == PREPARE for line in output.splitlines()) == 1
                  and sum(line.strip() == VERIFY for line in output.splitlines()) == 1
                  and not any(token in output for token in failures))
        print(f"GA01_CPU32_HEADLESS_{'PASS' if passed else 'FAIL'} "
              f"exit={result.returncode} source={args.source_sha} fixture={digest}",
              flush=True)
        return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
