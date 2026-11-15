#!/usr/bin/env python3
"""Source-level contract tests for the GA-01 isolated headless launcher.

Fake headless output tests the launcher, NOT Ghidra CPU32 decoding.
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run-ga01-cpu32-headless.py"
SHA = "a" * 40


class HeadlessRunnerContract(unittest.TestCase):
    def invoke(self, stdout, exit_code=0):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            binary = home / "support" / "analyzeHeadless"
            binary.parent.mkdir()
            binary.write_text("#!/bin/sh\nprintf '%s\\n' " +
                              " ".join("'" + line.replace("'", "'\\''") + "'"
                                       for line in stdout.splitlines()) +
                              f"\nexit {exit_code}\n")
            binary.chmod(0o755)
            return subprocess.run(
                [sys.executable, str(RUNNER), "--ghidra-home", str(home),
                 "--source-sha", SHA], capture_output=True, text=True)

    def test_both_markers(self):
        result = self.invoke("GA18_PREPARE_DECODED_SITES_PASS\nGA18_DECODED_SITES_GHIDRA_PASS")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("GA01_CPU32_HEADLESS_PASS", result.stdout)
        self.assertIn("FIXTURE_SHA256=", result.stdout)

    def test_missing_preparer(self):
        self.assertNotEqual(0, self.invoke("GA18_DECODED_SITES_GHIDRA_PASS").returncode)

    def test_missing_verifier(self):
        self.assertNotEqual(0, self.invoke("GA18_PREPARE_DECODED_SITES_PASS").returncode)

    def test_duplicate_marker(self):
        self.assertNotEqual(0, self.invoke("GA18_PREPARE_DECODED_SITES_PASS\n"
                                          "GA18_DECODED_SITES_GHIDRA_PASS\n"
                                          "GA18_DECODED_SITES_GHIDRA_PASS").returncode)

    def test_failure_dominates_pass(self):
        self.assertNotEqual(0, self.invoke("GA18_PREPARE_DECODED_SITES_PASS\n"
                                          "GA18_DECODED_SITES_GHIDRA_PASS\n"
                                          "GA18_DECODED_SITES_FAIL").returncode)

    def test_nonzero_exit_dominates_pass(self):
        self.assertNotEqual(0, self.invoke("GA18_PREPARE_DECODED_SITES_PASS\n"
                                          "GA18_DECODED_SITES_GHIDRA_PASS", 2).returncode)


if __name__ == "__main__":
    unittest.main()
