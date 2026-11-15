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
SHA = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
PREPARE = "GA18_PREPARE_DECODED_SITES_PASS instructions=4 function=0x100 bytes=18"
VERIFY = "GA18_DECODED_SITES_GHIDRA_PASS sites=2 positive=2 negative=4 recovery=2"


class HeadlessRunnerContract(unittest.TestCase):
    def invoke(self, stdout, exit_code=0, delay=0, timeout=600):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            binary = home / "support" / "analyzeHeadless"
            binary.parent.mkdir()
            binary.write_text("#!/bin/sh\nsleep " + str(delay) + "\nprintf '%s\\n' " +
                              " ".join("'" + line.replace("'", "'\\''") + "'"
                                       for line in stdout.splitlines()) +
                              f"\nexit {exit_code}\n")
            binary.chmod(0o755)
            return subprocess.run(
                [sys.executable, str(RUNNER), "--ghidra-home", str(home),
                 "--source-sha", SHA, "--timeout-seconds", str(timeout)],
                capture_output=True, text=True)

    def test_rejects_wrong_source_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            binary = home / "support" / "analyzeHeadless"
            binary.parent.mkdir()
            binary.write_text("#!/bin/sh\\necho should-not-run\\n")
            binary.chmod(0o755)
            result = subprocess.run(
                [sys.executable, str(RUNNER), "--ghidra-home", str(home),
                 "--source-sha", "a" * 40], capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn("should-not-run", result.stdout)
            self.assertIn("source SHA mismatch", result.stderr)

    def test_both_markers(self):
        result = self.invoke(PREPARE + "\n" + VERIFY)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("GA01_CPU32_HEADLESS_PASS", result.stdout)
        self.assertIn("FIXTURE_SHA256=", result.stdout)

    def test_headless_invocation_disables_autoanalysis(self):
        # The real preparer rejects any pre-existing disassembly or function.
        # Inspect argv from the fake executable, not merely its PASS markers.
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            binary = home / "support" / "analyzeHeadless"
            binary.parent.mkdir()
            binary.write_text(
                "#!/bin/sh\n"
                "printf '%s\n' \"$@\"\n"
                "echo "+PREPARE+"\n"
                "echo "+VERIFY+"\n"
            )
            binary.chmod(0o755)
            result = subprocess.run(
                [sys.executable, str(RUNNER), "--ghidra-home", str(home),
                 "--source-sha", SHA], capture_output=True, text=True)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            args = result.stdout.splitlines()
            self.assertIn("-noanalysis", args)
            self.assertIn("-loader", args)
            self.assertIn("BinaryLoader", args)
            self.assertIn("-loader-baseAddr", args)
            self.assertIn("0x100", args)
            self.assertIn("68000:BE:32:CPU32", args)
            self.assertLess(args.index("GA18PrepareDecodedEffectSites.java"),
                            args.index("GA18VerifyDecodedEffectSites.java"))

    def test_timeout_rejects_even_eventual_pass(self):
        result = self.invoke(PREPARE + "\n" + VERIFY, delay=2, timeout=1)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("GA01_CPU32_HEADLESS_FAIL timeout=1", result.stdout)

    def test_invalid_timeout(self):
        self.assertNotEqual(0, self.invoke("", timeout=0).returncode)
        self.assertNotEqual(0, self.invoke("", timeout=3601).returncode)

    def test_bare_markers_do_not_count_as_real_script_evidence(self):
        self.assertNotEqual(0, self.invoke("GA18_PREPARE_DECODED_SITES_PASS\nGA18_DECODED_SITES_GHIDRA_PASS").returncode)

    def test_wrong_evidence_counts_rejected(self):
        self.assertNotEqual(0, self.invoke(PREPARE + "\n" + VERIFY.replace("sites=2", "sites=1")).returncode)

    def test_real_verifier_executes_all_four_negative_controls(self):
        # Static source guard only: this does not substitute for a Ghidra run.
        source = (ROOT / "ghidra_scripts" / "GA18VerifyDecodedEffectSites.java").read_text()
        self.assertNotIn(r"\n        require(", source)
        self.assertIn("removeFunction(only.getEntryPoint())", source)
        self.assertIn("noFunctions.incomplete() && noFunctions.sites().isEmpty()", source)
        self.assertIn('negative=4 recovery=2', source)
        self.assertIn('recovered.sites().size() == 2', source)
        self.assertIn('!completeAgain.incomplete() && completeAgain.omitted() == 0', source)
        self.assertIn('full recovery must restore complete decoded coverage', source)
        self.assertIn('recovery must not hide undefined MOVEQ', source)

    def test_old_three_negative_marker_is_not_accepted(self):
        self.assertNotEqual(0, self.invoke(PREPARE + "\n" + VERIFY.replace("negative=4", "negative=3")).returncode)

    def test_missing_recovery_evidence_rejected(self):
        self.assertNotEqual(0, self.invoke(PREPARE + '\n' + VERIFY.replace(' recovery=2', '')).returncode)
        self.assertNotEqual(0, self.invoke(PREPARE + '\n' + VERIFY.replace('recovery=2', 'recovery=0')).returncode)

    def test_missing_recovery_count_is_rejected(self):
        self.assertNotEqual(0, self.invoke(PREPARE + "\\n" +
            VERIFY.replace(" recovery=2", "")).returncode)

    def test_wrong_positive_and_negative_counts_rejected(self):
        for old, new in (("positive=2", "positive=1"),
                         ("negative=4", "negative=5"),
                         ("recovery=2", "recovery=3")):
            with self.subTest(field=old):
                self.assertNotEqual(0, self.invoke(PREPARE + "\\n" +
                    VERIFY.replace(old, new)).returncode)

    def test_success_requires_zero_exit_even_with_valid_counts(self):
        result = self.invoke(PREPARE + "\\n" + VERIFY, exit_code=1)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("GA01_CPU32_HEADLESS_FAIL", result.stdout)

    def test_missing_preparer(self):
        self.assertNotEqual(0, self.invoke(VERIFY).returncode)

    def test_missing_verifier(self):
        self.assertNotEqual(0, self.invoke(PREPARE).returncode)

    def test_duplicate_marker(self):
        self.assertNotEqual(0, self.invoke(PREPARE + "\n" + VERIFY + "\n" + VERIFY).returncode)

    def test_marker_substrings_are_not_evidence(self):
        # Ghidra logs may echo script names, assertions, or quoted text.
        self.assertNotEqual(0, self.invoke(
            "prefix_GA18_PREPARE_DECODED_SITES_PASS\\n"
            "GA18_DECODED_SITES_GHIDRA_PASS"))
        self.assertNotEqual(0, self.invoke(
            "GA18_PREPARE_DECODED_SITES_PASS\\n"
            "GA18_DECODED_SITES_GHIDRA_PASS_suffix"))

    def test_embedded_duplicate_marker_is_not_evidence(self):
        self.assertNotEqual(0, self.invoke(
            "GA18_PREPARE_DECODED_SITES_PASS\\n"
            "GA18_DECODED_SITES_GHIDRA_PASS GA18_DECODED_SITES_GHIDRA_PASS"))

    def test_failure_dominates_pass(self):
        self.assertNotEqual(0, self.invoke(PREPARE + "\n" + VERIFY + "\nGA18_DECODED_SITES_FAIL").returncode)

    def test_nonzero_exit_dominates_pass(self):
        self.assertNotEqual(0, self.invoke(PREPARE + "\n" + VERIFY, 2).returncode)


if __name__ == "__main__":
    unittest.main()
