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
    def invoke(self, stdout, exit_code=0, delay=0, timeout=600, evidence_log=None):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            binary = home / "support" / "analyzeHeadless"
            binary.parent.mkdir()
            props = home / "Ghidra" / "application.properties"
            props.parent.mkdir(parents=True)
            props.write_text("application.version=12.1.4\napplication.release.name=PUBLIC\n")
            binary.write_text("#!/bin/sh\nsleep " + str(delay) + "\nprintf '%s\\n' " +
                              " ".join("'" + line.replace("'", "'\\''") + "'"
                                       for line in stdout.splitlines()) +
                              f"\nexit {exit_code}\n")
            binary.chmod(0o755)
            command = [sys.executable, str(RUNNER), "--ghidra-home", str(home),
                       "--source-sha", SHA, "--timeout-seconds", str(timeout)]
            if evidence_log is not None:
                command.extend(["--evidence-log", str(evidence_log)])
            return subprocess.run(command, capture_output=True, text=True)

    def test_genuine_release_lookup_is_authenticated(self):
        # This checks the CI contract only; it does not contact GitHub or run Ghidra.
        workflow = (ROOT / ".github/workflows/hardware-vector-reset-correlation.yml").read_text()
        self.assertIn('GH_TOKEN="${{ github.token }}" python3 - <<\'PY\'', workflow)
        self.assertIn("'Authorization':'Bearer ' + token", workflow)
        self.assertIn("if not token:", workflow)
        self.assertIn("Expected one official Ghidra 12.1.4 PUBLIC asset", workflow)
        self.assertNotIn("print(token)", workflow)

    def test_rejects_wrong_source_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            binary = home / "support" / "analyzeHeadless"
            binary.parent.mkdir()
            props = home / "Ghidra" / "application.properties"
            props.parent.mkdir(parents=True)
            props.write_text("application.version=12.1.4\napplication.release.name=PUBLIC\n")
            binary.write_text("#!/bin/sh\\necho should-not-run\\n")
            binary.chmod(0o755)
            result = subprocess.run(
                [sys.executable, str(RUNNER), "--ghidra-home", str(home),
                 "--source-sha", "a" * 40], capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn("should-not-run", result.stdout)
            self.assertIn("source SHA mismatch", result.stderr)

    def test_wrong_ghidra_release_rejected_before_launch(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            binary = home / "support" / "analyzeHeadless"
            binary.parent.mkdir()
            binary.write_text("#!/bin/sh\necho should-not-run\n")
            binary.chmod(0o755)
            props = home / "Ghidra" / "application.properties"
            props.parent.mkdir(parents=True)
            for metadata in (
                "application.version=12.1.3\napplication.release.name=PUBLIC\n",
                "application.version=12.1.4\napplication.release.name=PRIVATE\n",
                "application.version=12.1.4\n",
            ):
                with self.subTest(metadata=metadata):
                    props.write_text(metadata)
                    result = subprocess.run(
                        [sys.executable, str(RUNNER), "--ghidra-home", str(home),
                         "--source-sha", SHA], capture_output=True, text=True)
                    self.assertNotEqual(0, result.returncode)
                    self.assertNotIn("should-not-run", result.stdout)
                    self.assertIn("requires Ghidra 12.1.4 PUBLIC", result.stderr)
            props.unlink()
            result = subprocess.run(
                [sys.executable, str(RUNNER), "--ghidra-home", str(home),
                 "--source-sha", SHA], capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("missing Ghidra release metadata", result.stderr)

    def test_exclusive_evidence_log_contains_verdict_and_rejects_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "evidence.log"
            # invoke() owns a separate disposable fake Ghidra installation.
            # The log destination must survive that cleanup.
            result = self.invoke(PREPARE + "\n" + VERIFY, evidence_log=log)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            saved = log.read_text()
            self.assertIn(PREPARE, saved)
            self.assertIn(VERIFY, saved)
            self.assertIn("GA01_CPU32_HEADLESS_PASS", saved)
            previous = saved
            second = self.invoke(PREPARE + "\n" + VERIFY, evidence_log=log)
            self.assertNotEqual(0, second.returncode)
            self.assertEqual(previous, log.read_text())

    def test_both_markers(self):
        result = self.invoke(PREPARE + "\n" + VERIFY)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("GA01_CPU32_HEADLESS_PASS", result.stdout)
        self.assertIn("FIXTURE_SHA256=", result.stdout)

    def test_verifier_must_follow_preparer(self):
        result = self.invoke(VERIFY + "\n" + PREPARE)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("GA01_CPU32_HEADLESS_FAIL", result.stdout)

    def test_ordering_guard_is_executed_not_escaped(self):
        source = RUNNER.read_text()
        self.assertNotIn(r"\n        lines = [line.strip()", source)
        self.assertIn("and prepare_lines[0] < verify_lines[0]", source)

    def test_real_ghidra_log_envelopes_and_conflicts(self):
        prepare = "INFO  GA18PrepareDecodedEffectSites.java> " + PREPARE + " (GhidraScript)"
        verify = "INFO  GA18VerifyDecodedEffectSites.java> " + VERIFY + " (GhidraScript)"
        accepted = self.invoke(prepare + "\n" + verify)
        self.assertEqual(0, accepted.returncode, accepted.stdout + accepted.stderr)
        for output in (verify + "\n" + prepare,
                       prepare + "\n" + verify + "\n" + VERIFY,
                       prepare + "\n" + "INFO  Other.java> " + VERIFY + " (GhidraScript)",
                       prepare + "\n" + verify.replace("recovery=2", "recovery=1")):
            with self.subTest(output=output):
                self.assertNotEqual(0, self.invoke(output).returncode)

    def test_duplicate_preparer_is_rejected(self):
        result = self.invoke(PREPARE + "\n" + PREPARE + "\n" + VERIFY)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("GA01_CPU32_HEADLESS_FAIL", result.stdout)

    def test_headless_invocation_disables_autoanalysis(self):
        # The real preparer rejects any pre-existing disassembly or function.
        # Inspect argv from the fake executable, not merely its PASS markers.
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            binary = home / "support" / "analyzeHeadless"
            binary.parent.mkdir()
            props = home / "Ghidra" / "application.properties"
            props.parent.mkdir(parents=True)
            props.write_text("application.version=12.1.4\napplication.release.name=PUBLIC\n")
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

    def test_launch_error_persists_failure_verdict(self):
        # Executable exists but its interpreter does not: subprocess.run raises OSError.
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / "ghidra"
            binary = home / "support" / "analyzeHeadless"
            binary.parent.mkdir(parents=True)
            props = home / "Ghidra" / "application.properties"
            props.parent.mkdir(parents=True)
            props.write_text("application.version=12.1.4\napplication.release.name=PUBLIC\n")
            binary.write_text("#!/no/such/ga01-interpreter\n")
            binary.chmod(0o755)
            log = Path(directory) / "launch-evidence.log"
            result = subprocess.run(
                [sys.executable, str(RUNNER), "--ghidra-home", str(home),
                 "--source-sha", SHA, "--evidence-log", str(log)],
                capture_output=True, text=True)
            self.assertNotEqual(0, result.returncode)
            saved = log.read_text()
            self.assertIn("SOURCE_SHA=" + SHA, saved)
            self.assertIn("GA01_CPU32_HEADLESS_FAIL launch_error=", saved)
            self.assertNotIn("GA01_CPU32_HEADLESS_PASS", saved)

    def test_nonzero_exit_persists_failure_and_raw_output(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "nonzero-evidence.log"
            result = self.invoke(PREPARE + "\n" + VERIFY, exit_code=7,
                                 evidence_log=log)
            self.assertNotEqual(0, result.returncode)
            saved = log.read_text()
            self.assertIn(PREPARE, saved)
            self.assertIn(VERIFY, saved)
            self.assertIn("GA01_CPU32_HEADLESS_FAIL exit=7", saved)
            self.assertNotIn("GA01_CPU32_HEADLESS_PASS", saved)

    def test_timeout_persists_partial_output_and_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "timeout-evidence.log"
            result = self.invoke(PREPARE + "\n" + VERIFY, delay=2, timeout=1,
                                 evidence_log=log)
            self.assertNotEqual(0, result.returncode)
            saved = log.read_text()
            self.assertIn("GA01_CPU32_HEADLESS_FAIL timeout=1", saved)
            self.assertNotIn("GA01_CPU32_HEADLESS_PASS", saved)

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

    def test_genuine_failure_keeps_pcode_output_space_witness(self):
        # Source guard only; the genuine Ghidra workflow must provide the witness.
        source = (ROOT / "ghidra_scripts" / "GA18VerifyDecodedEffectSites.java").read_text()
        self.assertIn("GA18_CPU32_STORE_DIAGNOSTIC", source)
        self.assertIn("op.getOutput()", source)
        self.assertIn("outputSpace=", source)
        self.assertIn("outputOffset=0x", source)
        self.assertIn("outputSize=", source)
        self.assertIn("op.getOutput().getOffset() == 0x00fffa00L", source)
        self.assertIn("op.getOutput().getSize() == 2", source)
        self.assertIn("inputs.length == 1 && inputs[0] != null", source)
        self.assertIn("inputs[0].getSize() == op.getOutput().getSize()", source)
        self.assertIn("op.getOutput().getAddress().getAddressSpace().isMemorySpace()", source)
        self.assertIn('require(hasStore(store), "positive p-code memory write not decoded")', source)

    def test_direct_memory_copy_rejects_malformed_pcode(self):
        # Source contract only; genuine Ghidra remains the acceptance gate.
        decoder = (ROOT / "src/main/java/ghidrassist/hardware" /
                   "HardwareGhidraEffectSiteDecoder.java").read_text()
        self.assertIn("output.getAddress().getAddressSpace().isMemorySpace()", decoder)
        self.assertIn("inputs.length!=1", decoder)
        self.assertIn("inputs[0].getSize()!=width", decoder)
        self.assertIn("(width!=1 && width!=2 && width!=4)", decoder)
        self.assertIn("incomplete=true;", decoder)
        self.assertIn("else\n                                        store=true;", decoder)

    def test_old_three_negative_marker_is_not_accepted(self):
        self.assertNotEqual(0, self.invoke(PREPARE + "\n" + VERIFY.replace("negative=4", "negative=3")).returncode)

    def test_missing_recovery_evidence_rejected(self):
        self.assertNotEqual(0, self.invoke(PREPARE + '\n' + VERIFY.replace(' recovery=2', '')).returncode)
        self.assertNotEqual(0, self.invoke(PREPARE + '\n' + VERIFY.replace('recovery=2', 'recovery=0')).returncode)

    def test_missing_recovery_count_is_rejected(self):
        self.assertNotEqual(0, self.invoke(PREPARE + "\n" +
            VERIFY.replace(" recovery=2", "")).returncode)

    def test_wrong_positive_and_negative_counts_rejected(self):
        for old, new in (("positive=2", "positive=1"),
                         ("negative=4", "negative=5"),
                         ("recovery=2", "recovery=3")):
            with self.subTest(field=old):
                self.assertNotEqual(0, self.invoke(PREPARE + "\n" +
                    VERIFY.replace(old, new)).returncode)

    def test_success_requires_zero_exit_even_with_valid_counts(self):
        result = self.invoke(PREPARE + "\n" + VERIFY, exit_code=1)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("GA01_CPU32_HEADLESS_FAIL", result.stdout)

    def test_missing_preparer(self):
        self.assertNotEqual(0, self.invoke(VERIFY).returncode)

    def test_missing_verifier(self):
        self.assertNotEqual(0, self.invoke(PREPARE).returncode)

    def test_duplicate_marker(self):
        self.assertNotEqual(0, self.invoke(PREPARE + "\n" + VERIFY + "\n" + VERIFY).returncode)

    def test_marker_substrings_are_not_evidence(self):
        # Near-valid full evidence must fail even with a zero process exit.
        for output in ("prefix_" + PREPARE + "\n" + VERIFY,
                       PREPARE + "\n" + VERIFY + "_suffix",
                       PREPARE + "\n" + "prefix_" + VERIFY):
            with self.subTest(output=output):
                result = self.invoke(output)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("GA01_CPU32_HEADLESS_FAIL", result.stdout)

    def test_embedded_duplicate_marker_is_not_evidence(self):
        result = self.invoke(PREPARE + "\n" + VERIFY + " " + VERIFY)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("GA01_CPU32_HEADLESS_FAIL", result.stdout)

    def test_conflicting_phase_evidence_is_rejected(self):
        # A valid marker plus a contradictory phase line is not a PASS.
        variants = (
            PREPARE + "\n" + PREPARE.replace("instructions=4", "instructions=3") + "\n" + VERIFY,
            PREPARE + "\n" + VERIFY.replace("recovery=2", "recovery=1") + "\n" + VERIFY,
            PREPARE + "\n" + VERIFY + "\n" + VERIFY.replace("negative=4", "negative=3"),
        )
        for output in variants:
            with self.subTest(output=output):
                result = self.invoke(output)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("GA01_CPU32_HEADLESS_FAIL", result.stdout)

    def test_failure_after_valid_evidence_dominates(self):
        result = self.invoke(PREPARE + "\n" + VERIFY + "\nERROR: Ghidra verifier failed")
        self.assertNotEqual(0, result.returncode)
        self.assertIn("GA01_CPU32_HEADLESS_FAIL", result.stdout)

    def test_failure_dominates_pass(self):
        self.assertNotEqual(0, self.invoke(PREPARE + "\n" + VERIFY + "\nGA18_DECODED_SITES_FAIL").returncode)

    def test_nonzero_exit_dominates_pass(self):
        self.assertNotEqual(0, self.invoke(PREPARE + "\n" + VERIFY, 2).returncode)


if __name__ == "__main__":
    unittest.main()
