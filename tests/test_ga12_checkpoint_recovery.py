#!/usr/bin/env python3
"""Source regression for GA-12 checkpoint recovery selection."""
import importlib.util
import hashlib
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "recover-ga12-cpu32-checkpoint.py"
spec = importlib.util.spec_from_file_location("ga12_recovery", SCRIPT)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
SHA = "a" * 40


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def make(self, name, *, symlink=False):
        folder = self.root / name
        if symlink:
            folder.symlink_to(self.root, target_is_directory=True)
        else:
            folder.mkdir()
            (folder / "result.json").write_text("{}", encoding="utf-8")
            (folder / "evidence.log").write_text("evidence", encoding="utf-8")
        return folder

    def test_latest_valid(self):
        self.make("20261117T100000Z")
        self.make("20261117T110000Z")
        with patch.object(recovery, "check", return_value="PASS") as check:
            result = recovery.inspect(self.root, SHA)
        self.assertEqual(result["checkpoint"], "20261117T110000Z")
        self.assertEqual(check.call_count, 1)

    def test_corrupt_latest_blocks_without_fallback(self):
        self.make("20261117T100000Z")
        self.make("20261117T110000Z")
        with patch.object(recovery, "check", side_effect=[ValueError("tampered"), "PASS"]) as check:
            result = recovery.inspect(self.root, SHA)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertEqual(check.call_count, 1)

    def test_explicit_prior_recovers_and_discloses_skipped(self):
        self.make("20261117T100000Z")
        self.make("20261117T110000Z")
        with patch.object(recovery, "check", side_effect=[ValueError("tampered"), "PASS"]):
            result = recovery.inspect(self.root, SHA, allow_prior=True)
        self.assertEqual(result["checkpoint"], "20261117T100000Z")
        self.assertEqual(result["skipped"][0]["reason"], "tampered")

    def test_fail_verdict_is_not_recoverable(self):
        self.make("20261117T110000Z")
        with patch.object(recovery, "check", return_value="FAIL"):
            self.assertEqual(recovery.inspect(self.root, SHA)["status"], "BLOCKED")

    def test_symlink_latest_blocks(self):
        self.make("20261117T100000Z")
        self.make("20261117T110000Z", symlink=True)
        with patch.object(recovery, "check", return_value="PASS") as check:
            self.assertEqual(recovery.inspect(self.root, SHA)["status"], "BLOCKED")
        check.assert_not_called()

    def test_missing_log_blocks(self):
        folder = self.make("20261117T110000Z")
        (folder / "evidence.log").unlink()
        with patch.object(recovery, "check") as check:
            self.assertEqual(recovery.inspect(self.root, SHA)["status"], "BLOCKED")
        check.assert_not_called()


    def real_checkpoint(self, name, *, verdict="PASS"):
        folder = self.make(name)
        if verdict == "PASS":
            log = ("GA18_PREPARE_DECODED_SITES_PASS instructions=4 function=0x100 bytes=18\\n"
                   "GA18_DECODED_SITES_GHIDRA_PASS sites=2 positive=2 negative=4 recovery=2\\n"
                   "GA01_CPU32_HEADLESS_PASS exit=0 fixture=synthetic\\n")
        else:
            log = "GA01_CPU32_HEADLESS_FAIL exit=1\\n"
        (folder / "evidence.log").write_text(log, encoding="utf-8")
        payload = {
            "schema": 1, "source_sha": SHA,
            "fixture_sha256": recovery.module.EXPECTED_FIXTURE,
            "ghidra_version": "12.1.4 PUBLIC",
            "status": verdict, "reason": "verified" if verdict == "PASS" else "invalid_evidence_or_exit",
            "process_exit": 0 if verdict == "PASS" else 1,
            "evidence_kind": "isolated_synthetic_ghidra_headless",
            "evidence_log_sha256": hashlib.sha256(log.encode()).hexdigest(),
        }
        (folder / "result.json").write_text(json.dumps(payload), encoding="utf-8")
        return folder

    def test_real_verifier_and_cli_recovery(self):
        self.real_checkpoint("20261117T100000Z")
        latest = self.real_checkpoint("20261117T110000Z")
        command = [sys.executable, str(SCRIPT), "--root", str(self.root), "--source-sha", SHA]
        ok = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertEqual(json.loads(ok.stdout)["checkpoint"], latest.name)
        (latest / "evidence.log").write_text("tampered", encoding="utf-8")
        blocked = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(blocked.returncode, 2)
        self.assertEqual(json.loads(blocked.stdout)["status"], "BLOCKED")
        fallback = subprocess.run(command + ["--allow-prior"], capture_output=True, text=True, check=False)
        self.assertEqual(fallback.returncode, 0, fallback.stderr)
        result = json.loads(fallback.stdout)
        self.assertEqual(result["checkpoint"], "20261117T100000Z")
        self.assertEqual(result["skipped"][0]["checkpoint"], latest.name)

    def test_real_verifier_rejects_fail_and_wrong_source(self):
        self.real_checkpoint("20261117T100000Z")
        self.real_checkpoint("20261117T110000Z", verdict="FAIL")
        self.assertEqual(recovery.inspect(self.root, SHA)["status"], "BLOCKED")
        self.assertEqual(recovery.inspect(self.root, SHA, allow_prior=True)["checkpoint"],
                         "20261117T100000Z")
        self.assertEqual(recovery.inspect(self.root, "b" * 40, allow_prior=True)["status"],
                         "BLOCKED")

    def test_no_checkpoints(self):
        with self.assertRaisesRegex(ValueError, "no UTC-named"):
            recovery.inspect(self.root, SHA)


if __name__ == "__main__":
    unittest.main()
