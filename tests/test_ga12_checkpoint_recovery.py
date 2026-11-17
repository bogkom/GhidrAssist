#!/usr/bin/env python3
"""Source regression for GA-12 checkpoint recovery selection."""
import importlib.util
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

    def test_no_checkpoints(self):
        with self.assertRaisesRegex(ValueError, "no UTC-named"):
            recovery.inspect(self.root, SHA)


if __name__ == "__main__":
    unittest.main()
