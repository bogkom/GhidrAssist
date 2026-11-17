#!/usr/bin/env python3
"""Source-level negative/positive handoff contracts; not a Ghidra runtime test."""
import importlib.util
import hashlib
import json
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/handoff-ga12-cpu32-checkpoint.py"
spec = importlib.util.spec_from_file_location("ga12_handoff", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SOURCE = "a" * 40


class HandoffTests(unittest.TestCase):
    def make_checkpoint(self, root, name, *, status="PASS"):
        folder = root / name
        folder.mkdir()
        if status == "PASS":
            log = ("GA18_PREPARE_DECODED_SITES_PASS instructions=4 function=0x100 bytes=18\\n"
                   "GA18_DECODED_SITES_GHIDRA_PASS sites=2 positive=2 negative=4 recovery=2\\n"
                   "GA01_CPU32_HEADLESS_PASS exit=0 fixture=synthetic\\n")
        else:
            log = "GA01_CPU32_HEADLESS_FAIL exit=1\\n"
        (folder / "evidence.log").write_text(log, encoding="utf-8")
        payload = {
            "schema": 1, "source_sha": SOURCE,
            "fixture_sha256": module.recover.module.EXPECTED_FIXTURE,
            "ghidra_version": "12.1.4 PUBLIC",
            "status": status,
            "reason": "verified" if status == "PASS" else "invalid_evidence_or_exit",
            "process_exit": 0 if status == "PASS" else 1,
            "evidence_kind": "isolated_synthetic_ghidra_headless",
            "evidence_log_sha256": hashlib.sha256(log.encode()).hexdigest(),
        }
        (folder / "result.json").write_text(json.dumps(payload), encoding="utf-8")
        return folder

    def test_real_verified_handoff_cli_and_prior_policy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            older = self.make_checkpoint(root, "20261117T100000Z")
            latest = self.make_checkpoint(root, "20261117T110000Z")
            command = [sys.executable, str(SCRIPT), "--root", str(root), "--source-sha", SOURCE]
            ready = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(ready.returncode, 0, ready.stderr)
            manifest = json.loads(ready.stdout)
            self.assertEqual(manifest["status"], "HANDOFF_READY")
            self.assertEqual(manifest["checkpoint"], latest.name)
            self.assertEqual(manifest["result_sha256"], module.digest(latest / "result.json"))
            self.assertEqual(manifest["log_sha256"], module.digest(latest / "evidence.log"))
            self.assertIs(manifest["project_restore_authorized"], False)
            self.assertIs(manifest["apply_replay_authorized"], False)
            (latest / "evidence.log").write_text("tampered", encoding="utf-8")
            blocked = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(blocked.returncode, 2)
            self.assertEqual(json.loads(blocked.stdout)["status"], "BLOCKED")
            prior = subprocess.run(command + ["--allow-prior"], capture_output=True, text=True, check=False)
            self.assertEqual(prior.returncode, 0, prior.stderr)
            recovered = json.loads(prior.stdout)
            self.assertEqual(recovered["checkpoint"], older.name)
            self.assertEqual(recovered["skipped"][0]["checkpoint"], latest.name)

    def test_real_verifier_rejects_fail_source_and_symlink(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            good = self.make_checkpoint(root, "20261117T100000Z")
            self.make_checkpoint(root, "20261117T110000Z", status="FAIL")
            self.assertEqual(module.handoff(root, SOURCE)["status"], "BLOCKED")
            self.assertEqual(module.handoff(root, SOURCE, True)["checkpoint"], good.name)
            self.assertEqual(module.handoff(root, "b" * 40, True)["status"], "BLOCKED")
            (good / "evidence.log").unlink()
            (good / "evidence.log").symlink_to(root / "20261117T110000Z" / "evidence.log")
            self.assertEqual(module.handoff(root, SOURCE, True)["status"], "BLOCKED")

    def test_selector_block_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            with patch.object(module.recover, "inspect", return_value={"status": "BLOCKED", "reason": "FAIL"}):
                self.assertEqual(module.handoff(Path(temp), SOURCE)["status"], "BLOCKED")

    def test_missing_artifact_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / "20261117T000000Z"
            folder.mkdir()
            with patch.object(module.recover, "inspect", return_value={
                "status": "RECOVERABLE", "checkpoint": folder.name,
                "result_sha256": "0" * 64, "log_sha256": "0" * 64, "skipped": []}):
                self.assertEqual(module.handoff(root, SOURCE)["status"], "BLOCKED")

    def test_digest_mismatch_is_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / "20261117T000000Z"
            folder.mkdir()
            (folder / "result.json").write_text("tampered")
            (folder / "evidence.log").write_text("log")
            with patch.object(module.recover, "inspect", return_value={
                "status": "RECOVERABLE", "checkpoint": folder.name,
                "result_sha256": "0" * 64, "log_sha256": "0" * 64, "skipped": []}):
                self.assertEqual(module.handoff(root, SOURCE)["status"], "BLOCKED")

    def test_valid_handoff_is_never_apply_authorization(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / "20261117T000000Z"
            folder.mkdir()
            result = folder / "result.json"
            log = folder / "evidence.log"
            result.write_bytes(b"result")
            log.write_bytes(b"log")
            with patch.object(module.recover, "inspect", return_value={
                "status": "RECOVERABLE", "checkpoint": folder.name,
                "result_sha256": hashlib.sha256(b"result").hexdigest(),
                "log_sha256": hashlib.sha256(b"log").hexdigest(), "skipped": []}):
                # Real semantic verifier must reject fabricated fixtures.
                self.assertEqual(module.handoff(root, SOURCE)["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
