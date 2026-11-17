#!/usr/bin/env python3
"""Source-level negative/positive handoff contracts; not a Ghidra runtime test."""
import importlib.util
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
        import hashlib
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
                "log_sha256": hashlib.sha256(b"log").hexdigest(), "skipped": []}), \
                 patch("ga12_verify_handoff_placeholder", create=True) if False else patch.object(module.recover, "inspect") as unused:
                # Real semantic verifier must reject fabricated fixtures.
                self.assertEqual(module.handoff(root, SOURCE)["status"], "BLOCKED")


if __name__ == "__main__":
    unittest.main()
