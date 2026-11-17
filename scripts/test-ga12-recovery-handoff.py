#!/usr/bin/env python3
"""GA-12 selected evidence handoff regression (source-level, synthetic)."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("recover-ga12-cpu32-checkpoint.py")
spec = importlib.util.spec_from_file_location("ga12_recovery", SCRIPT)
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
SHA = "a" * 40


class HandoffTest(unittest.TestCase):
    def test_selected_pair_has_exact_digests(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            old = root / "20261117T110000Z"
            old.mkdir()
            result = old / "result.json"
            log = old / "evidence.log"
            result.write_bytes(b'{"synthetic":true}')
            log.write_bytes(b"synthetic log\n")
            original = recovery.check
            try:
                recovery.check = lambda r, l, sha: "PASS"
                selected = recovery.inspect(root, SHA)
            finally:
                recovery.check = original
            self.assertEqual(selected["status"], "RECOVERABLE")
            self.assertEqual(selected["checkpoint"], old.name)
            self.assertEqual(selected["result_sha256"], hashlib.sha256(result.read_bytes()).hexdigest())
            self.assertEqual(selected["log_sha256"], hashlib.sha256(log.read_bytes()).hexdigest())
            self.assertEqual(selected["skipped"], [])

    def test_blocked_does_not_issue_artifact_digests(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / "20261117T110000Z"
            folder.mkdir()
            result = recovery.inspect(root, SHA)
            self.assertEqual(result["status"], "BLOCKED")
            self.assertNotIn("result_sha256", result)
            self.assertNotIn("log_sha256", result)


if __name__ == "__main__":
    unittest.main()
