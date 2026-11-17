#!/usr/bin/env python3
"""GA-12 persisted evidence verification contract; synthetic files only."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify-ga12-cpu32-checkpoint.py"
spec = importlib.util.spec_from_file_location("ga12_checkpoint", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SHA = "a" * 40
PREPARE = "GA18_PREPARE_DECODED_SITES_PASS instructions=4 function=0x100 bytes=18"
VERIFY = "GA18_DECODED_SITES_GHIDRA_PASS sites=2 positive=2 negative=4 recovery=2"


class CheckpointVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.result = Path(self.temp.name) / "result.json"
        self.log = Path(self.temp.name) / "evidence.log"

    def write(self, status="PASS", output=None, **changes):
        if output is None:
            output = ("SOURCE_SHA=" + SHA + "\n" + PREPARE + "\n" + VERIFY
                      + "\nGA01_CPU32_HEADLESS_PASS exit=0 source=" + SHA + "\n")
        self.log.write_text(output)
        payload = {
            "schema": 1, "source_sha": SHA,
            "fixture_sha256": module.EXPECTED_FIXTURE,
            "ghidra_version": "12.1.4 PUBLIC",
            "status": status,
            "reason": "verified" if status == "PASS" else "invalid_evidence_or_exit",
            "process_exit": 0 if status == "PASS" else 9,
            "evidence_kind": "isolated_synthetic_ghidra_headless",
            "evidence_log_sha256": hashlib.sha256(self.log.read_bytes()).hexdigest(),
        }
        payload.update(changes)
        self.result.write_text(json.dumps(payload))

    def check(self):
        return module.check(self.result, self.log, SHA)

    def rejected(self):
        with self.assertRaises(ValueError):
            self.check()

    def test_valid_pass(self):
        self.write()
        self.assertEqual("PASS", self.check())

    def test_valid_failure_is_not_success(self):
        self.write(status="FAIL", output="GA01_CPU32_HEADLESS_FAIL exit=9\n")
        self.assertEqual("FAIL", self.check())

    def test_mutated_log(self):
        self.write()
        self.log.write_text(self.log.read_text() + "tampered\n")
        self.rejected()

    def test_missing_or_truncated_json(self):
        self.write()
        self.result.write_text('{"schema":')
        self.rejected()
        self.result.unlink()
        self.rejected()

    def test_wrong_provenance_and_extra_fields(self):
        for change in ({"source_sha": "b" * 40},
                       {"fixture_sha256": "0" * 64},
                       {"ghidra_version": "12.1.3 PUBLIC"},
                       {"schema": True},
                       {"untrusted": "unexpected"}):
            with self.subTest(change=change):
                self.write(**change)
                self.rejected()

    def test_false_pass_and_reversed_evidence(self):
        for output in (
            PREPARE + "\nGA01_CPU32_HEADLESS_PASS exit=0\n",
            VERIFY + "\n" + PREPARE + "\nGA01_CPU32_HEADLESS_PASS exit=0\n",
            PREPARE + "\n" + VERIFY + "\n" + VERIFY +
                "\nGA01_CPU32_HEADLESS_PASS exit=0\n",
            PREPARE + "\n" + VERIFY + "\nERROR crash\nGA01_CPU32_HEADLESS_PASS exit=0\n",
        ):
            with self.subTest(output=output):
                self.write(output=output)
                self.rejected()

    def test_failure_without_verdict_rejected(self):
        self.write(status="FAIL", output="partial output\n")
        self.rejected()

    def test_large_log_rejected(self):
        self.write(output="X" * (16 * 1024 * 1024 + 1))
        self.rejected()

    def test_exit_and_reason_mismatch(self):
        self.write(process_exit=7)
        self.rejected()
        self.write(reason="timeout")
        self.rejected()


if __name__ == "__main__":
    unittest.main()
