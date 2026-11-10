#!/usr/bin/env python3
"""GA-12/13/15/18: adversarial offline JSON receipt ambiguity regression.

Only synthetic deterministic fixtures. The test first captures four genuine
CLI receipt kinds, then modifies their *serialized* JSON without altering the
last-key interpretation or the already valid payload digest. These ambiguous
files used to pass Python's default last-key-wins decoder.
"""
import hashlib
import importlib.machinery
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    module = types.ModuleType(loader.name)
    module.__file__ = str(path)
    loader.exec_module(module)
    return module


agent = load(ROOT / "tools/ghidrassist-agent", "checkpoint_json_agent")
source_fixture = load(ROOT / "tools/tests/test_source_pair_checkpoint.py",
                      "checkpoint_json_source_fixture")
single_fixture = load(ROOT / "tools/tests/test_report_checkpoint.py",
                      "checkpoint_json_single_fixture")
set_fixture = load(ROOT / "tools/tests/test_report_set_checkpoint.py",
                   "checkpoint_json_set_fixture")
agentic_fixture = load(ROOT / "tests/automation/test_agentic_evidence_checkpoint.py",
                       "checkpoint_json_agentic_fixture")


class OfflineJsonAmbiguity(unittest.TestCase):
    def create_receipt(self, kind, target):
        def fake_rpc(_session, method, params):
            if kind == "source":
                self.assertEqual(method, "hardware.source_pairs.page")
                return source_fixture.page(params["offset"], params["limit"])
            if kind == "single":
                self.assertEqual(method, "analysis.export")
                return single_fixture.page(params["offset"], params["limit"])
            if kind == "set":
                if method == "analysis.report.manifest":
                    return {"manifest": set_fixture.initial_manifest()}
                self.assertEqual(method, "analysis.export")
                return set_fixture.page(params["format"], params["offset"],
                                        params["limit"])
            self.assertEqual(method, "agentic.findings.page")
            return agentic_fixture.page(params["offset"], params["limit"])

        with patch.object(agent, "rpc", fake_rpc):
            if kind == "source":
                agent.capture_source_pairs_checkpoint({}, target, 2)
            elif kind == "single":
                agent.capture_report_checkpoint({}, target, "markdown", 4)
            elif kind == "set":
                agent.capture_report_set_checkpoint({}, target, 3)
            else:
                agent.capture_agentic_checkpoint({}, target, 10)

    def verifier(self, kind):
        return {
            "source": agent.verify_source_pairs_checkpoint,
            "single": agent.verify_report_checkpoint,
            "set": agent.verify_report_set_checkpoint,
            "agentic": agent.verify_agentic_checkpoint,
        }[kind]

    def test_valid_historical_format_then_same_sha_duplicate_keys_denied(self):
        injections = {
            "source": ('"schema": 1', '"schema": 0, "schema": 1'),
            "single": ('"apply_authorized": false',
                       '"apply_authorized": true, "apply_authorized": false'),
            "set": ('"program_path": "/synthetic-mmio.bin"',
                    '"\\u0070rogram_path": "/forged.bin", '
                    '"program_path": "/synthetic-mmio.bin"'),
            "agentic": ('"complete": true',
                        '"complete": false, "complete": true'),
        }
        with tempfile.TemporaryDirectory() as work:
            for kind, (old, replacement) in injections.items():
                with self.subTest(kind=kind):
                    file = Path(work) / (kind + ".json")
                    self.create_receipt(kind, file)
                    verify = self.verifier(kind)
                    self.assertTrue(verify(file)["verified"])
                    original = json.loads(file.read_text(encoding="utf-8"))
                    raw = file.read_text(encoding="utf-8")
                    self.assertIn(old, raw)
                    forged = raw.replace(old, replacement, 1)
                    # Default json.loads still selects the final identical
                    # field: both payload and existing SHA remain unchanged.
                    self.assertEqual(json.loads(forged), original)
                    file.write_text(forged, encoding="utf-8")
                    with self.assertRaisesRegex(
                            ValueError, "Duplicate checkpoint JSON key"):
                        verify(file)

    def test_rehashed_nonfinite_or_oversized_ignored_row_value_denied(self):
        # Source/Agentic readers formerly accepted untrusted extra row
        # fields; digest recomputation alone must not permit non-JSON
        # NaN/Infinity tokens or pathological numeric allocation.
        numbers = [float("nan"), float("inf"), float("-inf"), int("9" * 65)]
        with tempfile.TemporaryDirectory() as work:
            for kind in ("source", "agentic"):
                original = Path(work) / (kind + "-good.json")
                self.create_receipt(kind, original)
                for number in numbers:
                    with self.subTest(kind=kind, number=str(number)[:20]):
                        envelope = json.loads(original.read_text(encoding="utf-8"))
                        envelope["payload"]["rows"][0]["ignored_number"] = number
                        canonical = json.dumps(
                            envelope["payload"], sort_keys=True,
                            separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                        envelope["payload_sha256"] = hashlib.sha256(
                            canonical).hexdigest()
                        modified = Path(work) / (kind + "-mutated.json")
                        modified.write_text(json.dumps(envelope), encoding="utf-8")
                        with self.assertRaisesRegex(
                                ValueError, "Non-finite|Oversized"):
                            self.verifier(kind)(modified)

    def test_malformed_utf8_and_recursive_json_fail_as_value_error(self):
        for raw in (b'{"x": "\xff"}', b"[" * 1100 + b"]" * 1100):
            with self.subTest(length=len(raw)):
                with self.assertRaises(ValueError):
                    agent._decode_checkpoint_json(raw)


if __name__ == "__main__":
    unittest.main(verbosity=2)
