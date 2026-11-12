#!/usr/bin/env python3
"""GA-12/18 deterministic offline source-pair checkpoint integration tests."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "ghidrassist-agent"
loader = importlib.machinery.SourceFileLoader("ghidrassist_agent_source_test", str(SCRIPT))
spec = importlib.util.spec_from_loader(loader.name, loader)
agent = importlib.util.module_from_spec(spec)
loader.exec_module(agent)


def page(offset, limit, generation="synthetic-run-A", revision=7,
         omitted=0, incomplete=False):
    pairs = [
        {"function": 0x130, "indirectPc": 0x138,
         "indirectTarget": 0x180, "vbrPc": 0x144,
         "mayMm": True, "uncertain": False},
        {"function": 0x200, "indirectPc": 0x206,
         "indirectTarget": 0x180, "vbrPc": 0x208,
         "mayMm": True, "uncertain": False},
    ]
    rows = pairs[offset:offset + limit]
    return {"source_pairs": {
        "schema": 1, "revision": revision, "generation": generation,
        "import_sha256": "a" * 64, "profile": "MC68332_USER_SELECTED",
        "total_pairs": 2, "indirect_sources": 2, "movec_sources": 2,
        "omitted_indirect": omitted, "omitted_movec": 0,
        "reset_root_recognized": True, "reset_graph_incomplete": False,
        "observed_inventory_incomplete": incomplete,
        "functions_with_both_sources": 2,
        "indirect_only_functions": 0, "movec_only_functions": 0,
        "indirect_only_sites": 0, "movec_only_sites": 0,
        "reset_visited_functions_with_both": 1,
        "coverage_incomplete": incomplete,
        "stage_epoch": 2,
        "offset": offset, "limit": limit, "next_offset": offset + len(rows),
        "has_more": offset + len(rows) < 2, "displayed": len(rows),
        "rows": rows,
    }}


class SourceCheckpoint(unittest.TestCase):
    def fake_rpc(self, _, method, params):
        self.assertEqual(method, "hardware.source_pairs.page")
        self.calls.append(dict(params))
        if params["offset"]:
            self.assertEqual(params["expected_revision"], 7)
            self.assertEqual(params["expected_generation"], "synthetic-run-A")
        return page(params["offset"], params["limit"])

    def setUp(self):
        self.calls = []

    def test_two_page_stitch_verification_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "checkpoint.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                report = agent.capture_source_pairs_checkpoint({}, out, 1)
            self.assertEqual(report["total_pairs"], 2)
            self.assertTrue(report["bounded_source_complete"])
            self.assertEqual([x["offset"] for x in self.calls], [0, 1, 2])
            verified = agent.verify_source_pairs_checkpoint(out)
            self.assertTrue(verified["verified"])
            self.assertTrue(verified["bounded_source_complete"])
            self.assertFalse(verified["resume_authorized"])
            payload=json.loads(out.read_text())["payload"]
            self.assertEqual(payload["functions_with_both_sources"],2)
            self.assertEqual(payload["reset_visited_functions_with_both"],1)
            self.assertEqual(payload["indirect_only_sites"],0)
            self.assertFalse(payload["coverage_incomplete"])
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                with self.assertRaises(FileExistsError):
                    agent.capture_source_pairs_checkpoint({}, out, 1)

    def test_terminal_generation_fence_rejects_rerun_after_final_page(self):
        with tempfile.TemporaryDirectory() as tmp:
            for fault in ("generation", "revision", "trailing", "cursor"):
                out = Path(tmp) / (fault + ".json")
                def late(_session, _method, params):
                    response = page(params["offset"], params["limit"])
                    if params["offset"] == 2:
                        data = response["source_pairs"]
                        if fault == "generation":
                            data["generation"] = "synthetic-run-B"
                        elif fault == "revision":
                            data["revision"] = 8
                        elif fault == "trailing":
                            data["rows"] = [page(0, 1)["source_pairs"]["rows"][0]]
                            data["displayed"] = 1
                            data["next_offset"] = 3
                        else:
                            data["next_offset"] = 1
                    return response
                with patch.object(agent, "rpc", side_effect=late):
                    with self.assertRaises(ValueError):
                        agent.capture_source_pairs_checkpoint({}, out, 1)
                self.assertFalse(out.exists())

    def test_cpu32_site_identity_rejects_rehashed_forged_rows(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            for fault in ("odd_pc", "outside_function", "same_site",
                          "bool_address", "missing_uncertainty"):
                out = Path(tmp) / (fault + ".json")
                with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                    agent.capture_source_pairs_checkpoint({}, out, 2)
                envelope = json.loads(out.read_text())
                row = envelope["payload"]["rows"][0]
                if fault == "odd_pc":
                    row["indirectPc"] = 0x139
                elif fault == "outside_function":
                    row["vbrPc"] = 0x100
                elif fault == "same_site":
                    row["vbrPc"] = row["indirectPc"]
                elif fault == "bool_address":
                    row["indirectTarget"] = True
                else:
                    row.pop("uncertain")
                raw = json.dumps(envelope["payload"], sort_keys=True,
                                 separators=(",", ":"), ensure_ascii=False).encode()
                envelope["payload_sha256"] = hashlib.sha256(raw).hexdigest()
                out.write_text(json.dumps(envelope))
                with self.assertRaisesRegex(ValueError, "source row"):
                    agent.verify_source_pairs_checkpoint(out)

    def test_cpu32_site_identity_refuses_invalid_live_rows_without_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            for fault in ("odd_pc", "outside_function", "same_site", "bool_mm"):
                out = Path(tmp) / (fault + ".json")
                def broken(_session, _method, params):
                    response = page(params["offset"], params["limit"])
                    for row in response["source_pairs"]["rows"]:
                        if fault == "odd_pc":
                            row["indirectPc"] += 1
                        elif fault == "outside_function":
                            row["vbrPc"] = 0x100
                        elif fault == "same_site":
                            row["vbrPc"] = row["indirectPc"]
                        else:
                            row["mayMm"] = 1
                    return response
                with patch.object(agent, "rpc", side_effect=broken):
                    with self.assertRaisesRegex(ValueError, "source row"):
                        agent.capture_source_pairs_checkpoint({}, out, 2)
                self.assertFalse(out.exists())

    def test_late_generation_change_rejects_atomic_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "forbidden.json"
            def changing(session, method, params):
                return page(params["offset"], params["limit"],
                            "synthetic-run-B" if params["offset"] else "synthetic-run-A")
            with patch.object(agent, "rpc", side_effect=changing):
                with self.assertRaisesRegex(ValueError, "revision/generation"):
                    agent.capture_source_pairs_checkpoint({}, out, 1)
            self.assertFalse(out.exists())

    def test_late_revision_change_rejects_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "forbidden.json"
            def changing(session, method, params):
                return page(params["offset"], params["limit"],
                            revision=8 if params["offset"] else 7)
            with patch.object(agent, "rpc", side_effect=changing):
                with self.assertRaisesRegex(ValueError, "revision/generation"):
                    agent.capture_source_pairs_checkpoint({}, out, 1)
            self.assertFalse(out.exists())

    def test_no_progress_wrong_count_and_duplicate_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            for fault in ("no_progress", "wrong_count", "duplicate"):
                out = Path(tmp) / (fault + ".json")
                def broken(session, method, params):
                    response = page(params["offset"], params["limit"])
                    data = response["source_pairs"]
                    if fault == "no_progress":
                        data["rows"] = []
                        data["displayed"] = 0
                        data["next_offset"] = params["offset"]
                    elif fault == "wrong_count":
                        data["total_pairs"] = 3
                    else:
                        if params["offset"]:
                            data["rows"][0] = page(0, 1)["source_pairs"]["rows"][0]
                    return response
                with patch.object(agent, "rpc", side_effect=broken):
                    with self.assertRaises(ValueError):
                        agent.capture_source_pairs_checkpoint({}, out, 1)
                self.assertFalse(out.exists())

    def test_unmatched_coverage_is_saved_without_inventing_pair_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/"unmatched.json"
            def unmatched(_session,_method,params):
                response=page(params["offset"],params["limit"],
                              omitted=1,incomplete=True)
                data=response["source_pairs"]
                data.update(indirect_sources=3,indirect_only_functions=1,
                            indirect_only_sites=1,coverage_incomplete=True)
                return response
            with patch.object(agent,"rpc",side_effect=unmatched):
                result=agent.capture_source_pairs_checkpoint({},out,1)
            self.assertFalse(result["bounded_source_complete"])
            payload=json.loads(out.read_text())["payload"]
            self.assertEqual(payload["indirect_only_sites"],1)
            self.assertEqual(payload["indirect_only_functions"],1)
            self.assertTrue(payload["coverage_incomplete"])
            verified=agent.verify_source_pairs_checkpoint(out)
            self.assertTrue(verified["verified"])
            self.assertEqual(verified["source_coverage"]["indirect_only_sites"],1)
            self.assertEqual(verified["source_coverage"]["functions_with_both_sources"],2)
            self.assertTrue(verified["source_coverage"]["coverage_incomplete"])

    def test_cross_page_coverage_mutation_is_rejected_atomically(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/"mutated.json"
            def mutated(_session,_method,params):
                response=page(params["offset"],params["limit"])
                if params["offset"]:
                    response["source_pairs"]["movec_only_sites"]=1
                    response["source_pairs"]["movec_only_functions"]=1
                return response
            with patch.object(agent,"rpc",side_effect=mutated):
                with self.assertRaisesRegex(ValueError,"revision/generation"):
                    agent.capture_source_pairs_checkpoint({},out,1)
            self.assertFalse(out.exists())

    def test_invalid_coverage_and_forged_saved_pair_counts_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            for invalid in ("bool_count","over_budget","false_complete"):
                out=Path(tmp)/(invalid+".json")
                def invalid_rpc(_session,_method,params):
                    response=page(params["offset"],params["limit"])
                    data=response["source_pairs"]
                    if invalid=="bool_count":
                        data["functions_with_both_sources"]=True
                    elif invalid=="over_budget":
                        data["reset_visited_functions_with_both"]=3
                    else:
                        data["coverage_incomplete"]=True
                    return response
                with patch.object(agent,"rpc",side_effect=invalid_rpc):
                    with self.assertRaises(ValueError):
                        agent.capture_source_pairs_checkpoint({},out,2)
                self.assertFalse(out.exists())
            valid=Path(tmp)/"valid.json"
            with patch.object(agent,"rpc",side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({},valid,2)
            envelope=json.loads(valid.read_text())
            envelope["payload"]["functions_with_both_sources"]=1
            import hashlib
            raw=json.dumps(envelope["payload"],sort_keys=True,
                           separators=(",",":"),ensure_ascii=False).encode()
            envelope["payload_sha256"]=hashlib.sha256(raw).hexdigest()
            valid.write_text(json.dumps(envelope))
            with self.assertRaisesRegex(ValueError,"coverage mismatch"):
                agent.verify_source_pairs_checkpoint(valid)

    def test_legacy_checkpoint_remains_verifiable_without_invented_coverage(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/"legacy.json"
            with patch.object(agent,"rpc",side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({},out,2)
            envelope=json.loads(out.read_text())
            for key in ("functions_with_both_sources","indirect_only_functions",
                        "movec_only_functions","indirect_only_sites",
                        "movec_only_sites","reset_visited_functions_with_both",
                        "coverage_incomplete"):
                envelope["payload"].pop(key)
            raw=json.dumps(envelope["payload"],sort_keys=True,
                           separators=(",",":"),ensure_ascii=False).encode()
            envelope["payload_sha256"]=hashlib.sha256(raw).hexdigest()
            out.write_text(json.dumps(envelope))
            verified=agent.verify_source_pairs_checkpoint(out)
            self.assertTrue(verified["verified"])
            self.assertFalse(verified["coverage_available"])
            self.assertIsNone(verified["source_coverage"])
            self.assertFalse(verified["resume_authorized"])

    def test_incomplete_inventory_not_marked_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "partial.json"
            with patch.object(agent, "rpc", side_effect=lambda session, method, params:
                              page(params["offset"], params["limit"],
                                   omitted=3, incomplete=True)):
                result = agent.capture_source_pairs_checkpoint({}, out, 2)
            self.assertFalse(result["bounded_source_complete"])
            verification = agent.verify_source_pairs_checkpoint(out)
            self.assertFalse(verification["bounded_source_complete"])

    def test_integrity_rejects_tamper_even_if_json_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "valid.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, out, 2)
            envelope = json.loads(out.read_text())
            envelope["payload"]["rows"][0]["indirectPc"] = 0x166
            out.write_text(json.dumps(envelope))
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                agent.verify_source_pairs_checkpoint(out)

    def test_limits_and_empty_input(self):
        with self.assertRaises(ValueError):
            agent.capture_source_pairs_checkpoint({}, "/nowhere", 33)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "empty.json"
            with patch.object(agent, "rpc", side_effect=lambda session, method, params:
                              {**page(0,1),
                               "source_pairs": {
                                   **page(0,1)["source_pairs"],
                                   "rows":[],"displayed":0,"next_offset":0}}):
                with self.assertRaises(ValueError):
                    agent.capture_source_pairs_checkpoint({}, out, 1)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
