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
                        if params["offset"] and data["rows"]:
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


    def test_offline_page_stitch_and_terminal(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "source.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, out, 1)
            with patch.object(agent, "rpc", side_effect=AssertionError("offline must not use RPC")):
                first = agent.read_source_pairs_checkpoint_page(out, 0, 1)
                second = agent.read_source_pairs_checkpoint_page(out, 1, 1)
                end = agent.read_source_pairs_checkpoint_page(out, 2, 1)
            self.assertTrue(first["offline"])
            self.assertTrue(first["read_only"])
            self.assertTrue(first["has_more"])
            self.assertFalse(second["has_more"])
            self.assertEqual(first["rows"] + second["rows"],
                             agent.read_source_pairs_checkpoint_page(out, 0, 32)["rows"])
            self.assertEqual(end["rows"], [])
            self.assertFalse(end["has_more"])
            self.assertFalse(end["resume_authorized"])
            self.assertEqual(first["verified_sha256"], second["verified_sha256"])
            self.assertEqual(first["source_coverage"], second["source_coverage"])

    def test_offline_page_rejects_invalid_arguments_and_forged_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "source.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, out, 2)
            for offset, limit in ((-1, 1), (0, 0), (0, 33),
                                  (1000001, 1), (True, 1), (0, False)):
                with self.subTest(offset=offset, limit=limit):
                    with self.assertRaisesRegex(ValueError, "bounded"):
                        agent.read_source_pairs_checkpoint_page(out, offset, limit)
            envelope = json.loads(out.read_text())
            envelope["payload"]["rows"][0]["indirectPc"] = 0x166
            out.write_text(json.dumps(envelope))
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                agent.read_source_pairs_checkpoint_page(out, 0, 1)

    def test_offline_page_legacy_coverage_is_unknown(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "legacy.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, out, 2)
            envelope = json.loads(out.read_text())
            for key in ("functions_with_both_sources", "indirect_only_functions",
                        "movec_only_functions", "indirect_only_sites",
                        "movec_only_sites", "reset_visited_functions_with_both",
                        "coverage_incomplete"):
                envelope["payload"].pop(key)
            raw = json.dumps(envelope["payload"], sort_keys=True,
                             separators=(",", ":"), ensure_ascii=False).encode()
            envelope["payload_sha256"] = hashlib.sha256(raw).hexdigest()
            out.write_text(json.dumps(envelope))
            result = agent.read_source_pairs_checkpoint_page(out, 0, 1)
            self.assertFalse(result["coverage_available"])
            self.assertIsNone(result["source_coverage"])
            self.assertEqual(len(result["rows"]), 1)


    def test_live_rebind_full_inventory_and_terminal_fence(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/"source.json"
            with patch.object(agent,"rpc",side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({},out,1)
            def live(_session,method,params):
                self.assertEqual(method,"hardware.source_pairs.page")
                response=page(params["offset"],params["limit"])
                response["read_only"]=True
                return response
            with patch.object(agent,"rpc",side_effect=live) as rpc_mock:
                result=agent.check_source_pairs_resume_preflight({},out,1)
            self.assertTrue(result["identity_matches"])
            self.assertTrue(result["evidence_matches"])
            self.assertFalse(result["resume_authorized"])
            self.assertFalse(result["apply_authorized"])
            self.assertEqual([x.args[2]["offset"] for x in rpc_mock.call_args_list],
                             [0,1,2])

    def test_live_rebind_refuses_changed_row_generation_and_non_readonly(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/"source.json"
            with patch.object(agent,"rpc",side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({},out,1)
            for fault in ("row","generation","read_only","terminal"):
                def live(_session,_method,params):
                    response=page(params["offset"],params["limit"])
                    response["read_only"]=True
                    data=response["source_pairs"]
                    if fault=="row" and params["offset"]==1:
                        data["rows"][0]["uncertain"]=True
                    if fault=="generation" and params["offset"]==1:
                        data["generation"]="synthetic-run-B"
                    if fault=="read_only":
                        response["read_only"]=False
                    if fault=="terminal" and params["offset"]==2:
                        data["generation"]="synthetic-run-B"
                    return response
                with self.subTest(fault=fault):
                    with patch.object(agent,"rpc",side_effect=live):
                        with self.assertRaises(ValueError):
                            agent.check_source_pairs_resume_preflight({},out,1)

    def test_live_rebind_rejects_malformed_nonmultiple_terminal_page(self):
        # Two saved rows and a page size of three exercise the separate
        # terminal generation fence, not the exact-multiple path.
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "source.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, out, 2)
            for fault in ("limit", "boolean_displayed", "missing_read_only",
                          "wrong_next_offset", "unexpected_row"):
                def live(_session, _method, params):
                    response = page(params["offset"], params["limit"])
                    response["read_only"] = True
                    if params["offset"] == 2:
                        data = response["source_pairs"]
                        if fault == "limit":
                            data["limit"] = 1
                        elif fault == "boolean_displayed":
                            data["displayed"] = False
                        elif fault == "missing_read_only":
                            response.pop("read_only")
                        elif fault == "wrong_next_offset":
                            data["next_offset"] = 1
                        else:
                            data["rows"] = [page(0, 1)["source_pairs"]["rows"][0]]
                    return response
                with self.subTest(fault=fault):
                    with patch.object(agent, "rpc", side_effect=live):
                        with self.assertRaises(ValueError):
                            agent.check_source_pairs_resume_preflight({}, out, 3)

    def test_live_rebind_rejects_legacy_and_invalid_page_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp)/"source.json"
            with patch.object(agent,"rpc",side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({},out,2)
            with self.assertRaises(ValueError):
                agent.check_source_pairs_resume_preflight({},out,33)
            envelope=json.loads(out.read_text())
            for key in ("functions_with_both_sources","indirect_only_functions",
                        "movec_only_functions","indirect_only_sites",
                        "movec_only_sites","reset_visited_functions_with_both",
                        "coverage_incomplete"):
                envelope["payload"].pop(key)
            import hashlib
            raw=json.dumps(envelope["payload"],sort_keys=True,
                           separators=(",",":"),ensure_ascii=False).encode()
            envelope["payload_sha256"]=hashlib.sha256(raw).hexdigest()
            out.write_text(json.dumps(envelope))
            with patch.object(agent,"rpc",side_effect=AssertionError("must not RPC")):
                with self.assertRaisesRegex(ValueError,"Legacy"):
                    agent.check_source_pairs_resume_preflight({},out,1)


    def test_offline_compare_added_removed_changed_and_no_rpc(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "old.json"
            new = Path(tmp) / "new.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, old, 1)

            def changed_rpc(session, method, params):
                reply = page(params["offset"], params["limit"],
                             generation="synthetic-run-B", revision=8)
                for row in reply["source_pairs"]["rows"]:
                    if row["function"] == 0x130:
                        row["indirectTarget"] = 0x1a0
                return reply

            with patch.object(agent, "rpc", side_effect=changed_rpc):
                agent.capture_source_pairs_checkpoint({}, new, 1)
            with patch.object(agent, "rpc", side_effect=AssertionError("offline only")):
                result = agent.compare_source_pairs_checkpoints(old, new, 0, 1)
                terminal = agent.compare_source_pairs_checkpoints(old, new, 1, 1)
            self.assertTrue(result["offline"])
            self.assertTrue(result["read_only"])
            self.assertFalse(result["resume_authorized"])
            self.assertFalse(result["apply_authorized"])
            self.assertEqual(result["total_changes"], 1)
            self.assertEqual(result["changes"][0]["kind"], "CHANGED")
            self.assertEqual(result["changes"][0]["before"]["indirectTarget"], 0x180)
            self.assertEqual(result["changes"][0]["after"]["indirectTarget"], 0x1a0)
            self.assertFalse(result["has_more"])
            self.assertEqual(terminal["changes"], [])
            self.assertFalse(result["coverage_changed"])
            self.assertEqual(result["change_counts"],
                             {"ADDED": 0, "REMOVED": 0, "CHANGED": 1})
            self.assertEqual(result["uncertainty_changes"],
                             {"became_uncertain": 0, "became_certain": 0})
            self.assertTrue(all(value == 0 for value in
                                result["coverage_delta"].values()))
            self.assertEqual(result["change_counts"], terminal["change_counts"])

    def test_offline_compare_added_removed_and_bounded_pagination(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "old.json"
            new = Path(tmp) / "new.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, old, 2)

            def shifted_rpc(session, method, params):
                reply = page(params["offset"], params["limit"],
                             generation="synthetic-run-B", revision=8)
                for row in reply["source_pairs"]["rows"]:
                    if row["function"] == 0x200:
                        row.update(function=0x220, indirectPc=0x226, vbrPc=0x228)
                return reply

            with patch.object(agent, "rpc", side_effect=shifted_rpc):
                agent.capture_source_pairs_checkpoint({}, new, 2)
            first = agent.compare_source_pairs_checkpoints(old, new, 0, 1)
            second = agent.compare_source_pairs_checkpoints(old, new, 1, 1)
            self.assertEqual(first["total_changes"], 2)
            self.assertTrue(first["has_more"])
            self.assertFalse(second["has_more"])
            self.assertEqual([first["changes"][0]["kind"], second["changes"][0]["kind"]],
                             ["REMOVED", "ADDED"])
            self.assertEqual(first["older_revision"], 7)
            self.assertEqual(first["newer_revision"], 8)
            self.assertEqual(first["change_counts"],
                             {"ADDED": 1, "REMOVED": 1, "CHANGED": 0})
            self.assertEqual(first["change_counts"], second["change_counts"])
            self.assertEqual(first["coverage_delta"], second["coverage_delta"])

    def test_compare_reports_uncertainty_and_unpaired_coverage_separately(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "old.json"
            new = Path(tmp) / "new.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, old, 2)

            def changed(_session, _method, params):
                reply = page(params["offset"], params["limit"],
                             generation="synthetic-run-B", revision=8)
                data = reply["source_pairs"]
                data["indirect_sources"] = 3
                data["indirect_only_functions"] = 1
                data["indirect_only_sites"] = 1
                data["coverage_incomplete"] = True
                data["observed_inventory_incomplete"] = True
                for row in data["rows"]:
                    if row["function"] == 0x130:
                        row["uncertain"] = True
                return reply

            with patch.object(agent, "rpc", side_effect=changed):
                agent.capture_source_pairs_checkpoint({}, new, 2)
            result = agent.compare_source_pairs_checkpoints(old, new, 0, 1)
            self.assertEqual(result["total_changes"], 1)
            self.assertEqual(result["change_counts"],
                             {"ADDED": 0, "REMOVED": 0, "CHANGED": 1})
            self.assertEqual(result["uncertainty_changes"],
                             {"became_uncertain": 1, "became_certain": 0})
            self.assertEqual(result["coverage_delta"]["indirect_only_sites"], 1)
            self.assertEqual(result["coverage_delta"]["indirect_only_functions"], 1)
            self.assertTrue(result["coverage_changed"])
            self.assertTrue(result["source_inventory_incomplete"])
            self.assertFalse(result["resume_authorized"])
            self.assertFalse(result["apply_authorized"])

    def test_observation_provenance_delta_without_pair_or_coverage_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "old.json"
            new = Path(tmp) / "new.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, old, 1)

            def changed(_session, _method, params):
                reply = page(params["offset"], params["limit"],
                             generation="synthetic-run-B", revision=8,
                             omitted=1, incomplete=False)
                data = reply["source_pairs"]
                data["stage_epoch"] = 3
                data["reset_graph_incomplete"] = True
                return reply

            with patch.object(agent, "rpc", side_effect=changed):
                agent.capture_source_pairs_checkpoint({}, new, 1)
            first = agent.compare_source_pairs_checkpoints(old, new, 0, 1)
            last = agent.compare_source_pairs_checkpoints(old, new, 2, 1)
            self.assertEqual(first["total_changes"], 0)
            self.assertFalse(first["coverage_changed"])
            self.assertTrue(first["observation_changed"])
            self.assertTrue(first["evidence_changed"])
            self.assertEqual(first["observation_changes"],
                             last["observation_changes"])
            self.assertEqual(first["observation_changes"]["omitted_indirect"],
                             {"before": 0, "after": 1})
            self.assertEqual(first["observation_changes"]["stage_epoch"],
                             {"before": 2, "after": 3})
            self.assertEqual(first["observation_changes"]["reset_graph_incomplete"],
                             {"before": False, "after": True})
            self.assertEqual(first["observation_changes"]["bounded_source_complete"],
                             {"before": True, "after": False})
            self.assertTrue(first["source_inventory_incomplete"])
            self.assertFalse(first["resume_authorized"])
            self.assertFalse(first["apply_authorized"])

    def test_coverage_incompleteness_is_both_coverage_and_observation_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "old.json"
            new = Path(tmp) / "new.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, old, 2)

            def changed(_session, _method, params):
                return page(params["offset"], params["limit"],
                            generation="synthetic-run-C", revision=9,
                            incomplete=True)

            with patch.object(agent, "rpc", side_effect=changed):
                agent.capture_source_pairs_checkpoint({}, new, 2)
            result = agent.compare_source_pairs_checkpoints(old, new)
            self.assertEqual(result["total_changes"], 0)
            self.assertTrue(result["coverage_changed"])
            self.assertEqual(result["coverage_delta"]["functions_with_both_sources"], 0)
            self.assertTrue(result["observation_changed"])
            self.assertEqual(result["observation_changes"]["coverage_incomplete"],
                             {"before": False, "after": True})
            self.assertTrue(result["evidence_changed"])
            self.assertFalse(result["resume_authorized"])
            self.assertFalse(result["apply_authorized"])

    def test_identical_observations_have_no_delta(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "old.json"
            new = Path(tmp) / "new.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, old, 2)
                agent.capture_source_pairs_checkpoint({}, new, 2)
            result = agent.compare_source_pairs_checkpoints(old, new)
            self.assertFalse(result["evidence_changed"])
            self.assertFalse(result["observation_changed"])
            self.assertEqual(result["observation_changes"], {})
            self.assertEqual(result["total_changes"], 0)

    def test_offline_compare_rejects_tamper_wrong_import_and_bad_page(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "old.json"
            new = Path(tmp) / "new.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, old, 2)
                agent.capture_source_pairs_checkpoint({}, new, 2)
            for offset, limit in ((True, 1), (-1, 1), (0, 0), (0, 33)):
                with self.subTest(offset=offset, limit=limit):
                    with self.assertRaises(ValueError):
                        agent.compare_source_pairs_checkpoints(old, new, offset, limit)
            envelope = json.loads(new.read_text())
            envelope["payload"]["rows"][0]["indirectTarget"] = 0x1a0
            new.write_text(json.dumps(envelope))
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                agent.compare_source_pairs_checkpoints(old, new)
            envelope["payload"]["import_sha256"] = "b" * 64
            canonical = json.dumps(envelope["payload"], sort_keys=True,
                                   separators=(",", ":"), ensure_ascii=False).encode()
            envelope["payload_sha256"] = hashlib.sha256(canonical).hexdigest()
            new.write_text(json.dumps(envelope))
            with self.assertRaisesRegex(ValueError, "identical import"):
                agent.compare_source_pairs_checkpoints(old, new)

    def test_offline_compare_refuses_legacy_coverage(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "old.json"
            new = Path(tmp) / "new.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, old, 2)
                agent.capture_source_pairs_checkpoint({}, new, 2)
            envelope = json.loads(old.read_text())
            for key in ("functions_with_both_sources", "indirect_only_functions",
                        "movec_only_functions", "indirect_only_sites",
                        "movec_only_sites", "reset_visited_functions_with_both",
                        "coverage_incomplete"):
                envelope["payload"].pop(key)
            raw = json.dumps(envelope["payload"], sort_keys=True,
                             separators=(",", ":"), ensure_ascii=False).encode()
            envelope["payload_sha256"] = hashlib.sha256(raw).hexdigest()
            old.write_text(json.dumps(envelope))
            with self.assertRaisesRegex(ValueError, "explicit coverage"):
                agent.compare_source_pairs_checkpoints(old, new)



    def test_live_compare_detects_changed_evidence_without_persistent_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "historical.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, old, 1)
            original_files = set(Path(tmp).iterdir())
            def live(_session, method, params):
                self.assertEqual(method, "hardware.source_pairs.page")
                reply = page(params["offset"], params["limit"],
                             generation="synthetic-run-B", revision=8)
                for row in reply["source_pairs"]["rows"]:
                    if row["function"] == 0x130:
                        row["indirectTarget"] = 0x1a0
                return reply
            with patch.object(agent, "rpc", side_effect=live):
                result = agent.compare_source_pairs_with_live({}, old, 0, 1, 1)
            self.assertFalse(result["offline"])
            self.assertTrue(result["live_read_only"])
            self.assertFalse(result["resume_authorized"])
            self.assertFalse(result["apply_authorized"])
            self.assertEqual(result["total_changes"], 1)
            self.assertEqual(result["changes"][0]["kind"], "CHANGED")
            self.assertEqual(result["older_generation"], "synthetic-run-A")
            self.assertEqual(result["newer_generation"], "synthetic-run-B")
            self.assertEqual(set(Path(tmp).iterdir()), original_files)

    def test_live_compare_refuses_changed_firmware_and_generation_race(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "historical.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, old, 2)
            for fault in ("import", "generation", "cursor"):
                def live(_session, method, params):
                    reply = page(params["offset"], params["limit"],
                                 generation="synthetic-run-B", revision=8)
                    if fault == "import":
                        reply["source_pairs"]["import_sha256"] = "b" * 64
                    if fault == "generation" and params["offset"] == 2:
                        reply["source_pairs"]["generation"] = "synthetic-run-C"
                    if fault == "cursor" and params["offset"] == 2:
                        reply["source_pairs"]["next_offset"] = 1
                    return reply
                with self.subTest(fault=fault):
                    with patch.object(agent, "rpc", side_effect=live):
                        with self.assertRaises(ValueError):
                            agent.compare_source_pairs_with_live({}, old, 0, 1, 2)

    def test_live_compare_refuses_invalid_input_before_rpc(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / "historical.json"
            with patch.object(agent, "rpc", side_effect=self.fake_rpc):
                agent.capture_source_pairs_checkpoint({}, old, 2)
            for offset, limit, size in ((-1, 1, 2), (0, 33, 2),
                                        (0, 1, 0), (0, 1, True)):
                with self.subTest(offset=offset, limit=limit, size=size):
                    with patch.object(agent, "rpc", side_effect=AssertionError("no RPC")):
                        with self.assertRaises(ValueError):
                            agent.compare_source_pairs_with_live(
                                {}, old, offset, limit, size)
            envelope = json.loads(old.read_text())
            envelope["payload"]["rows"][0]["uncertain"] = True
            old.write_text(json.dumps(envelope))
            with patch.object(agent, "rpc", side_effect=AssertionError("no RPC")):
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    agent.compare_source_pairs_with_live({}, old)



if __name__ == "__main__":
    unittest.main(verbosity=2)
