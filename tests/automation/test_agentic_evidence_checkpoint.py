"""Deterministic local Automation Agentic evidence handoff; no LLM or Ghidra."""
import hashlib
import importlib.machinery
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
AGENT = ROOT / "tools" / "ghidrassist-agent"
loader = importlib.machinery.SourceFileLoader("ghidrassist_cli_agentic",str(AGENT))
cli = types.ModuleType(loader.name)
loader.exec_module(cli)


def page(offset, limit, *, state="SUCCESS", incomplete=False, evicted=0,
         revision=7, run="test-opaque-run"):
    rows = [
        {"fact": "first fact", "evidence": "source 0x100",
         "toolUsed": "listing", "relevance": 9, "timestamp": 1},
        {"fact": "second fact", "evidence": "source 0x200",
         "toolUsed": "listing", "relevance": 6, "timestamp": 2},
        {"fact": "third fact", "evidence": "source 0x300",
         "toolUsed": "xrefs", "relevance": 3, "timestamp": 3},
    ]
    subset=rows[offset:offset+limit]
    return {"agentic": {
        "run": run, "programRevision": 12, "importSha256":"a"*64,
        "state":state,"complete": offset==0 and offset+limit>=3
            and state=="SUCCESS" and not incomplete and evicted==0,
        "findings":{
            "revision":revision,"offset":offset,"limit":limit,
            "retainedCount":3,"acceptedCount":3+evicted,
            "evictedCount":evicted,"sourceIncomplete":incomplete,
            "hasMore":offset+limit<3,"complete":offset==0 and offset+limit>=3,
            "rows":subset,
        }
    }}


class LocalAgenticCheckpoint(unittest.TestCase):
    def test_production_react_and_server_are_wired_without_model_rpc(self):
        root=ROOT/"src/main/java/ghidrassist"
        orchestrator=(root/"agent/react/ReActOrchestrator.java").read_text()
        server=(root/"automation/AutomationServer.java").read_text()
        registry=(root/"agent/react/AgenticEvidenceRegistry.java").read_text()
        for source,required in (
            (orchestrator,"AgenticEvidenceRegistry.shared().begin"),
            (orchestrator,"AgenticEvidenceRegistry.shared().finish"),
            (server,'"agentic.findings.page".equals(method)'),
            (server,'result.add("agentic",JSON.toJsonTree(page))'),
            (server,'result.addProperty("read_only",true)'),
            (registry,'bound.owner.get()!=owner'),
            (registry,'expectedFindingsRevision'),
        ):
            self.assertIn(required,source)
        self.assertIn('"agentic-findings":"agentic.findings.page"',AGENT.read_text())

    def test_multi_page_complete_and_atomic_no_overwrite(self):
        calls=[]
        def rpc(_session,method,args):
            self.assertEqual(method,"agentic.findings.page")
            calls.append(dict(args))
            return page(args["offset"],args["limit"])
        with tempfile.TemporaryDirectory() as work,patch.object(cli,"rpc",rpc):
            target=Path(work)/"checkpoint.json"
            status=cli.capture_agentic_checkpoint({"token":"never-export"},target,2)
            self.assertTrue(status["complete"])
            self.assertEqual(status["retained_count"],3)
            self.assertEqual(target.stat().st_mode & 0o777,0o600)
            payload=json.loads(target.read_text())
            self.assertEqual(payload["payload"]["state"],"SUCCESS")
            self.assertTrue(payload["payload"]["complete"])
            self.assertEqual(len(payload["payload"]["rows"]),3)
            self.assertNotIn("never-export",target.read_text())
            canonical=json.dumps(payload["payload"],sort_keys=True,
                separators=(",",":"),ensure_ascii=False).encode()
            self.assertEqual(payload["payload_sha256"],
                hashlib.sha256(canonical).hexdigest())
            self.assertEqual(calls[1]["expected_run"],"test-opaque-run")
            self.assertEqual(calls[1]["expected_program_revision"],12)
            self.assertEqual(calls[1]["expected_findings_revision"],7)
            with self.assertRaises(FileExistsError):
                cli.capture_agentic_checkpoint({},target,2)
            self.assertEqual(json.loads(target.read_text()),payload)
            verified=cli.verify_agentic_checkpoint(target)
            self.assertTrue(verified["verified"] and verified["complete"])
            self.assertEqual(verified["retained_count"],3)
            first_page=cli.read_agentic_checkpoint_page(target,0,2)
            self.assertEqual([x["fact"] for x in first_page["rows"]],
                ["first fact","second fact"])
            self.assertTrue(first_page["has_more"])
            self.assertFalse(first_page["page_complete"])
            self.assertTrue(first_page["source_complete"])
            last_page=cli.read_agentic_checkpoint_page(target,2,2)
            self.assertEqual(len(last_page["rows"]),1)
            self.assertFalse(last_page["has_more"])
            self.assertFalse(last_page["page_complete"])
            entire=cli.read_agentic_checkpoint_page(target,0,10)
            self.assertTrue(entire["page_complete"])
            self.assertTrue(entire["offline"] and entire["read_only"])
            # Client can browse a saved checkpoint without an active
            # Ghidra session receipt or network request, even after restart.
            import subprocess
            proc=subprocess.run(["python3",str(AGENT),"--session",
                str(Path(work)/"nonexistent-session.json"),"agentic-read",
                "--input",str(target),"--offset","1","--limit","1"],
                capture_output=True,text=True,check=True)
            offline=json.loads(proc.stdout)
            self.assertTrue(offline["offline"])
            self.assertEqual(offline["rows"][0]["fact"],"second fact")
            for offset,limit in ((-1,1),(0,0),(0,101),(1000001,1)):
                with self.assertRaises(ValueError):
                    cli.read_agentic_checkpoint_page(target,offset,limit)
            self.assertEqual(cli.read_agentic_checkpoint_page(target,999,2)["rows"],[])
            tampered=payload.copy()
            tampered["payload"]=dict(payload["payload"],state="CANCELLED")
            target.write_text(json.dumps(tampered))
            with self.assertRaises(ValueError):
                cli.verify_agentic_checkpoint(target)

    def test_historical_parent_lineage_is_read_only_and_bound_to_exact_source(self):
        import subprocess
        with tempfile.TemporaryDirectory() as work:
            root=Path(work)
            parent=root/"previous.json"
            child=root/"new-independent.json"
            def report(run):
                return page(0,100,run=run)
            with patch.object(cli,"rpc",lambda _s,_m,args:report("historical-run")):
                cli.capture_agentic_checkpoint({},parent,100)
            with patch.object(cli,"rpc",lambda _s,_m,args:report("new-run")):
                saved=cli.capture_agentic_checkpoint({},child,100,parent)
            self.assertTrue(saved["complete"])
            linked=cli.verify_agentic_lineage(child,parent)
            self.assertTrue(linked["verified"] and linked["lineage_matches"])
            self.assertTrue(linked["new_independent_run"] and linked["read_only"])
            self.assertFalse(linked["authorizes_tools"])
            self.assertFalse(linked["authorizes_apply"])
            self.assertFalse(linked["model_state_restored"])
            self.assertEqual(linked["parent_run"],"historical-run")
            self.assertEqual(linked["child_run"],"new-run")
            self.assertEqual(cli.read_agentic_checkpoint_page(child,0,10)
                ["rows"][0]["fact"],"first fact")
            result=subprocess.run(["python3",str(AGENT),"--session",
                str(root/"absent-session.json"),"agentic-lineage-verify",
                "--input",str(child),"--parent",str(parent)],
                capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue(json.loads(result.stdout)["lineage_matches"])
            other=root/"unrelated.json"
            with patch.object(cli,"rpc",lambda _s,_m,args:report("other-run")):
                cli.capture_agentic_checkpoint({},other,100)
            with self.assertRaises(ValueError):
                cli.verify_agentic_lineage(child,other)
            with self.assertRaises(ValueError):
                cli.verify_agentic_lineage(child,child)
            for changed in ("run","import_sha256"):
                data=json.loads(child.read_text())
                data["payload"][changed] = ("historical-run" if changed=="run"
                    else "b"*64)
                raw=json.dumps(data["payload"],sort_keys=True,
                    separators=(",",":"),ensure_ascii=False).encode()
                data["payload_sha256"]=hashlib.sha256(raw).hexdigest()
                forged=root/("forged-"+changed+".json")
                forged.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    cli.verify_agentic_lineage(forged,parent)
            for bad in ("parent_checkpoint_sha256","parent_run","continuation_kind"):
                data=json.loads(child.read_text())
                data["payload"].pop(bad)
                raw=json.dumps(data["payload"],sort_keys=True,
                    separators=(",",":"),ensure_ascii=False).encode()
                data["payload_sha256"]=hashlib.sha256(raw).hexdigest()
                forged=root/("missing-"+bad+".json")
                forged.write_text(json.dumps(data))
                with self.assertRaises(ValueError):
                    cli.load_verified_agentic_payload(forged)
            with patch.object(cli,"rpc",lambda _s,_m,args:report("new-run")):
                with self.assertRaises(ValueError):
                    cli.capture_agentic_checkpoint({},root/"same-run.json",100,child)
            # Changed firmware import cannot inherit the older source hash.
            def changed_firmware(_s,_m,args):
                current=report("changed-firmware-run")
                current["agentic"]["importSha256"]="b"*64
                return current
            with patch.object(cli,"rpc",changed_firmware):
                with self.assertRaises(ValueError):
                    cli.capture_agentic_checkpoint(
                        {},root/"wrong-firmware.json",100,parent)
            self.assertFalse((root/"wrong-firmware.json").exists())

    def test_three_generation_chain_and_unapproved_new_review(self):
        import subprocess
        with tempfile.TemporaryDirectory() as work:
            directory=Path(work)
            root=directory/"root.json"
            middle=directory/"middle.json"
            newest=directory/"newest.json"
            for name,path,parent in (
                    ("run-0",root,None),("run-1",middle,root),
                    ("run-2",newest,middle)):
                with patch.object(cli,"rpc",
                        lambda _s,_m,args,name=name:page(
                            args["offset"],args["limit"],run=name)):
                    cli.capture_agentic_checkpoint({},path,2,parent)
            result=cli.verify_agentic_lineage_chain(newest,[root,middle])
            self.assertTrue(result["verified"])
            self.assertTrue(result["read_only"])
            self.assertEqual(result["runs"],["run-0","run-1","run-2"])
            self.assertEqual(result["chain_length"],3)
            self.assertEqual(len(result["chain_sha256"]),64)
            self.assertFalse(result["authorizes_tools"])
            self.assertFalse(result["authorizes_apply"])
            self.assertFalse(result["old_approvals_inherited"])
            self.assertFalse(result["model_state_restored"])
            self.assertEqual(result["checkpoints"][-1]["run"],"run-2")
            self.assertEqual(result["checkpoints"][0]["program_revision"],12)
            offline=subprocess.run(["python3",str(AGENT),"--session",
                str(directory/"nonexistent-session.json"),
                "agentic-lineage-chain-verify","--input",str(newest),
                "--ancestor",str(root),"--ancestor",str(middle)],
                text=True,capture_output=True)
            self.assertEqual(offline.returncode,0,offline.stderr)
            self.assertEqual(json.loads(offline.stdout)["chain_sha256"],
                result["chain_sha256"])
            # A linked checkpoint without its COMPLETE ancestry cannot
            # seed a new review, even if its current evidence matches Ghidra.
            def live(_s,method,args):
                self.assertEqual(method,"agentic.findings.page")
                response=page(args["offset"],args["limit"],run="run-2")
                response["read_only"]=True
                return response
            review=directory/"new-review.json"
            with patch.object(cli,"rpc",live):
                with self.assertRaises(ValueError):
                    cli.create_agentic_review_draft({},
                        newest,review,"New independent source analysis")
                self.assertFalse(review.exists())
                status=cli.create_agentic_review_draft({},
                    newest,review,"New independent source analysis",
                    [root,middle])
            self.assertFalse(status["new_review_approved"])
            self.assertFalse(status["authorizes_tools"]
                if "authorizes_tools" in status else
                status["tool_execution_authorized"])
            draft=json.loads(review.read_text())["payload"]
            self.assertTrue(draft["historical_chain_verified"])
            self.assertEqual(draft["historical_chain_length"],3)
            self.assertEqual(draft["historical_chain_sha256"],
                result["chain_sha256"])
            self.assertEqual(draft["state"],"AWAITING_NEW_REVIEW")
            self.assertFalse(draft["old_plan_inherited"])
            self.assertFalse(draft["apply_authorized"])
            self.assertFalse(draft["resumable_ai_session"])

    def test_lineage_chain_rejects_hidden_parent_duplicates_and_rehashed_forgery(self):
        import subprocess
        with tempfile.TemporaryDirectory() as work:
            directory=Path(work)
            root=directory/"root.json"
            middle=directory/"middle.json"
            newest=directory/"newest.json"
            for name,path,parent in (
                    ("run-a",root,None),("run-b",middle,root),
                    ("run-c",newest,middle)):
                with patch.object(cli,"rpc",
                        lambda _s,_m,args,name=name:page(
                            args["offset"],args["limit"],run=name)):
                    cli.capture_agentic_checkpoint({},path,3,parent)
            for ancestors in (
                    [],[middle],[root],[middle,root],
                    [root,root],[root,middle,middle],
                    [root]*16,[newest,middle]):
                with self.subTest(ancestors=ancestors),self.assertRaises(ValueError):
                    cli.verify_agentic_lineage_chain(newest,ancestors)
            with self.assertRaises(ValueError):
                cli.verify_agentic_lineage_chain(root,[middle])
            for field,value in (
                    ("run","run-a"),
                    ("parent_run","run-a"),
                    ("parent_checkpoint_sha256","b"*64),
                    ("import_sha256","b"*64),
                    ("source_incomplete",True),
                    ("complete",False)):
                forged=directory/("changed-"+field+".json")
                blob=json.loads(newest.read_text())
                blob["payload"][field]=value
                canonical=json.dumps(blob["payload"],sort_keys=True,
                    separators=(",",":"),ensure_ascii=False).encode()
                blob["payload_sha256"]=hashlib.sha256(canonical).hexdigest()
                forged.write_text(json.dumps(blob))
                with self.subTest(field=field),self.assertRaises(ValueError):
                    cli.verify_agentic_lineage_chain(forged,[root,middle])
            # A legacy two-file lineage comparison alone cannot establish a
            # fully rooted chain if the parent itself already has a parent.
            self.assertTrue(cli.verify_agentic_lineage(newest,middle)["verified"])
            with self.assertRaises(ValueError):
                cli.verify_agentic_lineage_chain(newest,[middle])
            bad=subprocess.run(["python3",str(AGENT),"--session",
                str(directory/"absent-session.json"),
                "agentic-lineage-chain-verify","--input",str(newest),
                "--ancestor",str(middle)],capture_output=True,text=True)
            self.assertNotEqual(bad.returncode,0)
            self.assertIn("refused",bad.stderr)
            self.assertEqual(
                cli.verify_agentic_lineage_chain(newest,[root,middle])
                ["runs"],["run-a","run-b","run-c"])

    def test_offline_null_evidence_and_false_complete_forgery_rejected(self):
        with tempfile.TemporaryDirectory() as work:
            target=Path(work)/"nullable.json"
            with patch.object(cli,"rpc",lambda _,__,args:page(
                    args["offset"],args["limit"])):
                cli.capture_agentic_checkpoint({},target,3)
            data=json.loads(target.read_text())
            data["payload"]["rows"][0]["evidence"]=None
            canonical=json.dumps(data["payload"],sort_keys=True,
                separators=(",",":"),ensure_ascii=False).encode()
            data["payload_sha256"]=hashlib.sha256(canonical).hexdigest()
            target.write_text(json.dumps(data))
            self.assertIsNone(cli.read_agentic_checkpoint_page(target,0,1)
                ["rows"][0]["evidence"])
            data["payload"]["state"]="CANCELLED"
            canonical=json.dumps(data["payload"],sort_keys=True,
                separators=(",",":"),ensure_ascii=False).encode()
            data["payload_sha256"]=hashlib.sha256(canonical).hexdigest()
            target.write_text(json.dumps(data))
            with self.assertRaises(ValueError):
                cli.read_agentic_checkpoint_page(target,0,1)

    def test_cache_revision_change_refuses_partial_checkpoint(self):
        def rpc(_session,_method,args):
            return page(args["offset"],args["limit"],
                        revision=7 if args["offset"]==0 else 8)
        with tempfile.TemporaryDirectory() as work,patch.object(cli,"rpc",rpc):
            target=Path(work)/"checkpoint.json"
            with self.assertRaises(ValueError):
                cli.capture_agentic_checkpoint({},target,2)
            self.assertFalse(target.exists())

    def test_missing_or_evicted_source_and_running_state_stay_incomplete(self):
        for kw in ({"evicted":1},{"incomplete":True},{"state":"RUNNING"},
                   {"state":"CANCELLED"}):
            with self.subTest(kw=kw),tempfile.TemporaryDirectory() as work:
                with patch.object(cli,"rpc",lambda _,__,args:page(
                        args["offset"],args["limit"],**kw)):
                    target=Path(work)/"read-only.json"
                    info=cli.capture_agentic_checkpoint({},target,2)
                    self.assertFalse(info["complete"])
                    self.assertFalse(json.loads(target.read_text())
                        ["payload"]["complete"])
                    self.assertFalse(cli.verify_agentic_checkpoint(target)["complete"])
                    offline=cli.read_agentic_checkpoint_page(target,0,100)
                    self.assertFalse(offline["source_complete"])
                    self.assertFalse(offline["page_complete"])

    def test_resume_preflight_requires_exact_live_source_and_never_replays(self):
        calls=[]
        with tempfile.TemporaryDirectory() as work:
            target=Path(work)/"saved.json"
            with patch.object(cli,"rpc",lambda _,__,args:page(
                    args["offset"],args["limit"])):
                cli.capture_agentic_checkpoint({},target,2)
            def live(_session,method,args):
                calls.append((method,dict(args)))
                response=page(args["offset"],args["limit"])
                response["read_only"]=True
                return response
            with patch.object(cli,"rpc",live):
                result=cli.check_agentic_resume_preflight({},target)
            self.assertTrue(result["identity_matches"])
            self.assertFalse(result["resumable_ai_session"])
            self.assertFalse(result["tool_execution_authorized"])
            self.assertFalse(result["apply_authorized"])
            self.assertEqual(result["next_action"],"NEW_REVIEW_REQUIRED")
            self.assertEqual(calls,[("agentic.findings.page",
                {"offset":0,"limit":100,"expected_program_revision":12})])
            for mutation in (
                lambda p:p["agentic"].update(run="replacement"),
                lambda p:p["agentic"].update(state="CANCELLED"),
                lambda p:p["agentic"].update(programRevision=13),
                lambda p:p["agentic"].update(importSha256="b"*64),
                lambda p:p["agentic"]["findings"].update(revision=8),
                lambda p:p["agentic"]["findings"].update(acceptedCount=4),
                lambda p:p["agentic"]["findings"]["rows"][0].update(
                    fact="forged content with unchanged counters"),
                lambda p:p["agentic"]["findings"].update(rows=[]),
                lambda p:p["agentic"]["findings"].update(hasMore=True,rows=[]),
                lambda p:p.update(read_only=False),
            ):
                response=page(0,1)
                response["read_only"]=True
                mutation(response)
                with self.subTest(response=response),patch.object(cli,"rpc",
                        lambda _s,_m,_a,result=response:result):
                    with self.assertRaises(ValueError):
                        cli.check_agentic_resume_preflight({},target)
            with patch.object(cli,"rpc",side_effect=AssertionError("must not contact")):
                cancelled=Path(work)/"running.json"
                with patch.object(cli,"rpc",lambda _,__,args:page(
                        args["offset"],args["limit"],state="RUNNING")):
                    cli.capture_agentic_checkpoint({},cancelled,3)
                with self.assertRaises(ValueError):
                    cli.check_agentic_resume_preflight({},cancelled)

    def test_resume_preflight_stitches_all_rows_and_rejects_changed_later_page(self):
        with tempfile.TemporaryDirectory() as work:
            target=Path(work)/"saved.json"
            with patch.object(cli,"rpc",lambda _,__,args:page(
                    args["offset"],args["limit"])):
                cli.capture_agentic_checkpoint({},target,2)
            seen=[]
            def paginated(_session,method,args):
                self.assertEqual(method,"agentic.findings.page")
                seen.append(dict(args))
                reply=page(args["offset"],1)
                reply["read_only"]=True
                return reply
            # Force a one-row-per-page live transport even though requested
            # page limit is 100; the server is allowed to return fewer rows.
            with patch.object(cli,"rpc",paginated):
                verified=cli.check_agentic_resume_preflight({},target)
            self.assertTrue(verified["evidence_matches"])
            self.assertEqual(len(seen),3)
            self.assertEqual(seen[1]["expected_run"],"test-opaque-run")
            self.assertEqual(seen[1]["expected_findings_revision"],7)
            def changed_later(_session,method,args):
                reply=page(args["offset"],1)
                reply["read_only"]=True
                if args["offset"]==1:
                    reply["agentic"]["findings"]["rows"][0]["fact"]="altered"
                return reply
            with patch.object(cli,"rpc",changed_later),self.assertRaises(ValueError):
                cli.check_agentic_resume_preflight({},target)

    def test_review_draft_requires_new_objective_and_explicit_new_review(self):
        with tempfile.TemporaryDirectory() as work:
            original=Path(work)/"source.json"
            target=Path(work)/"review.json"
            with patch.object(cli,"rpc",lambda _,__,args:page(
                    args["offset"],args["limit"])):
                cli.capture_agentic_checkpoint({},original,2)
            def current(_session,method,args):
                self.assertEqual(method,"agentic.findings.page")
                response=page(args["offset"],args["limit"])
                response["read_only"]=True
                return response
            with patch.object(cli,"rpc",current):
                result=cli.create_agentic_review_draft({},
                    original,target,"Independently inspect MMIO references")
                self.assertFalse(result["new_review_approved"])
                self.assertFalse(result["tool_execution_authorized"])
                self.assertEqual(target.stat().st_mode & 0o777,0o600)
                draft=json.loads(target.read_text())["payload"]
                self.assertEqual(draft["state"],"AWAITING_NEW_REVIEW")
                self.assertEqual(draft["presented_evidence_count"],3)
                self.assertFalse(draft["policy_inherited"])
                self.assertFalse(draft["old_plan_inherited"])
                self.assertFalse(draft["resumable_ai_session"])
                self.assertFalse(draft["apply_authorized"])
                self.assertEqual(draft["new_objective"],
                                 "Independently inspect MMIO references")
                with self.assertRaises(FileExistsError):
                    cli.create_agentic_review_draft({},
                        original,target,"Independently inspect MMIO references")
                self.assertEqual(json.loads(target.read_text())["payload"],draft)
                for invalid in ("", "short", "X"*513, "bad\x00control"):
                    with self.subTest(invalid=invalid),self.assertRaises(ValueError):
                        cli.create_agentic_review_draft({},
                            original,Path(work)/"refused.json",invalid)
                self.assertFalse((Path(work)/"refused.json").exists())
            # A locally re-hashed fake old fact cannot seed a new review.
            altered=json.loads(original.read_text())
            altered["payload"]["rows"][0]["fact"]="injected old command"
            canonical=json.dumps(altered["payload"],sort_keys=True,
                separators=(",",":"),ensure_ascii=False).encode()
            altered["payload_sha256"]=hashlib.sha256(canonical).hexdigest()
            counterfeit=Path(work)/"counterfeit.json"
            counterfeit.write_text(json.dumps(altered))
            with patch.object(cli,"rpc",current),self.assertRaises(ValueError):
                cli.create_agentic_review_draft({},
                    counterfeit,Path(work)/"counterfeit-review.json",
                    "Independently inspect MMIO references")

    def test_gui_review_import_routes_through_explicit_plan_and_policy(self):
        tab=(ROOT/"src/main/java/ghidrassist/ui/tabs/QueryTab.java").read_text()
        controller=(ROOT/"src/main/java/ghidrassist/core/TabController.java").read_text()
        policy=(ROOT/"src/main/java/ghidrassist/ui/common/TaskToolPolicyPanel.java").read_text()
        bridge=(ROOT/"src/main/java/ghidrassist/agent/react/AgenticReviewDraft.java").read_text()
        self.assertIn("Import Review Draft",tab)
        self.assertIn("handleAgenticReviewDraftImport",tab)
        self.assertIn("stageNewAgenticReviewQuery",controller)
        self.assertIn("resetForImportedReview()",controller)
        self.assertIn("Mode.READ_ONLY, Lifetime.NEXT_TASK",policy)
        self.assertIn("new Settings(Mode.READ_ONLY",policy)
        self.assertIn("AgenticEvidenceRegistry",bridge)
        self.assertIn("public void handleAgentPlanApproved()",controller)
        self.assertNotIn("executeApprovedAgenticQuery(",bridge)

    def test_no_write_on_invalid_or_unbounded_pages(self):
        with tempfile.TemporaryDirectory() as work:
            target=Path(work)/"bad.json"
            with self.assertRaises(ValueError):
                cli.capture_agentic_checkpoint({},target,101)
            self.assertFalse(target.exists())
            def rpc(_session,_method,args):
                p=page(args["offset"],args["limit"])
                p["agentic"]["findings"]["retainedCount"]=1001
                return p
            with patch.object(cli,"rpc",rpc),self.assertRaises(ValueError):
                cli.capture_agentic_checkpoint({},target,2)
            self.assertFalse(target.exists())


if __name__=="__main__":
    unittest.main()
