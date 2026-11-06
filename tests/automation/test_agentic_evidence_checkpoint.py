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
