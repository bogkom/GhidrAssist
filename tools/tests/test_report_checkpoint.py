#!/usr/bin/env python3
"""GA-12/15/18 deterministic full hardware report capture (no Ghidra/LLM)."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT=Path(__file__).resolve().parents[1]/"ghidrassist-agent"
loader=importlib.machinery.SourceFileLoader("ga_report_agent",str(SCRIPT))
spec=importlib.util.spec_from_loader(loader.name,loader)
agent=importlib.util.module_from_spec(spec)
loader.exec_module(agent)
TEXT="0123456789"
GEN="ca5eb04c-6b1c-4bd0-abf5-424ea3e29047"

def page(offset,limit,*,generation=GEN,revision="GA12-REV1-object",
         program_path="/synthetic-mmio.bin",text=TEXT,fmt="markdown"):
    end=min(offset+limit,len(text))
    return {"report":{
        "format":fmt,"revision":revision,"program_revision":11,
        "generation":generation,"stage_epoch":3,
        "import_sha256":"a"*64,"profile":"MC68332_USER_SELECTED",
        "program_path":program_path,"total_characters":len(text),
        "scope":"STATIC EVIDENCE ONLY; NO EXECUTION OR PHYSICAL MAPPING",
        "offset":offset,"limit":limit,"text":text[offset:end],
        "more":end<len(text),
    }}

class ReportCapture(unittest.TestCase):
    def test_complete_three_pages_terminal_and_no_overwrite(self):
        calls=[]
        def api(_session,method,params):
            self.assertEqual(method,"analysis.export")
            calls.append(dict(params))
            return page(params["offset"],params["limit"])
        with tempfile.TemporaryDirectory() as work:
            target=Path(work)/"report.json"
            with patch.object(agent,"rpc",api):
                result=agent.capture_report_checkpoint({},target,"markdown",4)
            self.assertEqual([x["offset"] for x in calls],[0,4,8,10])
            for sub in calls[1:]:
                self.assertEqual(sub["expected_generation"],GEN)
                self.assertEqual(sub["expected_revision"],"GA12-REV1-object")
            self.assertEqual(result["total_characters"],10)
            self.assertEqual(target.stat().st_mode&0o777,0o600)
            verified=agent.verify_report_checkpoint(target)
            self.assertTrue(verified["complete"])
            self.assertTrue(verified["read_only"])
            self.assertFalse(verified["apply_authorized"])
            self.assertFalse(verified["model_state_restored"])
            self.assertEqual(verified["payload_sha256"],result["report_sha256"])
            self.assertEqual(json.loads(target.read_text())["payload"]["content"],TEXT)
            with patch.object(agent,"rpc",api):
                with self.assertRaises(FileExistsError):
                    agent.capture_report_checkpoint({},target,"markdown",4)
            self.assertEqual(agent.verify_report_checkpoint(target)["payload_sha256"],
                             result["report_sha256"])

    def test_changed_generation_and_program_before_next_page_fail_closed(self):
        with tempfile.TemporaryDirectory() as work:
            for field,new_value in (("generation","00000000-0000-0000-0000-000000000000"),
                                    ("program_path","/guard-other.bin"),
                                    ("revision","GA12-REV1-stale"),
                                    ("program_revision",99),
                                    ("stage_epoch",4),
                                    ("total_characters",11)):
                target=Path(work)/("denied-"+field+".json")
                def api(_session,method,params):
                    reply=page(params["offset"],params["limit"])
                    if params["offset"]:
                        reply["report"][field]=new_value
                    return reply
                with self.subTest(field=field),patch.object(agent,"rpc",api):
                    with self.assertRaises(ValueError):
                        agent.capture_report_checkpoint({},target,"markdown",4)
                    self.assertFalse(target.exists())

    def test_final_sentinel_change_refuses_even_after_last_content_page(self):
        with tempfile.TemporaryDirectory() as work:
            target=Path(work)/"denied.json"
            def api(_session,method,params):
                reply=page(params["offset"],params["limit"])
                if params["offset"]==len(TEXT):
                    reply["report"]["generation"]="00000000-0000-0000-0000-000000000000"
                return reply
            with patch.object(agent,"rpc",api),self.assertRaises(ValueError):
                agent.capture_report_checkpoint({},target,"markdown",4)
            self.assertFalse(target.exists())

    def test_wrong_content_gap_and_no_progress_refuse_without_file(self):
        for wrong in ("empty","short","oversize","wrong-flag"):
            with tempfile.TemporaryDirectory() as work:
                target=Path(work)/"denied.json"
                def api(_session,method,params):
                    reply=page(params["offset"],params["limit"])
                    if params["offset"]==4:
                        if wrong=="empty":
                            reply["report"]["text"]=""
                        elif wrong=="short":
                            reply["report"]["offset"]=5
                        elif wrong=="oversize":
                            reply["report"]["text"]="X"*(params["limit"]+1)
                        else:
                            reply["report"]["more"]=False
                    return reply
                with self.subTest(case=wrong),patch.object(agent,"rpc",api):
                    with self.assertRaises(ValueError):
                        agent.capture_report_checkpoint({},target,"markdown",4)
                    self.assertFalse(target.exists())

    def test_offline_tamper_false_authority_and_forged_content_denied(self):
        with tempfile.TemporaryDirectory() as work:
            path=Path(work)/"report.json"
            with patch.object(agent,"rpc",lambda _s,_m,p:page(p["offset"],p["limit"])):
                agent.capture_report_checkpoint({},path,"markdown",4)
            original=json.loads(path.read_text())
            for key,value in (("content","forged"),("apply_authorized",True),
                              ("complete",False),("read_only",False)):
                altered=json.loads(json.dumps(original))
                altered["payload"][key]=value
                other=Path(work)/("changed-"+key+".json")
                other.write_text(json.dumps(altered))
                with self.subTest(key=key),self.assertRaises(ValueError):
                    agent.verify_report_checkpoint(other)
            forged=json.loads(json.dumps(original))
            forged["payload"]["apply_authorized"]=True
            canonical=json.dumps(forged["payload"],sort_keys=True,
                                 separators=(",",":"),ensure_ascii=True).encode()
            forged["payload_sha256"]=agent.hashlib.sha256(canonical).hexdigest()
            other=Path(work)/"resealed-unsafe.json"
            other.write_text(json.dumps(forged))
            with self.assertRaises(ValueError):
                agent.verify_report_checkpoint(other)
            self.assertTrue(agent.verify_report_checkpoint(path)["verified"])

    def test_unicode_utf16_characters_preserved_without_truncation(self):
        full="ABéC"
        with tempfile.TemporaryDirectory() as work:
            target=Path(work)/"unicode.json"
            with patch.object(agent,"rpc",lambda _s,_m,p:page(
                    p["offset"],p["limit"],text=full)):
                agent.capture_report_checkpoint({},target,"markdown",2)
            self.assertEqual(json.loads(target.read_text())["payload"]["content"],full)
            self.assertTrue(agent.verify_report_checkpoint(target)["verified"])

if __name__=="__main__":
    unittest.main()
