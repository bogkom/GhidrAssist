#!/usr/bin/env python3
"""GA-12/18 deterministic full three-format Ghidra report manifest integrity."""
import copy
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT=Path(__file__).resolve().parents[1]/"ghidrassist-agent"
loader=importlib.machinery.SourceFileLoader("ga_report_set_agent",str(SCRIPT))
spec=importlib.util.spec_from_loader(loader.name,loader)
agent=importlib.util.module_from_spec(spec)
loader.exec_module(agent)

TEXTS={"markdown":"ABCDéFGH","config_csv":"offset,name\n0x100,SIMCR\n",
       "names_csv":"function,new_name\n0x130,RESET\n"}
GENERATIONS={
    "markdown":"12345678-1234-4234-8234-123456789abc",
    "config_csv":"12345678-1234-4234-8234-123456789abd",
    "names_csv":"12345678-1234-4234-8234-123456789abe",
}
def initial_manifest():
    return {
        "schema":1,"kind":"ghidrassist-hardware-report-set-manifest",
        "revision":"ga12-opaque-capture-7","program_revision":19,
        "stage_epoch":9,"program_path":"/synthetic-mmio.bin",
        "import_sha256":"a"*64,"profile":"MC68332_USER_SELECTED",
        "scope":"STATIC EVIDENCE ONLY; NO EXECUTION OR PHYSICAL MAPPING",
        "formats":{
            fmt:{"generation":GENERATIONS[fmt],
                 "total_characters":len(TEXTS[fmt]),
                 "sha256_utf8":hashlib.sha256(TEXTS[fmt].encode()).hexdigest()}
            for fmt in GENERATIONS},
    }

def page(fmt,offset,limit,manifest=None):
    m=manifest or initial_manifest()
    text=TEXTS[fmt]
    fields={k:m[k] for k in (
        "revision","program_revision","stage_epoch","program_path",
        "import_sha256","profile","scope")}
    fields.update(
        format=fmt,generation=m["formats"][fmt]["generation"],
        total_characters=m["formats"][fmt]["total_characters"],
        text=text[offset:offset+limit],
        offset=offset,limit=limit,more=offset+limit<len(text))
    return {"report":fields}

class ReportSet(unittest.TestCase):
    def test_realistic_three_format_capture_verify_and_no_overwrite(self):
        calls=[]
        def api(_session,method,args):
            calls.append((method,dict(args)))
            if method=="analysis.report.manifest":
                return {"manifest":copy.deepcopy(initial_manifest())}
            self.assertEqual(method,"analysis.export")
            return page(args["format"],args["offset"],args["limit"])
        with tempfile.TemporaryDirectory() as work,patch.object(agent,"rpc",api):
            output=Path(work)/"report-set.json"
            result=agent.capture_report_set_checkpoint({},output,3)
            self.assertTrue(result["complete"])
            self.assertEqual(set(result["formats"]),set(GENERATIONS))
            self.assertEqual(output.stat().st_mode & 0o777,0o600)
            self.assertEqual([name for name,_ in calls].count(
                "analysis.report.manifest"),2)
            self.assertGreater(len(calls),12)
            verified=agent.verify_report_set_checkpoint(output)
            self.assertEqual(verified["report_generations"],GENERATIONS)
            self.assertTrue(verified["verified"])
            self.assertFalse(verified["apply_authorized"])
            record=json.loads(output.read_text())
            self.assertEqual(record["payload"]["reports"],TEXTS)
            missing_session=Path(work)/"session-does-not-exist.json"
            offline=subprocess.run([sys.executable,str(SCRIPT),
                "--session",str(missing_session),"report-set-verify",
                "--input",str(output)],capture_output=True,text=True)
            self.assertEqual(offline.returncode,0,offline.stderr)
            self.assertTrue(json.loads(offline.stdout)["verified"])
            with self.assertRaises(FileExistsError):
                agent.capture_report_set_checkpoint({},output,3)
            self.assertTrue(agent.verify_report_set_checkpoint(output)["verified"])

    def test_undo_redo_like_mutation_in_each_format_refuses_all_output(self):
        for phase in ("initial_manifest","middle_page","between_formats",
                      "terminal_page","final_manifest"):
            with tempfile.TemporaryDirectory() as work:
                output=Path(work)/"denied.json"
                manifests=0
                exports=0
                def api(_session,method,args):
                    nonlocal manifests,exports
                    if method=="analysis.report.manifest":
                        manifests+=1
                        m=initial_manifest()
                        if phase=="initial_manifest":
                            m["formats"]["markdown"]["sha256_utf8"]="0"*64
                        elif phase=="final_manifest" and manifests==2:
                            # Undo/Redo may restore Program revision/content;
                            # the new per-scan generation must still differ.
                            m["formats"]["names_csv"]["generation"]=(
                                "00000000-0000-4000-8000-000000000000")
                        return {"manifest":m}
                    exports+=1
                    result=page(args["format"],args["offset"],args["limit"])
                    if phase=="middle_page" and args["format"]=="markdown" and args["offset"]>0:
                        result["report"]["program_revision"]=99
                    elif phase=="between_formats" and args["format"]=="config_csv":
                        result["report"]["stage_epoch"]=10
                    elif phase=="terminal_page" and args["format"]=="names_csv" and (
                            args["offset"]==len(TEXTS["names_csv"])):
                        result["report"]["generation"]=(
                            "00000000-0000-4000-8000-000000000000")
                    return result
                with self.subTest(phase=phase),patch.object(agent,"rpc",api):
                    with self.assertRaises(ValueError):
                        agent.capture_report_set_checkpoint({},output,3)
                    self.assertFalse(output.exists())
                    self.assertGreaterEqual(manifests,1)

    def test_cross_format_mix_bad_length_hash_and_duplicate_generation(self):
        for defect in ("sha","same-generation","extra-key","missing-format",
                       "wrong-path","bool-program-revision"):
            with tempfile.TemporaryDirectory() as work:
                target=Path(work)/"no.json"
                def api(_session,method,args):
                    if method=="analysis.report.manifest":
                        m=initial_manifest()
                        if defect=="sha":
                            m["formats"]["config_csv"]["sha256_utf8"]="b"*64
                        elif defect=="same-generation":
                            m["formats"]["names_csv"]["generation"]=GENERATIONS["markdown"]
                        elif defect=="extra-key":
                            m["source_unverified"]=True
                        elif defect=="missing-format":
                            del m["formats"]["names_csv"]
                        elif defect=="wrong-path":
                            m["program_path"]="/another.bin"
                        elif defect=="bool-program-revision":
                            m["program_revision"]=True
                        return {"manifest":m}
                    return page(args["format"],args["offset"],args["limit"])
                with self.subTest(defect=defect),patch.object(agent,"rpc",api):
                    with self.assertRaises(ValueError):
                        agent.capture_report_set_checkpoint({},target,3)
                    self.assertFalse(target.exists())

    def test_rehashed_fake_apply_and_missing_section_refused_offline(self):
        with tempfile.TemporaryDirectory() as work:
            source=Path(work)/"good.json"
            with patch.object(agent,"rpc",lambda _s,method,args:
                    {"manifest":initial_manifest()} if method=="analysis.report.manifest"
                    else page(args["format"],args["offset"],args["limit"])):
                agent.capture_report_set_checkpoint({},source,3)
            actual=json.loads(source.read_text())
            for field,value in (("apply_authorized",True),
                                ("read_only",False),("complete",False)):
                forged=copy.deepcopy(actual)
                forged["payload"][field]=value
                forged["payload_sha256"]=hashlib.sha256(json.dumps(
                    forged["payload"],sort_keys=True,separators=(",",":"),
                    ensure_ascii=True).encode()).hexdigest()
                candidate=Path(work)/("forged-"+field+".json")
                candidate.write_text(json.dumps(forged))
                with self.subTest(field=field),self.assertRaises(ValueError):
                    agent.verify_report_set_checkpoint(candidate)
            truncated=copy.deepcopy(actual)
            del truncated["payload"]["reports"]["config_csv"]
            out=Path(work)/"truncated.json"
            out.write_text(json.dumps(truncated))
            with self.assertRaises(ValueError):
                agent.verify_report_set_checkpoint(out)
            amended=copy.deepcopy(actual)
            amended["payload"]["reports"]["names_csv"]="tampered"
            out=Path(work)/"tampered.json"
            out.write_text(json.dumps(amended))
            with self.assertRaises(ValueError):
                agent.verify_report_set_checkpoint(out)

if __name__=="__main__":
    unittest.main()
