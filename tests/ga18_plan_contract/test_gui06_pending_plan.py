"""Offline Supervisor v1 plan contract checks, no GUI, no worker."""
import copy, json, re, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
NEW=ROOT/"docs/ga18-gui06-native-listing-required-pending-plan-20261031.json"
OLD=ROOT/"docs/ga18-gui06-listing-required-pending-plan.json"
ID="ga18-gui06-native-ack-pr101-20261031"; COMMIT="21b17626a629bf6d999fcd5e250475814b32700e"; ARCHIVE="975d3c538b83e6c68000c2176206ac9347e3b9098842da6b1375e059a4d6fb2d"
PNG="e67a128dd02309c1d6419f191221bfcb7226089902f9959a4a24385144b16792"; THREAD="01a19077-0c74-7192-a782-d8f36da8b2fd"; RUN="786766dad08141dda989ae5b2cab6131"
def validate(p):
    assert type(p) is dict and p["schema"]==1 and p["kind"]=="codex-supervisor-test-plan"
    assert re.fullmatch(r"[A-Za-z0-9_-]{1,64}",p["plan_id"]) and p["plan_id"]==ID
    assert p["execution_capability"]=="LISTING_REQUIRED" and p["requires_gui"] is True
    assert p["depends_on"]==[] and type(p["queue_priority"]) is int and 1<=p["queue_priority"]<=300
    t=p["target"]; a=t["artifact"]
    assert t["repository"]=="bogkom/GhidrAssist" and t["mode"]=="artifact" and t["commit"]==COMMIT
    assert re.fullmatch("[a-f0-9]{40}",t["commit"])
    assert a=={"run_id":41186284329,"id":13036804816,"name":"GhidrAssist-CodeBrowser-12.1.4-41186284329","sha256":ARCHIVE}
    auth=p["authorization"]
    assert set(auth)=={"policy","tracks","permissions","network","sudo","secrets","source_code_edits","publish_private_data","workspace"}
    assert auth["policy"]=="ghidrassist-18-track-v1" and auth["workspace"]=="dedicated"
    assert auth["tracks"]==["GA-09","GA-17","GA-18"]
    assert auth["permissions"]==["run-ghidra-gui","run-ghidra-headless","install-test-extension","write-test-project","write-test-files"]
    assert all(auth[k] is False for k in ("network","sudo","secrets","source_code_edits","publish_private_data"))
    assert len(p["steps"])==1
    s=p["steps"][0]; outs=s["outputs"]; cs=s["checks"]
    assert re.fullmatch(r"[A-Za-z0-9_-]{1,64}",s["id"]) and 1<=len(s["instruction"])<=2550
    for mark in ("UNPUBLISHED","STOP","AFTER","nonce","no new","run_id"):
        assert mark.lower() in s["instruction"].lower()
    assert len(outs)==3 and len(set(outs))==3
    assert all(x.startswith("reports/"+ID+"-") and ".." not in x and chr(92) not in x for x in outs)
    assert len(cs)==20 and all(c["path"]==outs[0] for c in cs)
    actual={}; bindings=[]
    for c in cs:
        if c["type"]=="json_field_equals":
            assert set(c)=={"type","path","key","value"} and c["key"].isidentifier()
            assert type(c["value"]) in (str,int,float,bool) and c["key"] not in actual
            actual[c["key"]]=c["value"]
        elif c["type"]=="json_sha256_matches":
            assert set(c)=={"type","path","file","key"} and c["file"]==outs[1] and c["key"]=="host_screenshot_sha256"
            bindings.append(c)
        else:raise AssertionError("Unsupported check")
    expected={"passed":True,"target_commit":COMMIT,"artifact_sha256":ARCHIVE,
        "native_thread_id":THREAD,"native_goal_identity_verified":True,
        "native_handoff_verified":True,"approval_present":True,"workflow_present":True,
        "native_turn_completed":True,"native_nonce_ack":True,"supervisor_ack":True,
        "window_identity_verified":True,"screenshot_sha256_verified":True,
        "visual_readback_verified":True,"codebrowser_listing_verified":True,
        "original_run_id":RUN,"host_screenshot_sha256":PNG,
        "formal_gui_pass":False,"synthetic_only":True}
    assert actual==expected and len(bindings)==1
    assert {"passed","window_identity_verified","screenshot_sha256_verified","visual_readback_verified","codebrowser_listing_verified"} <= {k for k,v in actual.items() if v is True}
    assert "report_published" not in actual
    return True

class Contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.p=json.loads(NEW.read_text())
        cls.old=json.loads(OLD.read_text())
    def test_schema(self):self.assertTrue(validate(copy.deepcopy(self.p)))
    def test_historical_pins(self):
        self.assertEqual(self.old["target"]["commit"],"5ba0d788ed029caec644e6aefb31dd52e6f4b908")
        self.assertEqual(self.old["target"]["artifact"]["id"],13034627639)
        self.assertNotEqual(self.old["plan_id"],ID)
        self.assertNotIn("test-plans/queue/",str(NEW))
    def test_negative_mutations(self):
        for keys,val in [
          (("execution_capability",),"HEADLESS_SAFE"),(("requires_gui",),False),
          (("target","commit"),"f"*40),(("target","artifact","sha256"),"f"*64),
          (("authorization","sudo"),True),(("authorization","permissions"),["run-ghidra-headless"]),
          (("steps",0,"checks",0,"value"),False),
          (("steps",0,"checks",9,"value"),False),
          (("steps",0,"checks",17,"value"),True),
          (("steps",0,"checks",19,"file"),"reports/fake.png")]:
            with self.subTest(keys=keys):
                p=copy.deepcopy(self.p); o=p
                for k in keys[:-1]:o=o[k]
                o[keys[-1]]=val
                with self.assertRaises((AssertionError,KeyError,TypeError)):validate(p)
    def test_no_secrets_or_status_laundering(self):
        source=NEW.read_text()
        self.assertNotIn("/home/",source)
        self.assertNotIn("nonce_value",source)
        self.assertNotIn('"report_published"',source)
        self.assertEqual(len(PNG),64)
if __name__=="__main__":unittest.main()
