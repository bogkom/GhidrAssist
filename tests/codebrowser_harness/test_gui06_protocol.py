"""Deterministic fail-closed GUI-06 READY/bridge linking negative tests."""
import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from assertion_audit import png_info
from gui06_protocol import verify, reserve_run, CASE, PROGRAM, ADDRESS, FUNCTION, CLASS, TITLE
from test_assertion_audit import AssertionsAuditTest


RUN="a"*32
XID="0x04000026"


class Gui06ProtocolTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.png=AssertionsAuditTest.fixture_image if hasattr(
            AssertionsAuditTest,"fixture_image") else None
        from test_assertion_audit import fixture_image
        cls.png=fixture_image()

    def setUp(self):
        f=AssertionsAuditTest("test_structurally_consistent_but_not_formally_trusted")
        f.setUp()
        self.receipt=copy.deepcopy(f.receipt)
        self.receipt.update(run_id=RUN,case_id=CASE,
                            window_id=XID,window_class=CLASS,window_title=TITLE)
        self.receipt["pre_capture_epoch_ms"]=1000
        self.receipt["capture_start_epoch_ms"]=1100
        self.receipt["capture_end_epoch_ms"]=1200
        self.receipt["post_capture_epoch_ms"]=1400
        self.ready=dict(run_id=RUN,case_id=CASE,window_id=XID,
                        window_title=TITLE,window_class=CLASS,program=PROGRAM,
                        address=ADDRESS,function=FUNCTION,
                        decompiler_function=FUNCTION,pre_capture_epoch_ms=1000)
        self.bridge=dict(
            run_id=RUN,case_id=CASE,window_id=XID,window_title=TITLE,
            wm_class=CLASS,source="host-owned-readonly-x11",applied=True,
            result="HOST_SYNTHETIC_X11_CAPTURED_PROVENANCE_PENDING",
            identity_before_after_capture=True,
            captured_screenshot_sha256=hashlib.sha256(self.png).hexdigest(),
            screenshot_width=640,screenshot_height=400,
            capture_start_epoch_ms=1150,capture_end_epoch_ms=1180,
            visual_readback_verified=False,native_nonce_ack=False,
            supervisor_ack=False,formal_gui_pass=False,
            trusted_ghidra_provenance_verified=False,
            same_run_semantics_verified=False)

    def check(self,*,ready=None,receipt=None,bridge=None,png=None,run=RUN):
        return verify(self.ready if ready is None else ready,
                      self.receipt if receipt is None else receipt,
                      self.bridge if bridge is None else bridge,
                      self.png if png is None else png,run)

    def bad(self,kind,field,value):
        obj=copy.deepcopy(getattr(self,kind))
        obj[field]=value
        with self.assertRaises(ValueError):
            self.check(**{kind:obj})

    def test_valid_structural_only(self):
        self.assertTrue(self.check()["structurally_correlated"])
        self.assertFalse(self.check()["formal_gui_pass"])

    def test_changed_xid(self):
        self.bad("bridge","window_id","0x04000027")

    def test_wrong_program(self):
        self.bad("ready","program","guard-other.bin")

    def test_wrong_address(self):
        self.bad("receipt","address","0x00000024")

    def test_wrong_listing_function(self):
        self.bad("receipt","function","FUN_00000024")

    def test_changed_window_during_capture(self):
        self.bad("bridge","identity_before_after_capture",False)

    def test_wrong_window_title(self):
        self.bad("bridge","window_title",TITLE+" forged")

    def test_wrong_window_class(self):
        self.bad("ready","window_class","ghidra-Ghidra.ghidra-Ghidra")

    def test_wrong_run(self):
        self.bad("bridge","run_id","b"*32)

    def test_wrong_sha(self):
        self.bad("bridge","captured_screenshot_sha256","f"*64)

    def test_missing_screenshot(self):
        with self.assertRaises(ValueError):
            self.check(png=b"")

    def test_mutated_png(self):
        with self.assertRaises(ValueError):
            self.check(png=self.png[:-1]+b"z")

    def test_capture_outside_window(self):
        self.bad("bridge","capture_start_epoch_ms",1450)

    def test_timeout_or_no_report(self):
        with self.assertRaises(ValueError):
            self.check(bridge={})

    def test_stale_listing(self):
        self.receipt["post_capture"]["address"]="0x00000024"
        with self.assertRaises(ValueError):
            self.check()

    def test_forged_native_ack(self):
        self.bad("bridge","native_nonce_ack",True)

    def test_reused_run_id_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"evidence").mkdir()
            created=reserve_run(root,RUN)
            self.assertEqual(created.name,"pilot-ghidra-"+RUN)
            with self.assertRaises(ValueError):
                reserve_run(root,RUN)

    def test_bridge_path_reuse_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            evidence=root/"evidence"
            evidence.mkdir()
            (evidence/("pilot-x11-"+RUN)).mkdir()
            with self.assertRaises(ValueError):
                reserve_run(root,RUN)


if __name__=="__main__":
    unittest.main()
