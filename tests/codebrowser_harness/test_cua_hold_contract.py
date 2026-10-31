"""Fail-closed unit contracts for bounded CUA live-window source receipt."""
import copy
import unittest
from run import validate_cua_hold

RUN="a"*32
XID="0x00200013"

def good():
    return {"result":"LIVE_CUA_WINDOW_RELEASED_STRUCTURAL_ONLY",
            "run_id":RUN,"native_cua_verified":False,
            "native_nonce_ack":False,"supervisor_ack":False,
            "formal_gui_pass":False,
            "pre_window_id":XID,"post_window_id":XID,
            "program":"synthetic-mmio.bin","address":"0x00000020",
            "function":"FUN_00000020","decompiler_function":"FUN_00000020",
            "source_run_id_reused":False}

class CuaHoldContracts(unittest.TestCase):
    def test_live_window_release_never_native_ack(self):
        self.assertTrue(validate_cua_hold(good(),{"window_id":XID},RUN))
    def test_missing_or_forged_native_authorization_and_identity_fail_closed(self):
        for field,value in (
            ("native_cua_verified",True),
            ("native_cua_verified",None),
            ("cua_native_verified",True),
            ("native_nonce_ack",True),
            ("supervisor_ack",True),
            ("formal_gui_pass",True),
            ("run_id","b"*32),
            ("pre_window_id","0x00000001"),
            ("post_window_id","0x00000001"),
            ("program","ECU411.bin"),
            ("address","0x00000040"),
            ("function","FUN_00000040"),
            ("decompiler_function","FUN_00000040"),
            ("source_run_id_reused",True)):
            with self.subTest(field=field):
                bad=copy.deepcopy(good())
                bad[field]=value
                if field=="cua_native_verified":
                    # A historical typo/alias must NOT substitute for canonical field.
                    bad.pop("native_cua_verified")
                with self.assertRaisesRegex(RuntimeError,"BLOCKED_CUA_HOLD"):
                    validate_cua_hold(bad,{"window_id":XID},RUN)
    def test_missing_window_identity_fails_closed(self):
        with self.assertRaises(RuntimeError):
            validate_cua_hold(good(),{},RUN)

if __name__=="__main__":
    unittest.main()
