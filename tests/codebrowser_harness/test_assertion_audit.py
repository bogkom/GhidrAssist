"""Negative fail-closed receipt regressions; no X11 or Ghidra installation needed."""
import copy
import hashlib
import json
import struct
import unittest
import zlib
from assertion_audit import validate, EvidenceError, sha256


def png_chunk(kind,payload):
    return (struct.pack(">I",len(payload))+kind+payload+
            struct.pack(">I",zlib.crc32(kind+payload)&0xffffffff))


def fixture_image():
    # This is fake TEST DATA ONLY for verifier negatives, never GUI proof.
    header=png_chunk(b"IHDR",struct.pack(">IIBBBBB",640,400,8,2,0,0,0))
    rows=[]
    for i in range(400):
        seed=hashlib.sha256(str(i).encode()).digest()
        rows.append(b"\0"+(seed*60)[:640*3])
    data=png_chunk(b"IDAT",zlib.compress(b"".join(rows),1))
    return b"\x89PNG\r\n\x1a\n"+header+data+png_chunk(b"IEND",b"")


class AssertionsAuditTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image=fixture_image()
        cls.expected=dict(case_id="synthetic-test-001",run_id="test-run-001")

    def setUp(self):
        snap=dict(program="synthetic-mmio.bin",address="0x00000020",
                  function="FUN_00000020",
                  decompiler_function="FUN_00000020",
                  observed_epoch_ms=100)
        self.receipt=dict(
            schema=1,kind="ga18-codebrowser-listing-assertions",
            case_id="synthetic-test-001",run_id="test-run-001",
            source_kind="ghidra-inprocess-codebrowser",
            window_id="0x01234567",
            window_class="ghidra-Ghidra.ghidra-Ghidra",
            window_title="GhidrAssist isolated CodeBrowser MMIO",
            program=snap["program"],address=snap["address"],
            function=snap["function"],decompiler_function=snap["decompiler_function"],
            listing_verified=True,decompiler_verified=True,
            image_sha256=sha256(self.image),image_width=640,image_height=400,
            pre_capture_epoch_ms=100,capture_start_epoch_ms=110,
            capture_end_epoch_ms=120,post_capture_epoch_ms=130,
            pre_capture=snap,post_capture={**snap,"observed_epoch_ms":130},
            inprocess_consistency_verified=True,
            trusted_ghidra_provenance_verified=False,
            same_run_semantics_verified=False,independent_visual_readback=False,
            visual_readback_verified=False,supervisor_ack=False,
            native_nonce_ack=False,formal_gui_pass=False)

    def passed(self,receipt=None,image=None):
        return validate(self.receipt if receipt is None else receipt,
                        self.image if image is None else image,**self.expected)

    def fail(self,mutate):
        altered=copy.deepcopy(self.receipt)
        mutate(altered)
        with self.assertRaises(EvidenceError):
            self.passed(altered)

    def test_structurally_consistent_but_not_formally_trusted(self):
        self.assertTrue(self.passed()["structural_evidence_consistent"])
        self.assertFalse(self.passed()["formal_gui_pass"])

    def test_wrong_program(self):
        self.fail(lambda r:r.update(program="owner-private.bin"))

    def test_wrong_address(self):
        self.fail(lambda r:r.update(address="0x00000024"))

    def test_wrong_function(self):
        self.fail(lambda r:r.update(function="FUN_00000024"))

    def test_decompiler_mismatch(self):
        self.fail(lambda r:r.update(decompiler_function="FUN_00000024"))

    def test_stale_listing_after_capture(self):
        self.fail(lambda r:r["post_capture"].update(address="0x00000024"))

    def test_stale_program_before_capture(self):
        self.fail(lambda r:r["pre_capture"].update(program="guard-other.bin"))

    def test_bad_png_digest(self):
        self.fail(lambda r:r.update(image_sha256="f"*64))

    def test_changed_png_with_old_digest(self):
        corrupted=bytearray(self.image)
        corrupted[-12]^=0x01
        with self.assertRaises(EvidenceError):
            self.passed(image=bytes(corrupted))

    def test_truncated_png(self):
        with self.assertRaises(EvidenceError):
            self.passed(image=self.image[:-4])

    def test_wrong_png_dimensions(self):
        self.fail(lambda r:r.update(image_width=700))

    def test_unearned_formal_pass(self):
        self.fail(lambda r:r.update(formal_gui_pass=True))

    def test_unearned_ack(self):
        self.fail(lambda r:r.update(supervisor_ack=True))

    def test_unearned_provenance(self):
        self.fail(lambda r:r.update(trusted_ghidra_provenance_verified=True))

    def test_wrong_xid(self):
        self.fail(lambda r:r.update(window_id="garbage"))

    def test_wrong_class(self):
        self.fail(lambda r:r.update(window_class="unknown"))

    def test_wrong_title(self):
        self.fail(lambda r:r.update(window_title="not the tool window"))

    def test_stale_time_order(self):
        self.fail(lambda r:r.update(post_capture_epoch_ms=101))

    def test_missing_report_field(self):
        self.fail(lambda r:r.pop("post_capture",None))

    def test_wrong_run_identity(self):
        self.fail(lambda r:r.update(run_id="different-test-run"))

    def test_claimed_listing_false(self):
        self.fail(lambda r:r.update(listing_verified=False))


if __name__=="__main__":
    unittest.main()
