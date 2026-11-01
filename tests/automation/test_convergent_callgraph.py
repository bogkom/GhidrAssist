"""Convergent CPU32 fixture golden bytes and manifest; no Ghidra or private firmware."""
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[2]
SCRIPT=ROOT/"tools/generate-synthetic-convergent.py"
spec=importlib.util.spec_from_file_location("ga18_convergent",SCRIPT)
generator=importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)

class Convergent(unittest.TestCase):
    def test_golden_fixture(self):
        data=generator.build()
        self.assertEqual(len(data),4096)
        self.assertEqual(data[:8],bytes.fromhex("00fff7fc00000100"))
        for site,target in [(0x100,0x130),(0x106,0x160),(0x130,0x190),(0x160,0x190)]:
            self.assertEqual(data[site:site+6],b"\x4e\xb9"+target.to_bytes(4,"big"))
        self.assertEqual(data[0x190:0x198],bytes.fromhex("33fc40ca00fffa00"))
        self.assertEqual(data[0x198:0x19a],bytes.fromhex("4e75"))
        self.assertEqual(len(hashlib.sha256(data).hexdigest()),64)

    def test_java_guard_and_real_product_call(self):
        bootstrap=(ROOT/"tools/ghidra_scripts/GA18BootstrapSyntheticConvergent.java").read_text()
        verifier=(ROOT/"tools/ghidra_scripts/GA18VerifySyntheticConvergent.java").read_text()
        self.assertIn('synthetic-convergent.bin',bootstrap)
        self.assertIn('endTransaction(tx,commit)',bootstrap)
        self.assertIn('synthetic-convergent.bin',verifier)
        self.assertIn('AutomationCallPaths',verifier)
        self.assertNotIn('startTransaction(',verifier)

if __name__=="__main__":
    unittest.main()
