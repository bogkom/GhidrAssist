#!/usr/bin/env python3
"""Deterministic synthetic CPU32 graph golden checks; no Ghidra needed."""
import hashlib
import importlib.util
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[2]
GEN=ROOT/"tools/generate-synthetic-callgraph.py"
spec=importlib.util.spec_from_file_location("fixture_gen",GEN)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class Fixture(unittest.TestCase):
    def test_script_is_fixture_only(self):
        code=(ROOT/"tools/ghidra_scripts/GA18BootstrapSyntheticCallgraph.py").read_text()
        self.assertIn('p.getName() != "synthetic-callgraph.bin"',code)
        self.assertIn('68000:BE:32:CPU32',code)
        self.assertIn('range(20)',code)
        self.assertIn('endTransaction(tx, success)',code)

    def test_determinism_and_separation(self):
        first,sites=module.generate()
        second,again=module.generate()
        self.assertEqual(first,second)
        self.assertEqual(sites,again)
        self.assertEqual(len(first),0x1000)
        self.assertEqual(first[4:8],bytes.fromhex("00000100"))
        self.assertEqual(len(sites),4)
        self.assertEqual(len(module.EDGES),19)
        self.assertEqual(module.EDGES[5],2)
        self.assertEqual(len(hashlib.sha256(first).hexdigest()),64)
        self.assertNotIn(b"ECU_FLASH",first)
    def test_encoded_calls_and_mmio(self):
        binary,_=module.generate()
        for origin,target in module.EDGES.items():
            at=module.BASE+origin*0x30
            self.assertEqual(binary[at:at+2],bytes.fromhex("4eb9"))
            self.assertEqual(int.from_bytes(binary[at+2:at+6],"big"),
                             module.BASE+target*0x30)
        for n in (3,8,13,18):
            at=module.BASE+n*0x30+6
            self.assertEqual(binary[at:at+2],bytes.fromhex("33fc"))

if __name__=="__main__":
    unittest.main()
