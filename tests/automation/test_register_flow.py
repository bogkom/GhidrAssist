#!/usr/bin/env python3
"""CPU32 bounded-flow fixture opcode and test wiring golden checks."""
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location("ga18_register_fixture",ROOT/"tools/generate-synthetic-register-flow.py")
fixture=importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)

class RegisterFlow(unittest.TestCase):
    def test_exact_bytes_and_disconnected_roots(self):
        b=fixture.build()
        self.assertEqual(len(b),4096)
        self.assertEqual(b[4:8],bytes.fromhex("00000100"))
        self.assertEqual(b[0x100:0x10c],bytes.fromhex("207c000001304e714e904e75"))
        self.assertEqual(b[0x130:0x13a],bytes.fromhex("33fc40ca00fffa004e75"))
        self.assertEqual(b[0x160:0x16c],bytes.fromhex("207c0000013020404e904e75"))
        self.assertEqual(b[0x190:0x19e],bytes.fromhex("207c0000013060024e714e904e75"))

    def test_production_conservative_wiring(self):
        source=(ROOT/"src/main/java/ghidrassist/automation/AutomationCallPaths.java").read_text()
        verifier=(ROOT/"tools/ghidra_scripts/GA18VerifySyntheticRegisterFlow.java").read_text()
        for token in ("boundedConstantRegisterCall", "bounded_movea_nop_chain",
                      "distance<4", "unresolved_call_sites"):
            self.assertIn(token,source)
        self.assertIn("endTransaction(tx,false)",verifier)
        self.assertIn('"bounded_movea_nop_chain"',verifier)
        self.assertIn('new long[]{0x108,0x168,0x19a}',verifier)

if __name__=="__main__":unittest.main()
