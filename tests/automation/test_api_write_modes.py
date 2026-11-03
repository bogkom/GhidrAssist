"""Fail-closed write-mode contract (full Ghidra native CI runs separately)."""
import ast
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]

class WriteModes(unittest.TestCase):
    def test_launcher_mode_is_explicit(self):
        launcher=(ROOT/"tools/ghidrassist-agent-start").read_text()
        ast.parse(launcher)
        self.assertIn('default="read-only"',launcher)
        self.assertIn('choices=("read-only","auto-safe","full-control")',launcher)
        self.assertIn('args.write_mode == "full-control"',launcher)
        self.assertIn('args.write_mode == "auto-safe" and not args.synthetic_writes',launcher)
        self.assertIn('args.synthetic_writes and args.write_mode == "read-only"',launcher)
        self.assertIn("ghidrassist.automation.writeMode=",launcher)

    def test_write_calls_share_policy_and_remain_synthetic(self):
        policy=(ROOT/"src/main/java/ghidrassist/automation/AutomationWritePolicy.java").read_text()
        hw=(ROOT/"src/main/java/ghidrassist/ui/tabs/HardwareAnalysisTab.java").read_text()
        server=(ROOT/"src/main/java/ghidrassist/automation/AutomationServer.java").read_text()
        self.assertIn("READ_ONLY, AUTO_SAFE, FULL_CONTROL",policy)
        self.assertIn('Boolean.getBoolean("ghidrassist.automation.syntheticWrites")',policy)
        self.assertIn('"synthetic-mmio.bin".equals(program.getName())',policy)
        self.assertIn("Production agent writes not enabled",policy)
        self.assertEqual(hw.count("AutomationWritePolicy.requireSyntheticSafe(program)"),3)
        self.assertIn('"production_writes_enabled",false',server)
        self.assertIn('"write_mode",AutomationWritePolicy.mode().name()',server)

if __name__=="__main__":
    unittest.main()
