"""Source-only contract for GA-12 genuine isolated Ghidra Actions lane."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GenuineWorkflowContract(unittest.TestCase):
    def test_java25_real_headless_lane_is_required(self):
        workflow = (ROOT / ".github/workflows/ga12-isolated-project-copy.yml").read_text()
        self.assertIn("genuine-project-reopen:", workflow)
        self.assertIn("java-version: '25'", workflow)
        self.assertIn("ghidra_12.1.4_PUBLIC_", workflow)
        self.assertIn("bash scripts/ga12-genuine-reopen-smoke.sh", workflow)
        self.assertIn("GA12_GENUINE_REOPEN_PASS", workflow)
        self.assertIn("GA12_CORRUPT_RESTORE_REJECTED", workflow)
        self.assertIn("actions/upload-artifact@v4", workflow)

    def test_persisted_database_annotation_is_seeded_then_verified(self):
        script = (ROOT / "scripts/ga12-genuine-reopen-smoke.sh").read_text()
        witness = (ROOT / "ghidra_scripts/GA12VerifyRestoredProgram.java").read_text()
        self.assertIn("ga12-synthetic.bin seed", script)
        self.assertIn("ga12-synthetic.bin verify", script)
        self.assertIn("GA12_ANALYSIS_SEEDED", script)
        self.assertIn("GA12_ANALYSIS_PERSISTED_PASS", script)
        self.assertIn("GA12_SYNTHETIC_PERSISTED_ANALYSIS_V1", witness)
        self.assertIn("getComment(CodeUnit.PLATE_COMMENT, start)", witness)
        self.assertIn("setComment(start, CodeUnit.PLATE_COMMENT, marker)", witness)
        self.assertIn("persisted annotation missing or changed", witness)

    def test_genuine_harness_reopens_without_import_and_rejects_corruption(self):
        script = (ROOT / "scripts/ga12-genuine-reopen-smoke.sh").read_text()
        self.assertIn("-import", script)
        self.assertIn("-process ga12-synthetic.bin", script)
        self.assertIn("--authorize-isolated-restore", script)
        self.assertIn('test -e "$WORK/should-not-exist"', script)
        self.assertIn("GA12VerifyRestoredProgram.java", script)


if __name__ == "__main__":
    unittest.main()
