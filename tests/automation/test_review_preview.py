#!/usr/bin/env python3
"""Read-only Review API source contracts; real 12.1.4 compile runs separately."""
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TAB = ROOT / "src/main/java/ghidrassist/ui/tabs/HardwareAnalysisTab.java"
SERVER = ROOT / "src/main/java/ghidrassist/automation/AutomationServer.java"
CLI = ROOT / "tools/ghidrassist-agent"


class ReviewPreviewContracts(unittest.TestCase):
    def test_no_mutating_apply_path(self):
        code = TAB.read_text(encoding="utf-8")
        snippet = code.split("public com.google.gson.JsonObject automationReviewPreview(", 1)[1].split(
            "/** A bounded, revision-checked snapshot", 1)[0]
        self.assertIn("!currentScan()", snippet)
        self.assertIn("!latestConcrete", snippet)
        self.assertIn("HardwareApplyService.preflight", snippet)
        self.assertIn("if (!currentScan())", snippet)
        self.assertNotIn("HardwareApplyService.apply(", snippet)
        self.assertNotIn("JOptionPane", snippet)
        self.assertIn("limit>100", snippet)

    def test_profile_selection_is_exact_and_nonmutating(self):
        tab = TAB.read_text(encoding="utf-8")
        server = SERVER.read_text(encoding="utf-8")
        cli = CLI.read_text(encoding="utf-8")
        self.assertIn('"CPU32_SURVEY".equals(profile)', tab)
        self.assertIn('"MC68332_USER_SELECTED".equals(profile)', tab)
        self.assertIn("selection.setSelectedIndex(index)", tab)
        self.assertIn('"hardware.profile.select".equals(method)', server)
        self.assertIn('"profile-select": "hardware.profile.select"', cli)

    def test_readonly_rpc_and_cli(self):
        server = SERVER.read_text(encoding="utf-8")
        cli = CLI.read_text(encoding="utf-8")
        self.assertIn('"hardware.review.preview".equals(method)', server)
        self.assertIn('automationReviewPreview(offset,limit)', server)
        self.assertIn('"review-preview": "hardware.review.preview"', cli)
        self.assertNotIn('"hardware.review.apply".equals(method)', server)


if __name__ == "__main__":
    unittest.main()
