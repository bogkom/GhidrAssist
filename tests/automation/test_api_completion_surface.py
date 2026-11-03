"""Source and CLI contracts; production Java compilation is gated separately by Ghidra 12.1.4 CI."""
import ast
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]

class ApiCompletion(unittest.TestCase):
    def test_cli_is_valid_and_exposes_actions(self):
        path=ROOT/"tools/ghidrassist-agent"
        ast.parse(path.read_text())
        content=path.read_text()
        for cmd in ("tab-select","table-select","cancel","report","export"):
            self.assertIn('"'+cmd+'"',content)

    def test_rpc_dispatch_and_edts(self):
        server=(ROOT/"src/main/java/ghidrassist/automation/AutomationServer.java").read_text()
        ui=(ROOT/"src/main/java/ghidrassist/ui/GhidrAssistUI.java").read_text()
        hw=(ROOT/"src/main/java/ghidrassist/ui/tabs/HardwareAnalysisTab.java").read_text()
        for name in ("ui.tab.select","ui.table.select","hardware.cancel","analysis.report","analysis.export"):
            self.assertIn('"'+name+'"',server)
        self.assertIn("automationSelectTab",ui)
        self.assertIn("automationSelectTableRow",ui)
        self.assertIn("automationMmioTable.setRowSelectionInterval",hw)
        self.assertIn("tabbedPane.isEnabledAt(i)",ui)
        self.assertIn("cancelScan.doClick()",hw)
        self.assertIn("currentScan()",hw)
        self.assertIn("limit>8192",hw)
        self.assertIn("content.substring(start,end)",hw)
        self.assertIn("No cancellable Analyze task",hw)
        # READY receipt write is deliberate; export RPC must not write files.
        export_branch=server.split('"analysis.report".equals(method)')[1].split('"hardware.profile.select".equals(method)')[0]
        self.assertNotIn("Files.writeString",export_branch)

if __name__=="__main__":unittest.main()
