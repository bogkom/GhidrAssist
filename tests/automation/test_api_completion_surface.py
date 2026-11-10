"""Source and CLI contracts; production Java compilation is gated separately by Ghidra 12.1.4 CI."""
import ast
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]

class ApiCompletion(unittest.TestCase):
    def test_cli_is_valid_and_exposes_actions(self):
        path=ROOT/"tools/ghidrassist-agent"
        ast.parse(path.read_text())
        content=path.read_text()
        for cmd in ("tab-select","table-select","program-open","cancel","report","export"):
            self.assertIn('"'+cmd+'"',content)

    def test_decompiler_status_binds_active_program_and_task(self):
        source=(ROOT/"src/main/java/ghidrassist/automation/AutomationDecompiler.java").read_text()
        server=(ROOT/"src/main/java/ghidrassist/automation/AutomationServer.java").read_text()
        cli=(ROOT/"tools/ghidrassist-agent").read_text()
        ast.parse(cli)
        self.assertIn("status(Program activeProgram, String expectedTaskId,",source)
        self.assertIn("activeProgram!=source",source)
        self.assertIn("Decompiler task_id mismatch",source)
        self.assertIn('result.addProperty("state","STALE")',source)
        self.assertIn("decompiler.status(program,taskId,offset,limit)",server)
        self.assertIn('"task_id": args.task_id',cli)
        self.assertIn('parser.add_argument("--task-id"',cli)

    def test_listing_instruction_evidence_is_read_only_and_bounded(self):
        listing=(ROOT/"src/main/java/ghidrassist/automation/AutomationListing.java").read_text()
        server=(ROOT/"src/main/java/ghidrassist/automation/AutomationServer.java").read_text()
        self.assertIn("AutomationListing.snapshot(program,loc)",server)
        self.assertIn('result.add("listing",listing)',server)
        self.assertIn('result.addProperty("address",listing.get("address").getAsString())',server)
        self.assertIn("getInstructionContaining",listing)
        self.assertIn("getReferencesFrom()",listing)
        self.assertIn("MAX_REFERENCES = 16",listing)
        self.assertIn("MAX_BYTES = 32",listing)
        self.assertIn("location.getProgram() != program",listing)

    def test_listing_range_and_body_xref_contract(self):
        listing=(ROOT/"src/main/java/ghidrassist/automation/AutomationListing.java").read_text()
        body=(ROOT/"src/main/java/ghidrassist/automation/AutomationFunctionXrefs.java").read_text()
        server=(ROOT/"src/main/java/ghidrassist/automation/AutomationServer.java").read_text()
        cli=(ROOT/"tools/ghidrassist-agent").read_text()
        ast.parse(cli)
        self.assertIn("JsonObject range(Program program",listing)
        self.assertIn("limit>64",listing)
        self.assertIn("Listing revision mismatch",listing)
        self.assertIn("Subsequent Listing page requires explicit start and revision",listing)
        self.assertIn("Subsequent Listing page requires explicit start address and Program revision",server)
        self.assertIn("new ProgramLocation(program,instruction.getAddress())",listing)
        self.assertIn("getReferenceDestinationIterator(function.getBody(),true)",body)
        self.assertIn("getReferenceSourceIterator(function.getBody(),true)",body)
        self.assertIn("Body XREF revision mismatch",body)
        self.assertIn("Active function changed during body XREF pagination",body)
        self.assertIn('"listing.range".equals(method)',server)
        self.assertIn('"function.xrefs.body".equals(method)',server)
        self.assertIn('"listing-range"',cli)
        self.assertIn('"function-xrefs-body"',cli)
        self.assertIn('parser.add_argument("--expected-revision"',cli)

    def test_later_listing_page_requires_original_address_and_revision(self):
        """Reject moving-UI-cursor pagination before attempting any RPC."""
        cli=ROOT/"tools/ghidrassist-agent"
        cases=[
            (["listing-range","--offset","4","--expected-revision","7"],
             "no explicit anchor, even with unchanged revision"),
            (["listing-range","00000100","--offset","4"],
             "no original revision, even with explicit start"),
            (["listing-range"," ","--offset","4","--expected-revision","7"],
             "blank start cannot anchor pages"),
        ]
        for args,why in cases:
            with self.subTest(why=why):
                completed=subprocess.run(
                    [sys.executable,str(cli),*args],capture_output=True,
                    text=True,check=False)
                self.assertEqual(2,completed.returncode)
                self.assertIn(
                    "nonzero offset requires an explicit first-page start address "
                    "and --expected-revision",completed.stderr)

    def test_rpc_dispatch_and_edts(self):
        server=(ROOT/"src/main/java/ghidrassist/automation/AutomationServer.java").read_text()
        ui=(ROOT/"src/main/java/ghidrassist/ui/GhidrAssistUI.java").read_text()
        hw=(ROOT/"src/main/java/ghidrassist/ui/tabs/HardwareAnalysisTab.java").read_text()
        for name in ("ui.tab.select","ui.table.select","project.program.open","hardware.cancel","analysis.report","analysis.export"):
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
        self.assertIn("ghidrassist.automation.allowProgramSwitch",server)
        self.assertIn("Save or revert existing program edits before switching",server)
        # READY receipt write is deliberate; export RPC must not write files.
        export_branch=server.split('"analysis.report".equals(method)')[1].split('"hardware.profile.select".equals(method)')[0]
        self.assertNotIn("Files.writeString",export_branch)

if __name__=="__main__":unittest.main()
