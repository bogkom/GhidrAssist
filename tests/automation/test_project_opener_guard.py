"""Regression contract for the dangerous recursive CodeBrowser launcher bug."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]

class ProjectOpenerRecursion(unittest.TestCase):
    def test_application_frontend_only_and_once(self):
        source=(ROOT/"src/main/java/ghidrassist/automation/AgentProjectOpenPlugin.java").read_text()
        self.assertIn("implements ApplicationLevelOnlyPlugin",source)
        self.assertIn("tool instanceof FrontEndTool",source)
        self.assertIn("AtomicBoolean OPEN_REQUEST_CONSUMED",source)
        self.assertIn("OPEN_REQUEST_CONSUMED.compareAndSet(false,true)",source)
        self.assertIn("poller.stop();",source)

    def test_real_codebrowser_negative_probe(self):
        native=(ROOT/"tests/codebrowser_harness/CodeBrowserMmioMain.java").read_text()
        runner=(ROOT/"tests/codebrowser_harness/run.py").read_text()
        self.assertIn("new ghidrassist.automation.AgentProjectOpenPlugin(tool[0])",native)
        self.assertIn("Recursive CodeBrowser opener armed",native)
        self.assertIn("agent_opener_codebrowser_recursion_blocked",native)
        self.assertIn('"agent_opener_codebrowser_recursion_blocked"',runner)

if __name__=="__main__":unittest.main()
