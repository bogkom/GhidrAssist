"""Regression contract for the dangerous recursive CodeBrowser launcher bug."""
from pathlib import Path
import unittest
import importlib.machinery
import importlib.util
import tempfile
import zipfile

ROOT=Path(__file__).resolve().parents[2]

class ProjectOpenerRecursion(unittest.TestCase):
    def test_application_frontend_only_and_once(self):
        source=(ROOT/"src/main/java/ghidrassist/automation/AgentProjectOpenPlugin.java").read_text()
        self.assertIn("implements ApplicationLevelOnlyPlugin",source)
        self.assertIn("tool instanceof FrontEndTool",source)
        self.assertIn("AtomicBoolean OPEN_REQUEST_CONSUMED",source)
        self.assertIn("OPEN_REQUEST_CONSUMED.compareAndSet(false,true)",source)
        self.assertIn("poller.stop();",source)

    def test_launcher_rejects_old_installed_jar_without_spawning(self):
        spec=importlib.util.spec_from_loader("ga18_launcher",
            importlib.machinery.SourceFileLoader("ga18_launcher",
                str(ROOT/"tools/ghidrassist-agent-start")))
        launcher=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(launcher)
        with tempfile.TemporaryDirectory() as work:
            settings=Path(work)
            jar=settings/"namok-ghidra"/"ghidra_12.1.4_PUBLIC"/"Extensions"/"GhidrAssist"/"lib"/"GhidrAssist.jar"
            jar.parent.mkdir(parents=True)
            env={"JAVA_TOOL_OPTIONS":"-Dapplication.settingsdir="+str(settings)}
            with zipfile.ZipFile(jar,"w") as z:
                z.writestr("ghidrassist/automation/AgentProjectOpenPlugin.class",
                    b"ApplicationLevelPlugin")
            with self.assertRaisesRegex(ValueError,"UNSAFE installed GhidrAssist"):
                launcher.verify_patched_project_opener(env)
            with zipfile.ZipFile(jar,"w") as z:
                z.writestr("ghidrassist/automation/AgentProjectOpenPlugin.class",
                    b"ApplicationLevelOnlyPlugin FrontEndTool OPEN_REQUEST_CONSUMED")
            self.assertEqual(launcher.verify_patched_project_opener(env),jar)

    def test_real_codebrowser_negative_probe(self):
        native=(ROOT/"tests/codebrowser_harness/CodeBrowserMmioMain.java").read_text()
        runner=(ROOT/"tests/codebrowser_harness/run.py").read_text()
        self.assertIn("new ghidrassist.automation.AgentProjectOpenPlugin(tool[0])",native)
        self.assertIn("Recursive CodeBrowser opener armed",native)
        self.assertIn("agent_opener_codebrowser_recursion_blocked",native)
        self.assertIn('"agent_opener_codebrowser_recursion_blocked"',runner)

if __name__=="__main__":unittest.main()
