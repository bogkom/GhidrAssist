"""Guard the real-Ghidra workflow's embedded Python and evidence uploader."""
import pathlib
import re
import unittest

WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / ".github/workflows/hardware-vector-reset-correlation.yml"

class WorkflowContract(unittest.TestCase):
    def test_inline_python_is_syntactically_complete(self):
        lines = WORKFLOW.read_text().splitlines()
        blocks = []
        for i, line in enumerate(lines):
            if line.strip().endswith("python3 - <<'PY'"):
                body = []
                for next_line in lines[i + 1:]:
                    if next_line == "          PY":
                        break
                    if not next_line.startswith("          "):
                        self.fail("Python heredoc escaped YAML run block")
                    body.append(next_line[10:])
                else:
                    self.fail("Unterminated Python heredoc")
                blocks.append("\n".join(body))
        self.assertGreaterEqual(len(blocks), 3)
        for block in blocks:
            compile(block, "<workflow-inline-python>", "exec")

    def test_runtime_witness_parses_ghidra_log_padding_without_accepting_duplicates(self):
        workflow = WORKFLOW.read_text()
        match = re.search(r"matches = re\.findall\((.+?), log, re\.M\)", workflow)
        self.assertIsNotNone(match)
        expression = match.group(1)
        # This is the same literal regex expression executed by the CI heredoc.
        import ast
        pattern = ast.literal_eval(expression)
        path = "/tmp/isolated/GhidrAssist/lib/GhidrAssist.jar"
        valid = "INFO  GA18VerifyDecodedEffectSites.java> GA01_RUNTIME_DECODER_JAR=" + path + " (GhidraScript)  "
        self.assertEqual(re.findall(pattern, valid, re.M), [path])
        self.assertEqual(re.findall(pattern, "GA18VerifyDecodedEffectSites.java> GA01_RUNTIME_DECODER_JAR=" + path, re.M), [path])
        self.assertEqual(re.findall(pattern, valid + "\n" + valid, re.M), [path, path])
        self.assertEqual(re.findall(pattern, "INFO    GA18VerifyDecodedEffectSites.java> GA01_RUNTIME_DECODER_JAR=" + path + " (GhidraScript)", re.M), [path])
        self.assertEqual(re.findall(pattern, "INFO  GA18VerifyDecodedEffectSites.java> GA01_RUNTIME_DECODER_JAR=" + path + " (GhidraScript) extra", re.M), [])
        self.assertEqual(re.findall(pattern, "GA18VerifyDecodedEffectSites.java> GA01_RUNTIME_DECODER_JAR=\n", re.M), [])
        self.assertEqual(re.findall(pattern, "GA01_RUNTIME_DECODER_JAR=" + path, re.M), [])
        self.assertEqual(re.findall(pattern, "INFO  Unrelated.java> GA01_RUNTIME_DECODER_JAR=" + path, re.M), [])

    def test_provenance_step_is_complete_and_uploader_is_outside_python(self):
        text = WORKFLOW.read_text()
        step = text.split("      - name: Verify runtime decoder class came from exact installed extension", 1)[1]
        script, uploader = step.split("      - name: Preserve genuine Ghidra evidence even on failure", 1)
        self.assertEqual(script.count("python3 - <<'PY'"), 1)
        self.assertEqual(script.count("\n          PY\n"), 1)
        self.assertNotIn("actions/upload-artifact", script)
        self.assertEqual(uploader.count("uses: actions/upload-artifact@v4"), 1)
        self.assertEqual(text.count("      - name: Preserve genuine Ghidra evidence even on failure"), 1)
        self.assertNotIn("matches = re.findall", uploader)
        self.assertNotIn("raise SystemExit", uploader)
        self.assertNotIn("          PY", uploader)
        self.assertEqual(text.count("GA01_RUNTIME_CLASS_ORIGIN_PASS"), 1)

    def test_uploader_is_final_workflow_step_without_stray_tail(self):
        text = WORKFLOW.read_text()
        uploader = text.split("      - name: Preserve genuine Ghidra evidence even on failure", 1)[1]
        self.assertTrue(uploader.rstrip().endswith("if-no-files-found: warn"))
        self.assertEqual(uploader.count("if-no-files-found: warn"), 1)
        # An unindented Python fragment after the uploader invalidates workflow YAML.
        self.assertTrue(all(line.startswith("          ") or not line.strip()
                            for line in uploader.splitlines()
                            if line.strip().startswith(("if-no-files-found:", "path:", "${{"))))

    def test_runtime_provenance_and_failure_artifact(self):
        text = WORKFLOW.read_text()
        self.assertEqual(text.count("GA01_RUNTIME_CLASS_ORIGIN_PASS"), 1)
        self.assertEqual(text.count("name: Preserve genuine Ghidra evidence even on failure"), 1)
        self.assertIn("if: always()", text)
        self.assertIn("GA01_RUNTIME_DECODER_JAR=", text)
        self.assertIn("loaded.is_relative_to(install)", text)
        self.assertIn("HardwareGhidraEffectSiteDecoder.class", text)

if __name__ == "__main__":
    unittest.main()
