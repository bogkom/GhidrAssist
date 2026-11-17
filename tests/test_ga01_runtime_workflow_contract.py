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
        valid = "GA01_RUNTIME_DECODER_JAR=" + path + " (GhidraScript)  "
        self.assertEqual(re.findall(pattern, valid, re.M), [path])
        self.assertEqual(re.findall(pattern, "GA01_RUNTIME_DECODER_JAR=" + path, re.M), [path])
        self.assertEqual(re.findall(pattern, valid + "\n" + valid, re.M), [path, path])
        self.assertEqual(re.findall(pattern, "GA01_RUNTIME_DECODER_JAR=\n", re.M), [])

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
