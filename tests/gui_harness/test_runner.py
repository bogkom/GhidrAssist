"""Pure-Python negative regressions. No Ghidra, GUI or external connection."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from runner import (digest, fixture_binary, output_directory,
                    verify_extension, verify_outcome, x11_capture, stop_owned)
from controlled_llm import ControlledLLM


class IsolatedHarnessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def archive(self, entries):
        p = self.root / "extension.zip"
        with zipfile.ZipFile(p, "w") as out:
            for name, body in entries.items():
                out.writestr(name, body)
        return p

    def test_zip_requires_exact_version_and_safe_paths(self):
        props = "name=GhidrAssist\nversion=12.1.4\n"
        good = self.archive({"GhidrAssist/extension.properties": props,
                             "GhidrAssist/lib/GhidrAssist.jar": "test"})
        target = self.root / "extensions"
        verify_extension(good, target)
        self.assertTrue((target / "GhidrAssist/extension.properties").exists())
        for name, body in [
            ("GhidrAssist/../outside", "evil"),
            ("GhidrAssist\\other", "bad"),
            ("/GhidrAssist/absolute", "bad"),
            ("GhidrAssist/extension.properties", "version=12.1.3\n"),
        ]:
            entries = {"GhidrAssist/extension.properties": props}
            entries[name] = body
            bad = self.archive(entries)
            with self.assertRaises(RuntimeError):
                verify_extension(bad, self.root / "not-extracted")

    def test_synthetic_fixture_and_digest(self):
        binary = self.root / "TEST_BINARY.bin"
        fixture_binary(binary)
        self.assertEqual(binary.stat().st_size, 256)
        self.assertEqual(binary.read_bytes()[:8],
                         bytes.fromhex("0000100000000020"))
        self.assertEqual(digest(binary),
                         hashlib.sha256(binary.read_bytes()).hexdigest())

    def test_output_must_not_erase_or_follow_symlink(self):
        path = self.root / "output"
        path.mkdir()
        (path / "user.txt").write_text("retain")
        with self.assertRaises(RuntimeError):
            output_directory(str(path))
        self.assertEqual((path / "user.txt").read_text(), "retain")
        link = self.root / "linked"
        link.symlink_to(path, target_is_directory=True)
        with self.assertRaises(RuntimeError):
            output_directory(str(link))
        fresh = self.root / "fresh"
        self.assertEqual(output_directory(str(fresh)), fresh)

    def test_result_does_not_claim_x11_or_visual_from_swing(self):
        out = self.root
        evidence = {"mode": "smoke", "application_headless": False,
                    "awt_headless": False, "window_showing": True,
                    "query_showing": True, "ran_on_edt": True,
                    "program_open": True, "swing_render": True}
        (out / "gui-results.json").write_text(json.dumps(evidence))
        self.assertTrue(verify_outcome(out, "smoke")["swing_checked"])
        evidence["query_showing"] = False
        (out / "gui-results.json").write_text(json.dumps(evidence))
        with self.assertRaisesRegex(RuntimeError, "query_showing"):
            verify_outcome(out, "smoke")

    def test_policy_mode_requires_all_execution_journals(self):
        cases = {name: {"journal": [{"state": state} for state in expected],
                        "window_showing": True, "edt": True}
                 for name, expected in {
                    "GUI_ALLOW": ["REJECTED"],
                    "GUI_ASYNC": ["SUCCEEDED", "SUCCEEDED"],
                    "GUI_ALIAS_BUDGET": ["SUCCEEDED", "REJECTED"],
                    "GUI_STATIC_DUP": ["SUCCEEDED", "REJECTED"]}.items()}
        evidence = {"mode": "policy", "application_headless": False,
                    "awt_headless": False,
                    "window_showing": True, "query_showing": True,
                    "ran_on_edt": True, "program_open": True,
                    "swing_render": True, "cases": cases}
        evidence.update({key: True for key in (
            "policy_editor_detached", "narrow_toolbar_unclipped",
            "conversation_new_reset", "conversation_switch_reset",
            "cancel_plan_retains_settings", "narrow_status_wrapped")})
        (self.root / "gui-results.json").write_text(json.dumps(evidence))
        self.assertEqual(verify_outcome(self.root, "policy")["policy_cases_checked"], 4)
        cases["GUI_ALLOW"]["journal"] = []
        (self.root / "gui-results.json").write_text(json.dumps(evidence))
        with self.assertRaisesRegex(RuntimeError, "GUI_ALLOW"):
            verify_outcome(self.root, "policy")

    def test_fake_model_rejects_unapproved_case_without_network(self):
        with ControlledLLM(self.root) as model:
            with self.assertRaisesRegex(ValueError, "Unapproved"):
                model.respond({"model": "real-api-model", "messages": []})
            answer = model.respond({"model": "GUI_ALLOW", "messages": []})
            self.assertIn("configured", str(answer))
        self.assertNotIn("body", (self.root / "controlled-model-events.json").read_text())

    def test_cleanup_of_process_group_even_if_launcher_exited(self):
        from types import SimpleNamespace
        import signal
        launcher = SimpleNamespace(
            pid=34567, poll=lambda: 0, wait=lambda timeout: 0)
        with mock.patch("runner.os.killpg") as kill:
            stop_owned(launcher)
        self.assertEqual(kill.call_args_list, [
            mock.call(34567, signal.SIGTERM),
            mock.call(34567, signal.SIGKILL),
        ], "an exited launcher may still have orphan Java descendants")

    def test_x11_rejects_untrusted_newline_title(self):
        (self.root / "gui-results.json").write_text(json.dumps({
            "window_title": "GhidrAssist isolated GUI regression: "
                            "GuiFixture:/TEST_BINARY.bin" + chr(10) + "Injected"}))
        with mock.patch("runner.shutil.which", return_value="/fixture/tool"):
            status = x11_capture(self.root)
        self.assertEqual(status["status"], "BLOCKED_X11_READBACK")
        self.assertIn("title", status["reason"])

    def test_x11_selects_one_largest_mapped_fixture_not_whole_desktop(self):
        (self.root / "gui-results.json").write_text(json.dumps({"window_title": "GhidrAssist isolated GUI regression: GuiFixture:/TEST_BINARY.bin"}))
        from types import SimpleNamespace
        tree = '''
  0x1 "Project - GhidrAssist isolated GUI regression": (200x120+0+0)
    0x2 "GhidrAssist isolated GUI regression: GuiFixture:/TEST_BINARY.bin": (1200x950+0+0)
  0x3 "Unrelated user window": (1900x900+0+0)
'''
        seen = []
        def fake_run(command, **kwargs):
            seen.append(command)
            if command[:3] == ["xwininfo", "-root", "-tree"]:
                return SimpleNamespace(stdout=tree)
            if command[:2] == ["xwininfo", "-id"]:
                return SimpleNamespace(stdout=("Map State: IsViewable\n"
                    + ("Width: 200\nHeight: 120\n" if command[2] == "0x1"
                       else "Width: 1200\nHeight: 950\n")))
            if command[0] == "import":
                Path(command[-1]).write_bytes(b"test-only-image" * 200)
                return SimpleNamespace(stdout="")
            if command[0] == "identify":
                return SimpleNamespace(stdout="1200 950 120")
            raise AssertionError("Unexpected external command")
        with mock.patch("runner.shutil.which", return_value="/fixture/tool"), \
             mock.patch("runner.subprocess.run", side_effect=fake_run):
            x11 = x11_capture(self.root)
        self.assertEqual(x11["status"], "X11_CAPTURED_NONBLANK_PIXEL_CHECKED")
        self.assertEqual(x11["human_visual_readback"], "NOT_PERFORMED")
        self.assertTrue(any(call[:4] == ["import", "-silent", "-window", "0x2"]
                            for call in seen))
        self.assertFalse(any("0x3" in call for call in seen))

    def test_x11_rejects_large_but_unpainted_window(self):
        (self.root / "gui-results.json").write_text(json.dumps({"window_title": "GhidrAssist isolated GUI regression: GuiFixture:/TEST_BINARY.bin"}))
        from types import SimpleNamespace
        def fake_run(command, **kwargs):
            if command[:3] == ["xwininfo", "-root", "-tree"]:
                return SimpleNamespace(stdout=(
                    '  0x9 "GhidrAssist isolated GUI regression: GuiFixture:/TEST_BINARY.bin": (...)\\n'
                ).replace("\\n", "\n"))
            if command[:2] == ["xwininfo", "-id"]:
                return SimpleNamespace(stdout="Map State: IsViewable\n"
                                       "Width: 1200\nHeight: 950\n")
            if command[0] == "import":
                Path(command[-1]).write_bytes(b"black" * 500)
                return SimpleNamespace(stdout="")
            if command[0] == "identify":
                return SimpleNamespace(stdout="1200 950 2")
            raise AssertionError("Unexpected external command")
        with mock.patch("runner.shutil.which", return_value="/fixture/tool"), \
             mock.patch("runner.subprocess.run", side_effect=fake_run):
            result = x11_capture(self.root)
        self.assertEqual(result["status"], "BLOCKED_X11_READBACK")
        self.assertEqual(result["human_visual_readback"], "NOT_PERFORMED")
        self.assertIn("unpainted", result["reason"])

    def test_x11_rejects_ambiguous_equally_sized_frames(self):
        (self.root / "gui-results.json").write_text(json.dumps({"window_title": "GhidrAssist isolated GUI regression: GuiFixture:/TEST_BINARY.bin"}))
        from types import SimpleNamespace
        tree = ('  0x1 "GhidrAssist isolated GUI regression: GuiFixture:/TEST_BINARY.bin": (...)\\n'
                '  0x2 "GhidrAssist isolated GUI regression: GuiFixture:/TEST_BINARY.bin": (...)\\n')
        def fake_run(command, **kwargs):
            if command[:3] == ["xwininfo", "-root", "-tree"]:
                return SimpleNamespace(stdout=tree.replace("\\n", "\n"))
            if command[:2] == ["xwininfo", "-id"]:
                return SimpleNamespace(stdout="Map State: IsViewable\n"
                                       "Width: 1200\nHeight: 950\n")
            raise AssertionError("Should not capture ambiguous X11 frames")
        with mock.patch("runner.shutil.which", return_value="/fixture/tool"), \
             mock.patch("runner.subprocess.run", side_effect=fake_run):
            result = x11_capture(self.root)
        self.assertEqual(result["status"], "BLOCKED_X11_READBACK")
        self.assertEqual(result["human_visual_readback"], "NOT_PERFORMED")

    def test_x11_cannot_be_inferred_from_swing_bitmap(self):
        # Invalid DISPLAY or missing tools never turns into a visual PASS.
        with mock.patch("runner.shutil.which", return_value=None):
            status = x11_capture(self.root)
        self.assertEqual(status["human_visual_readback"], "NOT_PERFORMED")
        self.assertTrue(status["status"].startswith("BLOCKED"))


if __name__ == "__main__":
    unittest.main()
