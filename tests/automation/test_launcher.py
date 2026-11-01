#!/usr/bin/env python3
"""Launcher contract: syntax, fixed-path option and fail-closed arguments."""
import ast
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
LAUNCHER = ROOT / "tools/ghidrassist-agent-start"
WRAPPER = ROOT / "tools/ga18-wyse-test.sh"


class LauncherContract(unittest.TestCase):
    def test_parses(self):
        ast.parse(LAUNCHER.read_text(encoding="utf-8"))

    def test_native_ghidra_go_dispatch(self):
        code = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn('support/GhidraGo/ghidraGo', code)
        self.assertIn('quote(args.program, safe="/")', code)
        self.assertIn('observed.get("program") != Path(args.program).name', code)
        self.assertIn('session_file.unlink()', code)
        self.assertIn('GHIDRASSIST_AUTOMATION_TOKEN', code)

    def test_wyse_wrapper_pins_synthetic_program(self):
        code = WRAPPER.read_text(encoding="utf-8")
        self.assertIn('--program synthetic-mmio.bin', code)
        self.assertIn('--mode test', code)


if __name__ == "__main__":
    unittest.main()
