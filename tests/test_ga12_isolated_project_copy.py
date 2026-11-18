"""Positive and negative offline GA-12 project copy tests (no Ghidra runtime)."""
import importlib.util
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "ga12-isolated-project-copy.py"
spec = importlib.util.spec_from_file_location("ga12_copy", SCRIPT)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ProjectCopyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "synthetic-project"
        self.project.mkdir()
        (self.project / "synthetic.gpr").write_bytes(b"fixture")
        (self.project / "synthetic.rep").mkdir()
        (self.project / "synthetic.rep" / "data").write_bytes(b"program-state")
        self.snapshot = self.root / "snapshot"
        self.restored = self.root / "restored"

    def make_snapshot(self):
        mod.copy_new(self.project, self.snapshot, True)

    def test_roundtrip_and_digest(self):
        self.make_snapshot()
        self.assertEqual(len(mod.validate_manifest(self.snapshot)["files"]), 2)
        mod.copy_new(self.snapshot, self.restored, False)
        self.assertEqual(mod.inventory(self.project), mod.inventory(self.restored))
        self.assertFalse((self.restored / mod.MANIFEST).exists())

    def test_refuse_overwrite(self):
        self.make_snapshot()
        with self.assertRaisesRegex(ValueError, "already exists"):
            mod.copy_new(self.project, self.snapshot, True)

    def test_refuse_modified_snapshot(self):
        self.make_snapshot()
        (self.snapshot / "synthetic.rep" / "data").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "differ"):
            mod.validate_manifest(self.snapshot)
        with self.assertRaisesRegex(ValueError, "differ"):
            mod.copy_new(self.snapshot, self.restored, False)
        self.assertFalse(self.restored.exists())

    def test_refuse_symlink(self):
        (self.project / "alias").symlink_to(self.project / "synthetic.gpr")
        with self.assertRaisesRegex(ValueError, "symlinks"):
            mod.copy_new(self.project, self.snapshot, True)
        self.assertFalse(self.snapshot.exists())

    def test_refuse_nested_destination(self):
        with self.assertRaisesRegex(ValueError, "inside source"):
            mod.copy_new(self.project, self.project / "snapshot", True)

    def test_refuse_missing_manifest(self):
        with self.assertRaisesRegex(ValueError, "manifest"):
            mod.validate_manifest(self.project)

    def test_refuse_extra_file(self):
        self.make_snapshot()
        (self.snapshot / "unexpected").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "differ"):
            mod.validate_manifest(self.snapshot)

    def test_refuse_non_ghidra_folder(self):
        (self.project / "synthetic.gpr").unlink()
        with self.assertRaisesRegex(ValueError, "exactly one Ghidra"):
            self.make_snapshot()
        self.assertFalse(self.snapshot.exists())

    def test_refuse_unpaired_repository(self):
        (self.project / "synthetic.rep").rename(self.project / "other.rep")
        with self.assertRaisesRegex(ValueError, "matching Ghidra"):
            self.make_snapshot()
        self.assertFalse(self.snapshot.exists())

    def test_refuse_multiple_projects(self):
        (self.project / "other.gpr").write_bytes(b"another")
        with self.assertRaisesRegex(ValueError, "exactly one Ghidra"):
            self.make_snapshot()
        self.assertFalse(self.snapshot.exists())

    def test_refuse_snapshot_with_broken_project_pair_even_if_manifest_matches(self):
        self.make_snapshot()
        (self.snapshot / "synthetic.rep").rename(self.snapshot / "other.rep")
        manifest_path = self.snapshot / mod.MANIFEST
        import json
        manifest = json.loads(manifest_path.read_text())
        for item in manifest["files"]:
            item["path"] = item["path"].replace("synthetic.rep/", "other.rep/")
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "matching Ghidra"):
            mod.validate_manifest(self.snapshot)

    def test_refuse_restore_without_authorization(self):
        # CLI must reject restore even if snapshot is valid.
        import subprocess
        self.make_snapshot()
        run = subprocess.run(["python3", str(SCRIPT), "restore", "--source",
                              str(self.snapshot), "--destination", str(self.restored)],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertIn("authorization", run.stdout)
        self.assertFalse(self.restored.exists())


    def run_cli(self, action, source, destination=None, authorize=False):
        import json
        import subprocess
        import sys
        command = [sys.executable, str(SCRIPT), action, "--source", str(source)]
        if destination is not None:
            command += ["--destination", str(destination)]
        if authorize:
            command.append("--authorize-isolated-restore")
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        self.assertEqual(result.stderr, "")
        return result.returncode, json.loads(result.stdout)

    def test_cli_snapshot_verify_authorized_restore_end_to_end(self):
        code, result = self.run_cli("snapshot", self.project, self.snapshot)
        self.assertEqual((code, result["status"]), (0, "SNAPSHOT_CREATED"))
        code, result = self.run_cli("verify", self.snapshot)
        self.assertEqual((code, result["status"], result["files"]), (0, "VERIFIED", 2))
        code, result = self.run_cli("restore", self.snapshot, self.restored, True)
        self.assertEqual((code, result["status"]), (0, "RESTORED_OFFLINE_COPY"))
        self.assertIs(result["apply_replay_authorized"], False)
        self.assertEqual(mod.inventory(self.project), mod.inventory(self.restored))
        self.assertFalse((self.restored / mod.MANIFEST).exists())

    def test_cli_rejects_tampered_snapshot_without_partial_restore(self):
        self.make_snapshot()
        (self.snapshot / "synthetic.rep" / "data").write_bytes(b"changed")
        code, result = self.run_cli("restore", self.snapshot, self.restored, True)
        self.assertEqual((code, result["status"]), (2, "BLOCKED"))
        self.assertFalse(self.restored.exists())

    def test_cli_rejects_existing_restore_target(self):
        self.make_snapshot()
        self.restored.mkdir()
        (self.restored / "sentinel").write_bytes(b"preserve")
        code, result = self.run_cli("restore", self.snapshot, self.restored, True)
        self.assertEqual((code, result["status"]), (2, "BLOCKED"))
        self.assertEqual((self.restored / "sentinel").read_bytes(), b"preserve")

    def test_cli_rejects_manifest_symlink_and_preserves_destination(self):
        self.make_snapshot()
        manifest = self.snapshot / mod.MANIFEST
        manifest.rename(self.snapshot / "manifest-original")
        manifest.symlink_to(self.snapshot / "manifest-original")
        code, result = self.run_cli("restore", self.snapshot, self.restored, True)
        self.assertEqual((code, result["status"]), (2, "BLOCKED"))
        self.assertFalse(self.restored.exists())


    def test_genuine_reopen_harness_requires_second_program_witness(self):
        # Source contract only; this does NOT execute Ghidra.
        harness = (SCRIPT.parent / "ga12-genuine-reopen-smoke.sh").read_text()
        witness = (SCRIPT.parents[1] / "ghidra_scripts" /
                   "GA12VerifyRestoredProgram.java").read_text()
        self.assertIn("-process ga12-synthetic.bin", harness)
        self.assertIn("GA12_GENUINE_REOPEN_PASS", harness)
        self.assertIn("GA12_CORRUPT_RESTORE_REJECTED", harness)
        self.assertIn("GA12_NEGATIVE_FAIL: rejected restore created a destination", harness)
        self.assertIn("--authorize-isolated-restore", harness)
        self.assertGreaterEqual(harness.count("grep -q 'GA12_REOPEN_PASS'"), 2)
        self.assertIn("currentProgram.getMemory().getSize() != 6", witness)
        self.assertIn("68000:BE:32:CPU32", witness)
        self.assertIn("java.util.Arrays.equals(actual, expected)", witness)
        self.assertIn("fixture=4e714e714e75", witness)
        self.assertIn("GA12_REOPEN_PASS", witness)
        self.assertNotIn(" -import ", harness.split("# Open the restored project")[1])

if __name__ == "__main__":
    unittest.main()
