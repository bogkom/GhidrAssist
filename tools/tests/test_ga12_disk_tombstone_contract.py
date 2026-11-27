"""GA-12 source boundary regression: explicit clear must fence durable restore.

This contract complements the real Ghidra restart tests; it does not claim
execution of the plugin or substitute for the exact-head Java 25 build.
"""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src/main/java/ghidrassist/hardware/HardwareFlowStageCache.java"

class DiskTombstonePublicationContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = SOURCE.read_text(encoding="utf-8")

    def test_clear_always_sets_tombstone_after_invalidating(self):
        clear = self.code.split("public static void clear(Program program)", 1)[1]
        self.assertRegex(clear, r"EPOCHS\.invalidate\(program\);[\s\S]*?SKIP_DISK\.put\(program,true\);")

    def test_memory_publication_does_not_release_disk_tombstone(self):
        code = self.code
        start = code.index("COMPLETED.put(program,checkpoint);")
        finish = code.index("if(directory!=null && analysisInputKey!=null", start)
        self.assertNotIn("SKIP_DISK.remove(program)", code[start:finish])

    def test_only_successful_durable_save_releases_tombstone_inside_fence(self):
        code = self.code
        start = code.index("final boolean[] saved={false};")
        end = code.index("if(saved[0])SKIP_DISK.remove(program);", start)
        fenced = code[start:end]
        self.assertIn("EPOCHS.publishIfCurrent(program,computationEpoch", fenced)
        self.assertIn("saved[0]=HardwareDurableStageStore.saveIfSameSource(", fenced)
        self.assertIn("throw new CancelledException();", fenced)
        self.assertIn("synchronized(COMPLETED)", code[code.rfind("synchronized(COMPLETED)", 0, start):start+1])
        self.assertEqual(code.count("SKIP_DISK.remove(program)"), 1)
        self.assertNotRegex(code, r"(?m)^\s*SKIP_DISK\.remove\(program\);")

    def test_failed_save_is_best_effort_without_releasing_tombstone(self):
        code = self.code
        self.assertIn("catch(IOException|IllegalArgumentException skip)", code)
        self.assertIn("if(saved[0])SKIP_DISK.remove(program);", code)
        self.assertIn("if(beforeWrite!=null)", code)

if __name__ == "__main__":
    unittest.main()
