"""Deterministic CI test for a cross-process partially written CUA ready JSON."""
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest

from ci_cua_observer import read_complete_ready


class CompleteCuaReadyTest(unittest.TestCase):
    def test_waits_for_finished_other_process_document(self):
        with tempfile.TemporaryDirectory() as directory:
            ready=Path(directory)/"cua-live-ready.json"
            def write_partially():
                ready.write_text('{"action":',encoding="utf-8")
                time.sleep(.22)
                ready.write_text(json.dumps({
                    "action":"GA18_NATIVE_CUA_LIVE_READY",
                    "run_id":"a"*32}),encoding="utf-8")
            writer=threading.Thread(target=write_partially)
            writer.start()
            try:
                obj=read_complete_ready(ready,time.monotonic()+2)
                self.assertEqual(obj["action"],"GA18_NATIVE_CUA_LIVE_READY")
                self.assertEqual(obj["run_id"],"a"*32)
            finally:
                writer.join(timeout=2)

    def test_never_promotes_permanently_partial_document(self):
        with tempfile.TemporaryDirectory() as directory:
            ready=Path(directory)/"cua-live-ready.json"
            ready.write_text('{"action":',encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError,
                    "NO_COMPLETE_LIVE_CUA_READY"):
                read_complete_ready(ready,time.monotonic()+.12)

    def test_rejects_complete_wrong_type(self):
        with tempfile.TemporaryDirectory() as directory:
            ready=Path(directory)/"cua-live-ready.json"
            ready.write_text('[]',encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError,"INVALID_LIVE_CUA_READY"):
                read_complete_ready(ready,time.monotonic()+1)


if __name__=="__main__":
    unittest.main()
