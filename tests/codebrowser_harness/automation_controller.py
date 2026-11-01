#!/usr/bin/env python3
"""External test-only controller of a live Ghidra Swing Hardware Analysis tab."""
import argparse
import json
import time
from pathlib import Path

def await_file(path, seconds=65):
    deadline=time.monotonic()+seconds
    while time.monotonic()<deadline:
        if path.is_file():
            return path.read_text(encoding="utf-8")
        time.sleep(0.05)
    raise TimeoutError("Missing live Ghidra automation response: "+path.name)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--directory",type=Path,required=True)
    args=parser.parse_args()
    folder=args.directory
    assert await_file(folder/"automation-ready",40)=="hardware-ui-v1"
    (folder/"automation-command.json").write_text(
        json.dumps({"action":"hardware.analyze"}),encoding="utf-8")
    snapshot=json.loads(await_file(folder/"automation-response.json"))
    assert snapshot["schema"]==1
    assert snapshot["action"]=="hardware.analyze"
    assert snapshot["selected_tab"]=="Hardware Analysis"
    assert snapshot["program"]=="synthetic-mmio.bin"
    assert snapshot["mmio_enabled"] is True
    assert snapshot["edt"] is True
    assert isinstance(snapshot["analyze_enabled"],bool)
    assert isinstance(snapshot["review_enabled"],bool)
    assert isinstance(snapshot["status"],str) and snapshot["status"]
    print("PASS: external process controlled real Swing and read live state")

if __name__=="__main__":
    main()
