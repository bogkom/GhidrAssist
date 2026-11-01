#!/usr/bin/env python3
"""Isolated CPU32 unresolved register-indirect JSR fixture; never infer target."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

def build():
    data=bytearray(b"\x4e\x71"*2048)
    data[:8]=struct.pack(">II",0x00FFF7FC,0x100)
    # JSR (A0) has no statically certified target, followed by RTS.
    data[0x100:0x104]=bytes.fromhex("4e904e75")
    # Disconnected writer is intentionally NOT counted as reset-reachable.
    data[0x130:0x13a]=bytes.fromhex("33fc40ca00fffa004e75")
    return bytes(data)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    data=build()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_bytes(data)
    manifest={"schema":1,"file":args.output.name,"language":"68000:BE:32:CPU32",
        "reset_pc":"00000100","entries":["00000100","00000130"],
        "indirect_call_site":"00000100","indirect_instruction":"JSR (A0)",
        "unresolved_calls_from_reset":1,"reachable_from_reset":1,
        "unreachable_writer_site":"00000130","write_target":"00fffa00",
        "expected_reset_paths":0,"expected_complete":False,
        "sha256":hashlib.sha256(data).hexdigest(),
        "evidence":"Unknown indirect target is never inferred or treated as executed"}
    args.output.with_suffix(".json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(manifest["sha256"])

if __name__=="__main__":
    main()
