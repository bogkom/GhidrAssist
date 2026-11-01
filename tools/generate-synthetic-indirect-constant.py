#!/usr/bin/env python3
"""Tiny isolated CPU32 fixture for proven adjacent MOVEA-immediate + JSR (A0)."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

def build():
    blob=bytearray(b"\x4e\x71"*2048)
    blob[:8]=struct.pack(">II",0x00fff7fc,0x100)
    blob[0x100:0x10a]=bytes.fromhex("207c000001304e904e75")
    blob[0x130:0x13a]=bytes.fromhex("33fc40ca00fffa004e75")
    return bytes(blob)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    o=p.parse_args().output
    data=build();o.parent.mkdir(parents=True,exist_ok=True);o.write_bytes(data)
    manifest={"schema":1,"file":o.name,"language":"68000:BE:32:CPU32",
      "reset_pc":"00000100","movea_site":"00000100",
      "indirect_call_site":"00000106","target":"00000130",
      "evidence":"adjacent_movea_immediate","write_site":"00000130",
      "mmio_target":"00fffa00","sha256":hashlib.sha256(data).hexdigest()}
    o.with_suffix(".json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(manifest["sha256"])

if __name__=="__main__": main()
