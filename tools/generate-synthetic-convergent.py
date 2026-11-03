#!/usr/bin/env python3
"""Isolated deterministic CPU32 fixture: two direct CALL paths converge on one MMIO WRITE."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

ENTRIES=(0x100,0x130,0x160,0x190)
SIZE=4096
WRITE_SITE=0x190
TARGET=0xFFFA00

def build():
    blob=bytearray(b"\x4e\x71"*(SIZE//2))
    blob[:8]=struct.pack(">II",0x00FFF7FC,ENTRIES[0])
    def jsr(site,target):
        blob[site:site+6]=struct.pack(">HI",0x4EB9,target)
    # RESET -> A -> WRITER and RESET -> B -> WRITER.
    jsr(0x100,0x130)
    jsr(0x106,0x160)
    blob[0x10c:0x10e]=bytes.fromhex("4e75")
    jsr(0x130,0x190)
    blob[0x136:0x138]=bytes.fromhex("4e75")
    jsr(0x160,0x190)
    blob[0x166:0x168]=bytes.fromhex("4e75")
    blob[0x190:0x198]=struct.pack(">HHI",0x33FC,0x40CA,TARGET)
    blob[0x198:0x19a]=bytes.fromhex("4e75")
    return bytes(blob)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    data=build()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_bytes(data)
    manifest={
        "schema":1,"file":args.output.name,"language":"68000:BE:32:CPU32",
        "reset_pc":"00000100","size":SIZE,
        "functions":[f"{x:08x}" for x in ENTRIES],
        "calls":[{"site":f"{s:08x}","target":f"{t:08x}"} for s,t in
                 ((0x100,0x130),(0x106,0x160),(0x130,0x190),(0x160,0x190))],
        "writes":[{"site":"00000190","target":"00fffa00","value":"40ca"}],
        "paths":[
            {"functions":["00000100","00000130","00000190"],"call_sites":["00000100","00000130"]},
            {"functions":["00000100","00000160","00000190"],"call_sites":["00000106","00000160"]}
        ],
        "sha256":hashlib.sha256(data).hexdigest(),
        "evidence":"Static synthetic paths; not execution or physical MMIO mapping"
    }
    args.output.with_suffix(".json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(manifest["sha256"])

if __name__=="__main__":
    main()
