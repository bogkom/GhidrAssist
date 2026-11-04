#!/usr/bin/env python3
"""Generate a reproducible, stand-alone CPU32/68000 call graph. Synthetic data only."""
from pathlib import Path
import argparse
import hashlib
import json
import struct

BASE=0x100
COUNT=20
SIZE=0x1000
MMIO=[0x00FFFA00,0x00FFFA4C,0x00FFFC00,0x00FFFD00]
# Each node has precisely one JSR; common targets, a cycle, and dead nodes.
EDGES={0:1,1:2,2:3,3:4,4:5,5:2,6:7,7:8,8:9,9:10,
       10:11,11:12,12:13,13:14,14:15,15:16,16:17,17:18,18:19}
# One reachable cycle (2..5), disconnected test branches and MMIO sites.
def generate():
    blob=bytearray(b"\x4e\x71"*(SIZE//2))
    blob[0:8]=struct.pack(">II",0x00FFF7FC,BASE)
    # Image-zero static vector POINTER CANDIDATES: reset-connected,
    # disconnected exact entry and pointer inside a function body.
    for vector,target in ((26,BASE+0x30),(32,BASE+6*0x30),
                          (33,BASE+6*0x30+2)):
        blob[vector*4:vector*4+4]=struct.pack(">I",target)
    sites={}
    for n in range(COUNT):
        entry=BASE+n*0x30
        cursor=entry
        if n in EDGES:
            target=BASE+EDGES[n]*0x30
            blob[cursor:cursor+6]=struct.pack(">HI",0x4EB9,target)
            cursor+=6
        if n in (3,8,13,18):
            mmio=MMIO[(n//5)%len(MMIO)]
            blob[cursor:cursor+8]=struct.pack(">HHI",0x33FC,0x40CA+n,mmio)
            sites[str(n)]={"site":f"{cursor:08x}","target":f"{mmio:08x}",
                            "value":f"{0x40CA+n:04x}","classification":"static_write_candidate"}
            cursor+=8
        blob[cursor:cursor+2]=struct.pack(">H",0x4E75)
    return bytes(blob),sites

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    binary,sites=generate()
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_bytes(binary)
    manifest={"schema":1,"file":a.output.name,"language":"68000:BE:32:CPU32",
              "base":"00000000","reset_pc":"00000100","function_count":COUNT,
              "function_entries":[f"{BASE+i*0x30:08x}" for i in range(COUNT)],
              "calls":[{"from":f"{BASE+i*0x30:08x}",
                        "to":f"{BASE+j*0x30:08x}"} for i,j in sorted(EDGES.items())],
              "mmio":sites,
              "image_zero_vector_candidates":[
                  {"vector":26,"pointer":"00000130","scope":"reset_direct_call_candidate"},
                  {"vector":32,"pointer":"00000220","scope":"outside_bounded_reset_subset"},
                  {"vector":33,"pointer":"00000222","scope":"interior_not_function_entry"}],
              "sha256":hashlib.sha256(binary).hexdigest(),
              "note":"Synthetic static reference model; no runtime/MM/CS claims"}
    a.output.with_suffix(".json").write_text(json.dumps(manifest,indent=2)+"\n")
    print(manifest["sha256"])
if __name__=="__main__":
    main()
