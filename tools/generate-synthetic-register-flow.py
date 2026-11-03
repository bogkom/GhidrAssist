#!/usr/bin/env python3
"""Isolated 4-function CPU32 bounded MOVEA / NOP / clobber / branch fixture."""
import argparse, hashlib, json, struct
from pathlib import Path

def build():
    d=bytearray(b"\x4e\x71"*2048)
    d[:8]=struct.pack(">II",0x00fff7fc,0x100)
    d[0x100:0x10c]=bytes.fromhex("207c000001304e714e904e75") # MOVEA #130; NOP; JSR (A0); RTS
    d[0x130:0x13a]=bytes.fromhex("33fc40ca00fffa004e75") # writer
    d[0x160:0x16c]=bytes.fromhex("207c0000013020404e904e75") # MOVEA D0,A0 invalidates prior
    d[0x190:0x19e]=bytes.fromhex("207c0000013060024e714e904e75") # branch barrier
    return bytes(d)

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    o=p.parse_args().output
    b=build();o.parent.mkdir(parents=True,exist_ok=True);o.write_bytes(b)
    m={"schema":1,"file":o.name,"language":"68000:BE:32:CPU32",
       "entries":["00000100","00000130","00000160","00000190"],
       "positive_call_site":"00000108","clobbered_call_site":"00000168",
       "branch_call_site":"0000019a","writer":"00000130",
       "sha256":hashlib.sha256(b).hexdigest(),"evidence":"static only"}
    o.with_suffix(".json").write_text(json.dumps(m,indent=2)+"\n")
    print(m["sha256"])

if __name__=="__main__":main()
