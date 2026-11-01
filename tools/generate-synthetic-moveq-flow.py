#!/usr/bin/env python3
"""Isolated CPU32 MOVEQ-safe register-flow fixture; no ECU firmware."""
from pathlib import Path
import argparse, hashlib, struct

def build():
    b=bytearray(b"\x4e\x71"*2048)
    b[:8]=struct.pack(">II",0x00fff7fc,0x1c0)
    b[0x130:0x13a]=bytes.fromhex("33fc40ca00fffa004e75")
    b[0x1c0:0x1ce]=bytes.fromhex("207c0000013070014e714e904e75")
    # MOVEA #130,A0; BNE +2; NOP; JSR (A0); RTS.
    # Conditional branch is a hard barrier, even when a particular path could reach JSR.
    b[0x1f0:0x1fe]=bytes.fromhex("207c0000013066024e714e904e75")
    # MOVEA #130,A0; MOVEQ #1,D0; MOVEA.L D0,A0; JSR (A0); RTS.
    b[0x220:0x22e]=bytes.fromhex("207c00000130700120404e904e75")
    return bytes(b)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();a.output.parent.mkdir(parents=True,exist_ok=True)
    raw=build();a.output.write_bytes(raw)
    print("GA18 MOVEQ FIXTURE SHA256:",hashlib.sha256(raw).hexdigest())
