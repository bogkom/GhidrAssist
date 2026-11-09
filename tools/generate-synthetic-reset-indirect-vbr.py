#!/usr/bin/env python3
"""Reproducible CPU32 source-only RESET/indirect JSR/MOVEC fixture."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

SIZE=0x600
def build():
    b=bytearray(b"\x4e\x71"*(SIZE//2))
    b[0:8]=struct.pack(">II",0x00fff7fc,0x100)
    # Reset root -> exact direct function entry at 0x130.
    b[0x100:0x108]=bytes.fromhex("4eb9000001304e75")
    # Conditional source fork. The byte-proven JSR arm cannot
    # statically enter the MOVEC arm without another invocation.
    b[0x130:0x13c]=bytes.fromhex(
        "6612"                # BNE.B 0x144
        "207c00000180"        # MOVEA.L #0x180,A0
        "4e90"                # JSR (A0)
        "600e")              # BRA.B 0x14a
    # 0x13c..0x143 are NOPs, deliberately unreachable.
    b[0x144:0x14c]=bytes.fromhex(
        "4e7b0801"            # MOVEC D0,VBR (CPU32)
        "4e71"                # NOP
        "4e75")              # RTS
    # Source-only candidate to write SIMCR/MM in indirect target.
    b[0x180:0x18a]=bytes.fromhex("33fc40ca00fffa004e75")
    # Disconnected function: byte-proven JSR precedes MOVEC in CFG.
    b[0x200:0x20e]=bytes.fromhex(
        "207c00000180"        # MOVEA.L #0x180,A0
        "4e90"                # JSR (A0)
        "4e7b0801"            # MOVEC D0,VBR
        "4e75")              # RTS
    # Disconnected unresolved computed JSR (A1): no bounded MOVEA proof.
    # It is an omitted/UNKNOWN source, never an absent-call conclusion.
    b[0x240:0x244]=bytes.fromhex("4e914e75")
    return bytes(b)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    data=build()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_bytes(data)
    manifest={
        "schema":1,"fixture":args.output.name,
        "processor":"68000:BE:32:CPU32",
        "reset_pc":"00000100",
        "observed_reset_direct_function":"00000130",
        "reset_subset_indirect_jsr":"00000138",
        "reset_subset_movec":"00000144",
        "disconnected_function":"00000200",
        "disconnected_indirect_jsr":"00000206",
        "disconnected_movec":"00000208",
        "unresolved_indirect_site":"00000240",
        "unresolved_indirect_evidence":"UNKNOWN",
        "indirect_target":"00000180",
        "mmio_source_candidate":"00fffa00",
        "sha256":hashlib.sha256(data).hexdigest(),
        "limit":"Static source candidates, never execution or active VBR/MM"
    }
    args.output.with_suffix(".json").write_text(
        json.dumps(manifest,indent=2,sort_keys=True)+"\n")
    print(manifest["sha256"])

if __name__=="__main__":
    main()
