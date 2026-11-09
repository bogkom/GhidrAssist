#!/usr/bin/env python3
"""Byte-exact isolated CPU32 branching CFG fixture; no user firmware."""
from pathlib import Path
import argparse
import hashlib
import json
import struct

SIZE = 0x400
# Valid 68k/CPU32 instruction encodings, explicit byte-level regression:
# BNE.s +6, NOP, BRA.s +4, dead NOP, NOP, RTS
DIAMOND = (0x6606, 0x4e71, 0x6004, 0x4e71, 0x4e71, 0x4e75)
# NOP, BNE.s +4, NOP, BRA.s -6, RTS
LOOP = (0x4e71, 0x6604, 0x4e71, 0x60fa, 0x4e75)
LINEAR = (0x4e71, 0x4e71, 0x4e75)
# JMP (A0) followed by unreachable NOP/RTS (unknown computed control)
COMPUTED = (0x4ed0, 0x4e71, 0x4e75)


def generate():
    data = bytearray(b"\x4e\x71" * (SIZE // 2))
    for entry, words in ((0x100, DIAMOND), (0x140, LOOP),
                         (0x180, LINEAR), (0x1c0, COMPUTED)):
        for i, word in enumerate(words):
            struct.pack_into(">H", data, entry + 2 * i, word)
    return bytes(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    data = generate()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(data)
    manifest = {
        "schema": 1,
        "fixture": "synthetic-cfg-routes.bin",
        "processor": "68000:BE:32:CPU32",
        "sha256": hashlib.sha256(data).hexdigest(),
        "entrypoints": ["0x00000100", "0x00000140",
                        "0x00000180", "0x000001c0"],
        "evidence": "CPU32 Listing CFG only; never firmware execution",
    }
    args.output.with_suffix(".json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(manifest["sha256"])


if __name__ == "__main__":
    main()
