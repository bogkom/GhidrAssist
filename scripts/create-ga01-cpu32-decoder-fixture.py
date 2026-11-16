#!/usr/bin/env python3
"""Create ONLY the disposable GA-01 CPU32 decoder acceptance input.

This tool never opens or modifies a Ghidra project. The output is a raw
18-byte fixture, not ECU firmware.
"""
import argparse
import hashlib
from pathlib import Path

# MOVE.W #$40CA,($00FFFA00).L; MOVEC D0,VBR; MOVEC VBR,D0; MOVEQ #1,D0
PAYLOAD = bytes.fromhex("33 fc 40 ca 00 ff fa 00 4e 7b 08 01 4e 7a 08 01 70 01")
EXPECTED = ((0x100, "MOVE.W", 8), (0x108, "MOVEC-to-VBR", 4),
            (0x10C, "MOVEC-from-VBR", 4), (0x110, "MOVEQ", 2))


def verify(payload: bytes) -> None:
    assert len(payload) == 18
    position = 0
    for pc, _name, size in EXPECTED:
        assert pc == 0x100 + position
        position += size
    assert position == len(payload)
    assert payload == PAYLOAD, "synthetic fixture bytes changed"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="new disposable .bin file")
    args = parser.parse_args()
    verify(PAYLOAD)
    # Exclusive creation: never overwrite an existing file, especially firmware.
    with args.output.open("xb") as stream:
        stream.write(PAYLOAD)
    print(f"GA18_CPU32_FIXTURE_CREATED path={args.output} bytes={len(PAYLOAD)} "
          f"sha256={hashlib.sha256(PAYLOAD).hexdigest()}")
    for pc, name, size in EXPECTED:
        print(f"  0x{pc:08x} {name} size={size}")


if __name__ == "__main__":
    main()
