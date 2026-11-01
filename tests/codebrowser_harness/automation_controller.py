#!/usr/bin/env python3
"""External sequential command client for a live Ghidra 12.1.4 Swing fixture."""
import argparse
import json
import time
from pathlib import Path


def await_file(path, seconds=65):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.is_file():
            return path.read_text(encoding="utf-8")
        time.sleep(0.05)
    raise TimeoutError("Missing live Ghidra automation response: " + path.name)


def command(folder, sequence, action, **parameters):
    request = {"schema": 2, "sequence": sequence, "action": action, **parameters}
    (folder / f"automation-{sequence}-command.json").write_text(
        json.dumps(request), encoding="utf-8"
    )
    result = json.loads(await_file(folder / f"automation-{sequence}-response.json"))
    assert result["schema"] == 2
    assert result["sequence"] == sequence
    assert result["action"] == action
    assert result["program"] == "synthetic-mmio.bin"
    assert result["edt"] is True
    for key, component in (
        ("run", "hardware.analyze"),
        ("cancelScan", "hardware.cancel"),
        ("approve", "hardware.review"),
        ("exploreMmio", "hardware.mmio"),
    ):
        assert result[key]["id"] == component
        assert isinstance(result[key]["enabled"], bool)
        assert isinstance(result[key]["visible"], bool)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    folder = args.directory
    assert await_file(folder / "automation-ready", 40) == "hardware-ui-v2"
    before = command(folder, 0, "ui.snapshot")
    # The component may already be enabled by tab initialization; do not
    # assume initial disabled state. Observe state rather than invent it.
    analyzed = command(folder, 1, "hardware.analyze")
    assert analyzed["selected_tab"] == "Hardware Analysis"
    assert analyzed["exploreMmio"]["enabled"] is True
    assert analyzed["status"]
    after = command(folder, 2, "ui.snapshot")
    assert after["exploreMmio"]["enabled"] is True
    navigated = command(folder, 3, "listing.goto", address="0x20")
    assert int(navigated["listing_address"], 16) == 0x20
    listed = command(folder, 4, "listing.snapshot")
    assert int(listed["listing_address"], 16) == 0x20
    print("PASS: external v2 Swing snapshots, Hardware Analyze, Listing navigation")


if __name__ == "__main__":
    main()
