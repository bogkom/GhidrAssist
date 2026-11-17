#!/usr/bin/env python3
"""Read-only GA-12 recovery selection from immutable synthetic CPU32 checkpoints.

Each run is stored in a UTC-named directory (YYYYMMDDTHHMMSSZ) containing
result.json and evidence.log. Never rewrites evidence or silently falls back.
"""
import argparse
import json
from pathlib import Path
import re
import sys

import importlib.util

spec = importlib.util.spec_from_file_location(
    "ga12_verify", Path(__file__).with_name("verify-ga12-cpu32-checkpoint.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
check = module.check

STAMP = re.compile(r"20[0-9]{6}T[0-9]{6}Z")


def inspect(root, source_sha, allow_prior=False):
    if not root.is_dir() or root.is_symlink():
        raise ValueError("checkpoint root must be a real directory")
    candidates = sorted((p for p in root.iterdir() if STAMP.fullmatch(p.name)),
                        key=lambda p: p.name, reverse=True)
    if not candidates:
        raise ValueError("no UTC-named checkpoints")
    failures = []
    for folder in candidates:
        if folder.is_symlink() or not folder.is_dir():
            reason = "checkpoint directory is not a real directory"
        else:
            result, log = folder / "result.json", folder / "evidence.log"
            if any(p.is_symlink() or not p.is_file() for p in (result, log)):
                reason = "checkpoint files missing or symlinked"
            else:
                try:
                    verdict = check(result, log, source_sha)
                    if verdict == "PASS":
                        return {"status": "RECOVERABLE", "checkpoint": folder.name,
                                "source_sha": source_sha, "skipped": failures}
                    reason = "checkpoint records FAIL"
                except ValueError as exc:
                    reason = str(exc)
        failures.append({"checkpoint": folder.name, "reason": reason})
        if not allow_prior:
            break
    return {"status": "BLOCKED", "source_sha": source_sha, "skipped": failures}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--allow-prior", action="store_true",
                        help="explicitly permit recovery from older valid evidence")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        parser.error("source SHA must be 40 lowercase hexadecimal characters")
    try:
        result = inspect(args.root, args.source_sha, args.allow_prior)
    except (OSError, ValueError) as exc:
        result = {"status": "BLOCKED", "reason": str(exc)}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "RECOVERABLE" else 2


if __name__ == "__main__":
    sys.exit(main())
