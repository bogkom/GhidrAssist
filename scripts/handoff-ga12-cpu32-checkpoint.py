#!/usr/bin/env python3
"""GA-12 fail-closed, read-only recovery handoff from verified CPU32 evidence.

Does not replay Apply or restore a Ghidra project. Revalidates the selected
checkpoint immediately before issuing a digest-bound handoff manifest.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ga12_recover", HERE / "recover-ga12-cpu32-checkpoint.py")
recover = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recover)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def handoff(root, source_sha, allow_prior=False):
    selection = recover.inspect(root, source_sha, allow_prior)
    if selection["status"] != "RECOVERABLE":
        return selection
    folder = root / selection["checkpoint"]
    if folder.is_symlink() or not folder.is_dir():
        return {"status": "BLOCKED", "reason": "selected checkpoint directory changed"}
    paths = {"result": folder / "result.json", "log": folder / "evidence.log"}
    for key, path in paths.items():
        if path.is_symlink() or not path.is_file():
            return {"status": "BLOCKED", "reason": key + " artifact changed"}
        if digest(path) != selection[key + "_sha256"]:
            return {"status": "BLOCKED", "reason": key + " digest changed"}
    # Repeat semantic verification after digest checks: a hash alone is not acceptance.
    verifier_spec = importlib.util.spec_from_file_location("ga12_verify_handoff", HERE / "verify-ga12-cpu32-checkpoint.py")
    verifier = importlib.util.module_from_spec(verifier_spec)
    verifier_spec.loader.exec_module(verifier)
    try:
        if verifier.check(paths["result"], paths["log"], source_sha) != "PASS":
            return {"status": "BLOCKED", "reason": "checkpoint no longer passes verification"}
    except (ValueError, OSError) as exc:
        return {"status": "BLOCKED", "reason": str(exc)}
    return {"status": "HANDOFF_READY", "checkpoint": selection["checkpoint"],
            "source_sha": source_sha, "result_sha256": selection["result_sha256"],
            "log_sha256": selection["log_sha256"], "skipped": selection["skipped"],
            "evidence_class": "STATIC_SYNTHETIC_HEADLESS",
            "project_restore_authorized": False, "apply_replay_authorized": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--allow-prior", action="store_true")
    args = p.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        p.error("source SHA must be 40 lowercase hexadecimal characters")
    try:
        output = handoff(args.root, args.source_sha, args.allow_prior)
    except (OSError, ValueError) as exc:
        output = {"status": "BLOCKED", "reason": str(exc)}
    print(json.dumps(output, sort_keys=True))
    return 0 if output["status"] == "HANDOFF_READY" else 2


if __name__ == "__main__":
    sys.exit(main())
