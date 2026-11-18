#!/usr/bin/env python3
"""GA-12 offline snapshot and restore of a CLOSED, disposable Ghidra project directory.

Never restores into an existing directory, never replays Apply, and never opens
Ghidra. The caller must ensure the project is closed and isolated.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

MANIFEST = "ga12-project-manifest.json"
MAX_FILES = 100000
MAX_BYTES = 2 * 1024 ** 3


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def inventory(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("project must be a real directory")
    files = []
    total = 0
    for base, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            p = Path(base) / name
            if p.is_symlink():
                raise ValueError("symlinks are forbidden")
        for name in names:
            p = Path(base) / name
            if not p.is_file():
                raise ValueError("nonregular project file")
            relative = p.relative_to(root).as_posix()
            if relative == MANIFEST:
                raise ValueError("reserved manifest filename")
            size = p.stat().st_size
            total += size
            if len(files) >= MAX_FILES or total > MAX_BYTES:
                raise ValueError("project exceeds snapshot bounds")
            files.append({"path": relative, "size": size, "sha256": sha256(p)})
    return sorted(files, key=lambda item: item["path"])


def validate_manifest(root):
    path = root / MANIFEST
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing or symlinked manifest")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if set(manifest) != {"schema", "evidence_class", "files"} or manifest["schema"] != 1:
        raise ValueError("invalid manifest schema")
    if manifest["evidence_class"] != "OFFLINE_ISOLATED_PROJECT_COPY":
        raise ValueError("invalid evidence classification")
    actual = inventory_without_manifest(root)
    if actual != manifest["files"]:
        raise ValueError("snapshot contents differ from manifest")
    return manifest


def inventory_without_manifest(root):
    # Inventory treats the manifest as metadata rather than a project file.
    if root.is_symlink() or not root.is_dir():
        raise ValueError("snapshot must be a real directory")
    manifest = root / MANIFEST
    if manifest.is_symlink():
        raise ValueError("symlinked manifest")
    temp = []
    total = 0
    for base, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            if (Path(base) / name).is_symlink():
                raise ValueError("symlinks are forbidden")
        for name in names:
            p = Path(base) / name
            rel = p.relative_to(root).as_posix()
            if rel == MANIFEST:
                continue
            if not p.is_file():
                raise ValueError("nonregular snapshot file")
            size = p.stat().st_size
            total += size
            if len(temp) >= MAX_FILES or total > MAX_BYTES:
                raise ValueError("snapshot exceeds bounds")
            temp.append({"path": rel, "size": size, "sha256": sha256(p)})
    return sorted(temp, key=lambda item: item["path"])


def copy_new(source, destination, with_manifest):
    if destination.exists() or destination.is_symlink():
        raise ValueError("destination already exists")
    if source.resolve() == destination.resolve() or source.resolve() in destination.resolve().parents:
        raise ValueError("destination must not be inside source")
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise ValueError("destination parent must be a real directory")
    staging = Path(tempfile.mkdtemp(prefix=".ga12-staging-", dir=destination.parent))
    try:
        shutil.copytree(source, staging, dirs_exist_ok=True, symlinks=True)
        if with_manifest:
            expected = inventory(source)
            if inventory(staging) != expected:
                raise ValueError("source changed during snapshot")
            (staging / MANIFEST).write_text(json.dumps({
                "schema": 1, "evidence_class": "OFFLINE_ISOLATED_PROJECT_COPY",
                "files": expected}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            validate_manifest(staging)
        else:
            validate_manifest(staging)
            (staging / MANIFEST).unlink()
            if inventory(staging) != inventory_without_manifest(source):
                raise ValueError("restore verification failed")
        if destination.exists() or destination.is_symlink():
            raise ValueError("destination appeared during copy")
        staging.rename(destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["snapshot", "verify", "restore"])
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--authorize-isolated-restore", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "verify":
            manifest = validate_manifest(args.source)
            result = {"status": "VERIFIED", "files": len(manifest["files"])}
        elif args.action == "snapshot":
            if args.destination is None:
                raise ValueError("destination required")
            copy_new(args.source, args.destination, True)
            result = {"status": "SNAPSHOT_CREATED"}
        else:
            if not args.authorize_isolated_restore:
                raise ValueError("explicit isolated restore authorization required")
            if args.destination is None:
                raise ValueError("destination required")
            validate_manifest(args.source)
            copy_new(args.source, args.destination, False)
            result = {"status": "RESTORED_OFFLINE_COPY", "apply_replay_authorized": False}
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "BLOCKED", "reason": str(exc)}, sort_keys=True))
        return 2


if __name__ == "__main__":
    sys.exit(main())
