#!/usr/bin/env python3
"""Read-only verification of a persisted GA-12 CPU32 headless checkpoint.

A PASS means the saved runner verdict and preserved log are mutually consistent;
it does not independently establish real Ghidra execution or MCU behavior.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

EXPECTED_FIXTURE = hashlib.sha256(bytes.fromhex(
    "33fc40ca00fffa004e7b08014e7a08017001")).hexdigest()
PREPARE = re.compile(
    r"(?:INFO  GA18PrepareDecodedEffectSites\.java> )?"
    r"GA18_PREPARE_DECODED_SITES_PASS instructions=4 function=0x100 bytes=18"
    r"(?: \(GhidraScript\))?")
VERIFY = re.compile(
    r"(?:INFO  GA18VerifyDecodedEffectSites\.java> )?"
    r"GA18_DECODED_SITES_GHIDRA_PASS sites=2 positive=2 negative=4 recovery=2"
    r"(?: \(GhidraScript\))?")


def check(result_path, log_path, expected_sha):
    try:
        raw = result_path.read_bytes()
        if len(raw) > 65536:
            raise ValueError("oversized checkpoint")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("checkpoint is not an object")
        required = {"schema", "source_sha", "fixture_sha256", "ghidra_version",
                    "status", "reason", "process_exit", "evidence_kind",
                    "evidence_log_sha256"}
        if set(payload) != required:
            raise ValueError("missing or unexpected checkpoint fields")
        if (type(payload["schema"]) is not int or payload["schema"] != 1
                or payload["source_sha"] != expected_sha
                or payload["fixture_sha256"] != EXPECTED_FIXTURE
                or payload["ghidra_version"] != "12.1.4 PUBLIC"
                or payload["evidence_kind"] != "isolated_synthetic_ghidra_headless"):
            raise ValueError("checkpoint provenance mismatch")
        if not re.fullmatch(r"[0-9a-f]{64}", payload["evidence_log_sha256"]):
            raise ValueError("invalid log digest")
        digest = hashlib.sha256()
        lines = []
        with log_path.open("rb") as stream:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
                if sum(map(len, lines)) + len(chunk) > 16 * 1024 * 1024:
                    raise ValueError("oversized evidence log")
                lines.append(chunk)
        if digest.hexdigest() != payload["evidence_log_sha256"]:
            raise ValueError("log digest mismatch")
        output = b"".join(lines).decode("utf-8", "strict")
        records = [line.strip() for line in output.splitlines()]
        prepare = [i for i, line in enumerate(records) if PREPARE.fullmatch(line)]
        verify = [i for i, line in enumerate(records) if VERIFY.fullmatch(line)]
        markers = [i for i, line in enumerate(records)
                   if "GA18_PREPARE_DECODED_SITES_PASS" in line
                   or "GA18_DECODED_SITES_GHIDRA_PASS" in line]
        if payload["status"] == "PASS":
            if (payload["reason"] != "verified" or type(payload["process_exit"]) is not int
                    or payload["process_exit"] != 0
                    or len(prepare) != 1 or len(verify) != 1
                    or len(markers) != 2 or prepare[0] >= verify[0]
                    or any(s in output for s in
                           ("GA18_PREPARE_FAIL", "GA18_DECODED_SITES_FAIL",
                            "ERROR", "Exception", "AssertionError"))
                    or not any(line.startswith("GA01_CPU32_HEADLESS_PASS exit=0 ")
                               for line in records)):
                raise ValueError("PASS not supported by evidence")
            return "PASS"
        if payload["status"] == "FAIL":
            if (payload["reason"] not in
                    ("timeout", "launch_error", "invalid_evidence_or_exit")
                    or (payload["process_exit"] is not None
                        and type(payload["process_exit"]) is not int)
                    or not any("GA01_CPU32_HEADLESS_FAIL" in line for line in records)):
                raise ValueError("FAIL not supported by evidence")
            return "FAIL"
        raise ValueError("invalid status")
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"checkpoint rejected: {exc}") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--result-json", required=True, type=Path)
    parser.add_argument("--evidence-log", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.source_sha):
        parser.error("source SHA must be 40 lowercase hex digits")
    try:
        status = check(args.result_json, args.evidence_log, args.source_sha)
    except ValueError as exc:
        print(f"GA12_CHECKPOINT_REJECTED {exc}", file=sys.stderr)
        return 2
    print(f"GA12_CHECKPOINT_{status} source={args.source_sha}")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
