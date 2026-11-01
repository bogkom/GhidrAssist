#!/usr/bin/env python3
"""GA-18 read-only Review preview host regression; no Apply, Undo or database edits."""
import argparse
from datetime import datetime, timezone
import importlib.machinery
import json
import os
from pathlib import Path
import time
import types

ROOT = Path.home() / "Projekty/Codex/ga-automation-test"
loader = importlib.machinery.SourceFileLoader("ga18client", str(ROOT / "bin/ghidrassist-agent"))
client = types.ModuleType("ga18client")
loader.exec_module(client)


def run():
    p = argparse.ArgumentParser()
    p.add_argument("--source-sha", required=True)
    args = p.parse_args()
    if len(args.source_sha) != 40 or not all(x in "0123456789abcdef" for x in args.source_sha):
        p.error("Exact source SHA required")
    session = client.load_session(ROOT / "session.json")
    checks = []
    def check(name, ok, note):
        checks.append({"name": name, "result": "PASS" if ok else "FAIL", "detail": note})
        print(checks[-1]["result"], name, note, flush=True)
    def rpc(name, params=None):
        data = client.rpc(session, name, params)
        if data.get("schema") != 3 or data.get("program") != "synthetic-mmio.bin":
            raise RuntimeError("Unexpected schema or program")
        if data.get("program_writable") is not True or data.get("program_read_only") is not False:
            raise RuntimeError("Fixture not writable")
        return data

    started = datetime.now(timezone.utc).isoformat()
    failure = None
    try:
        rpc("hardware.profile.select", {"profile": "CPU32_SURVEY"})
        rpc("hardware.analyze")
        for i in range(60):
            task = rpc("hardware.task")["task"]
            if task["state"] != "RUNNING":
                break
            time.sleep(1)
        check("survey-completed", task["state"] == "COMPLETED", task["state"])
        try:
            client.rpc(session, "hardware.review.preview", {"offset": 0, "limit": 10})
        except Exception:
            check("generic-profile-rejected", True, "MC68332 Review not inherited from CPU32")
        else:
            check("generic-profile-rejected", False, "Unsafe generic CPU32 Review accepted")
        selected = rpc("hardware.profile.select", {"profile": "MC68332_USER_SELECTED"})
        check("explicit-mc68332", "MC68332" in selected["ui"]["hardware"]["profile"],
              "explicit user-selected MC68332 profile")
        rpc("hardware.analyze")
        for i in range(60):
            task = rpc("hardware.task")["task"]
            if task["state"] != "RUNNING":
                break
            time.sleep(1)
        check("concrete-completed", task["state"] == "COMPLETED", task["state"])
        review = rpc("hardware.review.preview", {"offset": 0, "limit": 10})["review"]
        rows = review.get("rows", [])
        check("review-readonly-preview",
              review.get("total", 0) > 0 and len(rows) > 0 and
              all("state" in x and "allowed" in x for x in rows) and
              "PREVIEW ONLY" in review.get("scope", ""),
              "bounded preflight proposal rows, no Apply")
        tail = rpc("hardware.review.preview",
                   {"offset": review["total"], "limit": 1})["review"]
        check("review-pagination", not tail.get("rows"), "out-of-range offset has no rows")
        try:
            client.rpc(session, "hardware.review.preview", {"offset": -1, "limit": 1000})
        except Exception:
            check("review-invalid-page-rejected", True, "bounds validated")
        else:
            check("review-invalid-page-rejected", False, "invalid bounds accepted")
    except Exception as exc:
        failure = type(exc).__name__ + ": " + str(exc)
        check("fatal", False, failure)
    finally:
        try:
            rpc("hardware.profile.select", {"profile": "CPU32_SURVEY"})
        except Exception as exc:
            check("profile-restore", False, type(exc).__name__ + ": " + str(exc))
        reports = ROOT / "reports"
        reports.mkdir(exist_ok=True)
        path = reports / ("ga18-review-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json")
        result = {"schema": 1, "suite": "ga18-hardware-review-readonly",
                  "source_commit": args.source_sha, "started_utc": started,
                  "finished_utc": datetime.now(timezone.utc).isoformat(),
                  "classification": "codex-host-test-not-formal-supervisor-pass",
                  "checks": checks, "error": failure,
                  "overall": "PASS" if checks and all(x["result"] == "PASS" for x in checks) else "FAIL"}
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(result, handle, ensure_ascii=False, indent=2)
        print("REPORT=" + str(path))
        print("RESULT=" + result["overall"])
        return 0 if result["overall"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(run())
