#!/usr/bin/env python3
"""GA-18 Wyse real CodeBrowser smoke: local API only, no Supervisor and no writes."""
import argparse
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import traceback

ROOT = Path.home() / "Projekty/Codex/ga-automation-test"
CLIENT = ROOT / "bin/ghidrassist-agent"
EXPECTED_PROGRAM = "synthetic-mmio.bin"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--session", type=Path, default=ROOT / "session.json")
    parser.add_argument("--outdir", type=Path, default=ROOT / "reports")
    args = parser.parse_args()
    if not (len(args.source_sha) == 40 and all(c in "0123456789abcdef" for c in args.source_sha)):
        parser.error("--source-sha requires exact lowercase 40-character Git commit")
    spec = importlib.util.spec_from_file_location("agent_client", CLIENT)
    # Extension-less Python script cannot be imported by spec_from_file_location.
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader("agent_client", str(CLIENT))
    import types
    client = types.ModuleType("agent_client")
    loader.exec_module(client)
    session = client.load_session(args.session)
    if args.session.stat().st_mode & 0o077:
        parser.error("Session file must be private (chmod 600)")
    checks = []
    evidence = {}
    def check(name, passed, detail):
        checks.append({"name": name, "result": "PASS" if passed else "FAIL", "detail": detail})
        print(("%-5s " % checks[-1]["result"]) + name + ": " + detail, flush=True)

    def api(method, params=None):
        reply = client.rpc(session, method, params)
        if reply.get("schema") != 3 or reply.get("program") != EXPECTED_PROGRAM:
            raise AssertionError("Wrong schema/program: " + repr(reply))
        if reply.get("program_writable") is not True or reply.get("program_read_only") is not False:
            raise AssertionError("API did not confirm writable synthetic fixture")
        return reply

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    args.outdir.mkdir(parents=True, exist_ok=True)
    path = args.outdir / ("ga18-api-" + stamp + ".json")
    start = dt.datetime.now(dt.timezone.utc).isoformat()
    fatal = None
    try:
        status = api("session.status")
        check("ready-writable-synthetic", status.get("status") == "READY", "actual Ghidra API READY")
        snap = api("ui.snapshot")
        check("ui-snapshot", bool(snap.get("ui", {}).get("hardware", {}).get("hardware.analyze", {}).get("enabled")), "Analyze control exposed")
        analyze = api("hardware.analyze")
        check("analyze-trigger", analyze.get("ui", {}).get("selected_tab") == "Hardware Analysis", "Hardware Analysis selected")
        task = None
        for _ in range(60):
            task = api("hardware.task").get("task", {})
            if task.get("state") != "RUNNING":
                break
            time.sleep(1)
        check("task-completed", task.get("state") == "COMPLETED" and task.get("site_count") == 1, "state=%s sites=%s" % (task.get("state"), task.get("site_count")))
        result = api("hardware.mmio.rows", {"filter": "SIMCR", "offset": 0, "limit": 100}).get("table", {})
        rows = result.get("rows", [])
        match = len(rows) == 1 and rows[0].get("pc") == "0x00000020" and rows[0].get("register") == "SIMCR" and rows[0].get("address") == "0x00FFFA00" and rows[0].get("value") == "0x40CA"
        check("simcr-static-candidate", match and result.get("total") == 1, "one static SIMCR candidate, not runtime evidence")
        empty = api("hardware.mmio.rows", {"filter": "NONEXISTENT_GA18_REGISTER", "offset": 0, "limit": 10}).get("table", {})
        check("mmio-filter-empty", empty.get("total") == 0 and not empty.get("rows"), "unknown register yields zero rows")
        page = api("hardware.mmio.rows", {"filter": "SIMCR", "offset": 1, "limit": 1}).get("table", {})
        check("mmio-pagination", page.get("total") == 1 and not page.get("rows"), "offset=1 excludes first result")
        nav = api("listing.goto", {"address": "00000020"})
        listing = api("listing.snapshot")
        check("listing-navigation", nav.get("requested_address") == "00000020" and listing.get("address") == "00000020", "Listing 0x20 confirmed")
        # Negative test: a memory address outside the isolated 256-byte fixture.
        try:
            client.rpc(session, "listing.goto", {"address": "00ABCDEF"})
        except Exception:
            check("reject-invalid-address", True, "invalid fixture address rejected")
        else:
            check("reject-invalid-address", False, "invalid fixture address accepted")
        evidence = {"session": {"pid": session.get("pid"), "schema": session.get("schema")},
                    "task": task, "mmio": rows, "listing_address": listing.get("address")}
    except Exception as exc:
        fatal = type(exc).__name__ + ": " + str(exc)
        check("fatal-api-error", False, fatal)
    finally:
        report = {"schema": 1, "suite": "ga18-wyse-automation-api-smoke",
                  "source_repository": "bogkom/GhidrAssist", "source_commit": args.source_sha,
                  "started_utc": start, "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                  "fixture": EXPECTED_PROGRAM, "checks": checks, "evidence": evidence,
                  "fatal": fatal, "overall": "PASS" if checks and all(c["result"] == "PASS" for c in checks) else "FAIL",
                  "classification": "host-api-test-not-formal-supervisor-pass"}
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        print("REPORT=" + str(path), flush=True)
        print("RESULT=" + report["overall"], flush=True)
        return 0 if report["overall"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
