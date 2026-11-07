#!/usr/bin/env python3
"""One genuine CodeBrowser Program -> ReAct -> 127.0.0.1 JSON-RPC -> CLI fixture.

The only scripted component is the model response, which calls the real
read-only Ghidra tool through ReAct's ToolRegistry. No real AI/model or MCU.
The authorization receipt lives outside the artifact directory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT=Path(__file__).resolve().parents[2]
AGENT=ROOT/"tools"/"ghidrassist-agent"


def wait_path(path,seconds):
    stop=time.monotonic()+seconds
    while time.monotonic()<stop:
        if path.is_file():
            return path
        time.sleep(0.05)
    raise TimeoutError("Actual ReAct did not reach bounded stage: "+path.name)


def command(session,*args,success=True):
    cmd=[sys.executable,str(AGENT),"--session",str(session),*map(str,args)]
    result=subprocess.run(cmd,capture_output=True,text=True,timeout=40)
    if success and result.returncode!=0:
        raise AssertionError("Production CLI rejected expected safe operation: "+
                             " ".join(map(str,args))+" "+result.stderr[:600])
    if not success:
        if result.returncode==0:
            raise AssertionError("Stale or unbounded Agentic RPC was accepted: "+str(args))
        return result.stderr[:300]
    return json.loads(result.stdout)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--session",required=True,type=Path)
    ap.add_argument("--output",required=True,type=Path)
    args=ap.parse_args()
    session=json.loads(args.session.read_text())
    out=args.output
    wait_path(out/"ga15-react-running",65)
    live=command(args.session,"agentic-findings","--offset",0,"--limit",1)
    r=live["agentic"]
    assert live["read_only"] is True and live["program"]=="synthetic-mmio.bin"
    assert r["state"]=="RUNNING" and not r["complete"]
    assert r["findings"]["retainedCount"]==0
    assert r["findings"]["rows"]==[] and not r["findings"]["sourceIncomplete"]
    assert len(r["run"])>=32 and r["programRevision"]>=0
    assert len(r["importSha256"])==64

    # Bearer token enforcement by the *actual* production loopback server.
    payload=json.dumps({"method":"agentic.findings.page","params":{}}).encode()
    req=Request("http://127.0.0.1:%d/rpc"%session["port"],data=payload,
                headers={"Authorization":"Bearer definitely-wrong-token",
                         "Content-Type":"application/json"},method="POST")
    try:
        with urlopen(req,timeout=10):
            raise AssertionError("Untrusted HTTP client got ReAct findings")
    except HTTPError as exc:
        assert exc.code==401,exc.code
    # Never permit an unknown run or client-supplied revision for page stitching.
    command(args.session,"agentic-findings","--offset",1,"--limit",1,
            success=False)
    command(args.session,"agentic-findings","--offset",1,"--limit",1,
            "--expected-run","wrong-run",
            "--expected-revision",r["programRevision"],
            "--expected-findings-revision",r["findings"]["revision"],
            success=False)

    (out/"ga15-react-release").write_text("external-CLI-verified-running")
    result=json.loads(wait_path(out/"ga15-react-result.json",60).read_text())
    assert result["status"]=="SUCCESS" and result["tool_calls"]==1,result
    assert result["tool_succeeded"] is True and result["revision_unchanged"] is True,result
    assert result["real_react_orchestrator"] and result["scripted_model_no_network"],result
    assert result["findings"]>=2,result

    first=command(args.session,"agentic-findings","--offset",0,"--limit",1)
    evidence=first["agentic"]
    assert evidence["state"]=="SUCCESS" and not evidence["complete"]
    assert evidence["findings"]["retainedCount"]>=2
    assert evidence["findings"]["hasMore"] and evidence["run"]==r["run"]
    assert evidence["findings"]["revision"]!=r["findings"]["revision"]
    second=command(args.session,"agentic-findings","--offset",1,"--limit",1,
                   "--expected-run",evidence["run"],
                   "--expected-revision",evidence["programRevision"],
                   "--expected-findings-revision",evidence["findings"]["revision"])
    assert second["agentic"]["findings"]["rows"],second
    assert second["agentic"]["run"]==evidence["run"]
    command(args.session,"agentic-findings","--offset",1,"--limit",1,
            "--expected-run",evidence["run"],
            "--expected-revision",evidence["programRevision"]+1,
            "--expected-findings-revision",evidence["findings"]["revision"],
            success=False)
    command(args.session,"agentic-findings","--offset",1,"--limit",1,
            "--expected-run",evidence["run"],
            "--expected-revision",evidence["programRevision"],
            "--expected-findings-revision",r["findings"]["revision"],
            success=False)
    command(args.session,"agentic-findings","--offset",0,"--limit",101,
            success=False)

    # The CLI must fetch *all* real ReAct pages from HTTP and create one
    # private no-overwrite checkpoint, then verify/read it with no session.
    checkpoint=out/"ga15-react-local-evidence.json"
    saved=command(args.session,"agentic-checkpoint","--limit",1,
                  "--output",checkpoint)
    assert saved["complete"] is True and saved["retained_count"]>=2,saved
    assert checkpoint.stat().st_mode & 0o777==0o600
    command(args.session,"agentic-checkpoint","--limit",1,
            "--output",checkpoint,success=False)
    offline_session=out/"nonexistent-agentic-session.json"
    verified=command(offline_session,"agentic-verify","--input",checkpoint)
    offline=command(offline_session,"agentic-read","--input",checkpoint,
                    "--offset",1,"--limit",1)
    assert verified["verified"] and verified["complete"]
    assert offline["offline"] and offline["read_only"] and offline["rows"]
    assert offline["run"]==evidence["run"]
    digest=hashlib.sha256(json.dumps(
        json.loads(checkpoint.read_text())["payload"],
        ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    assert verified["payload_sha256"]==saved["payload_sha256"]==digest

    # Corruption must be rejected by offline reader, not merely flagged.
    tampered=out/"ga15-corrupted-private.json"
    data=json.loads(checkpoint.read_text())
    data["payload"]["state"]="CANCELLED"
    tampered.write_text(json.dumps(data))
    command(offline_session,"agentic-read","--input",tampered,
            "--offset",0,"--limit",10,success=False)
    tampered.unlink()

    # Real Ghidra tool evidence is sourced from its static Listing PC.
    all_rows=json.loads(checkpoint.read_text())["payload"]["rows"]
    assert any("00000020" in (row.get("fact") or "") for row in all_rows)
    receipt={
        "schema":1,"synthetic_only":True,"actual_ghidra_codebrowser":True,
        "real_react_execution":True,"llm_provider":"scripted-no-network",
        "native_readonly_tool":"ga_get_current_address",
        "real_http_bearer_401":True,"real_cli_in_progress":True,
        "real_cli_completed":True,"source_program":"synthetic-mmio.bin",
        "source_revision_unchanged":result["revision_unchanged"],
        "program_revision":evidence["programRevision"],
        "stale_run_and_revision_denied":True,
        "checkpoint_no_overwrite":True,
        "offline_no_session_verify_and_read":True,
        "tampered_offline_denied":True,
        "retained":len(all_rows),"tool_calls":result["tool_calls"],
        "checkpoint_sha256":digest,
        "runtime_execution_verified":False,"model_or_oauth_used":False,
        "genuine_llm_resumption_verified":False,
    }
    (out/"ga15-react-e2e.json").write_text(
        json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print("GA15/18 REAL REACT + CODEBROWSER + BEARER JSON-RPC + CLI E2E PASS")


if __name__=="__main__":
    main()
