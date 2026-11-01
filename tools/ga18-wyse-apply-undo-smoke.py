#!/usr/bin/env python3
"""One-shot synthetic-only Ghidra Apply/Undo pilot; no firmware, no Supervisor."""
import argparse
from datetime import datetime, timezone
import importlib.machinery
import json
import os
from pathlib import Path
import types
import time
from urllib.error import HTTPError

ROOT = Path.home() / "Projekty/Codex/ga-automation-test"
loader = importlib.machinery.SourceFileLoader("ga18client", str(ROOT / "bin/ghidrassist-agent"))
client = types.ModuleType("ga18client")
loader.exec_module(client)


def run():
    p=argparse.ArgumentParser()
    p.add_argument("--source-sha", required=True)
    args=p.parse_args()
    if len(args.source_sha)!=40 or not all(x in "0123456789abcdef" for x in args.source_sha):
        p.error("Exact commit SHA required")
    session=client.load_session(ROOT / "session.json")
    checks=[]
    def check(name,ok,detail):
        checks.append(dict(name=name,result="PASS" if ok else "FAIL",detail=detail))
        print(checks[-1]["result"],name,detail,flush=True)
    def rpc(method,params=None):
        ans=client.rpc(session,method,params)
        if ans.get("schema")!=3 or ans.get("program")!="synthetic-mmio.bin":
            raise RuntimeError("Not the pinned synthetic fixture")
        if ans.get("program_writable") is not True or ans.get("program_read_only") is not False:
            raise RuntimeError("Synthetic fixture is not writable")
        return ans
    def reject(method,params):
        try:
            client.rpc(session,method,params)
        except HTTPError as error:
            return error.code==400
        return False

    started=datetime.now(timezone.utc).isoformat()
    failure=None
    applied=False
    undone=False
    try:
        check("session-writable",rpc("session.status").get("status")=="READY",
              "Ghidra writable synthetic")
        rpc("hardware.profile.select",{"profile":"MC68332_USER_SELECTED"})
        rpc("hardware.analyze")
        for i in range(60):
            task=rpc("hardware.task")["task"]
            if task.get("state")!="RUNNING":break
            time.sleep(1)
        check("analysis-ready",task.get("state")=="COMPLETED","MC68332 analysis complete")
        review=rpc("hardware.review.preview",{"offset":0,"limit":30})["review"]
        possible=[row for row in review.get("rows",[])
                  if row.get("kind")=="MEMORY" and row.get("state")=="READY"
                  and row.get("selected_by_default") and
                  not row.get("name","").startswith("CS") and
                  "CANDIDATE" not in row.get("name","")]
        if not possible:raise RuntimeError("No safe memory proposal")
        chosen=possible[0]
        first=rpc("hardware.apply.prepare",{"index":chosen["index"]})["approval"]
        check("wrong-token-rejected",
              reject("hardware.apply.commit",{"token":"invalid","name":first["name"]}),
              "invalid token refused")
        check("consumed-token-rejected",
              reject("hardware.apply.commit",{"token":first["token"],"name":first["name"]}),
              "token cannot be reused")
        second=rpc("hardware.apply.prepare",{"index":chosen["index"]})["approval"]
        check("explicit-name-bound",second["name"]==chosen["name"],"same proposal identity")
        outcome=rpc("hardware.apply.commit",
                    {"token":second["token"],"name":second["name"]})["apply"]
        applied=True
        check("one-transaction",outcome.get("changed")==1 and outcome.get("skipped")==0
              and outcome.get("undo_available") is True,"exactly one synthetic memory region")
        outcome_undo=rpc("hardware.apply.undo")["undo"]
        undone=bool(outcome_undo.get("undone"))
        check("undo",undone,"Ghidra transaction Undo")
        check("second-undo-rejected",reject("hardware.apply.undo",{}),
              "one-shot Undo consumed")
    except Exception as error:
        failure=type(error).__name__+": "+str(error)
        check("fatal",False,failure)
    finally:
        if applied and not undone:
            # Never attempt blind rollback through another API after a failed
            # Undo. Preserve Ghidra and request operator inspection instead.
            check("manual-undo-required",False,"Apply occurred but Undo unconfirmed; inspect isolated Ghidra")
        try:
            rpc("hardware.profile.select",{"profile":"CPU32_SURVEY"})
        except Exception as error:
            check("restore-profile",False,type(error).__name__+": "+str(error))
        directory=ROOT/"reports"
        directory.mkdir(exist_ok=True)
        report=directory/("ga18-apply-undo-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+".json")
        record={"schema":1,"suite":"ga18-synthetic-apply-undo","source_commit":args.source_sha,
                "classification":"codex-host-synthetic-write-test-not-supervisor",
                "started_utc":started,"finished_utc":datetime.now(timezone.utc).isoformat(),
                "checks":checks,"apply_attempted":applied,"undo_confirmed":undone,
                "error":failure,"overall":"PASS" if checks and all(x["result"]=="PASS" for x in checks) else "FAIL"}
        fd=os.open(report,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,"w") as stream:
            json.dump(record,stream,ensure_ascii=False,indent=2)
        print("REPORT="+str(report))
        print("RESULT="+record["overall"])
        return 0 if record["overall"]=="PASS" else 1


if __name__=="__main__":
    raise SystemExit(run())
