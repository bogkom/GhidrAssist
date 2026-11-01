#!/usr/bin/env python3
"""Isolated Wyse CodeBrowser Decompiler smoke; one shot, no Supervisor."""
import argparse
import importlib.machinery
import json
import os
import time
import types
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError

ROOT=Path.home()/"Projekty/Codex/ga-automation-test"
loader=importlib.machinery.SourceFileLoader("agent",str(ROOT/"bin/ghidrassist-agent"))
agent=types.ModuleType("agent")
loader.exec_module(agent)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--source-sha",required=True)
    args=ap.parse_args()
    if len(args.source_sha)!=40 or any(c not in "0123456789abcdef" for c in args.source_sha):
        ap.error("Pinned full source SHA required")
    session=agent.load_session(ROOT/"session.json")
    checks=[]
    def check(name,value,detail):
        checks.append(dict(name=name,result="PASS" if value else "FAIL",detail=detail))
        print(checks[-1]["result"],name,detail,flush=True)
        if not value:raise RuntimeError(name+": "+detail)
    def rpc(method,params=None):
        r=agent.rpc(session,method,params)
        if r.get("schema")!=3 or r.get("program")!="synthetic-mmio.bin":
            raise RuntimeError("Not the isolated synthetic program")
        return r
    failed=None
    started=datetime.now(timezone.utc).isoformat()
    try:
        check("ready",rpc("session.status").get("status")=="READY","Synthetic API ready")
        rpc("listing.goto",{"address":"00000020"})
        active=rpc("function.snapshot")["function"]
        check("fixture-function",active.get("entry")=="00000020",
              "Existing synthetic function at 0x20")
        start=rpc("decompiler.start")["decompiler"]
        check("async-start",start.get("state")=="RUNNING" and bool(start.get("task_id")),
              "Background task created")
        state={}
        for _ in range(120):
            state=rpc("decompiler.status",{"offset":0,"limit":128})["decompiler"]
            if state.get("state")!="RUNNING":break
            time.sleep(0.25)
        check("completed",state.get("state")=="COMPLETED",
              "Ghidra decompiled function without LLM")
        check("bounded-page",0<len(state.get("text",""))<=128 and
              state.get("total_characters",0)>0,"128 character page")
        end=rpc("decompiler.status",{
            "offset":state["total_characters"],"limit":128})["decompiler"]
        check("page-end",end.get("text")=="","Empty beyond last character")
        try:
            agent.rpc(session,"decompiler.status",{"offset":-1,"limit":10000})
        except HTTPError as error:
            check("invalid-bounds",error.code==400,"Invalid page rejected")
        else:
            check("invalid-bounds",False,"Invalid page accepted")
    except HTTPError as err:
        failed="HTTP "+str(err.code)+": "+err.read(8192).decode("utf-8",errors="replace")
        checks.append(dict(name="api-error",result="FAIL",detail=failed))
        print("FAIL api-error",failed,flush=True)
    except Exception as err:
        failed=type(err).__name__+": "+str(err)
        if not checks or checks[-1]["result"]!="FAIL":
            checks.append(dict(name="fatal",result="FAIL",detail=failed))
            print("FAIL fatal",failed,flush=True)
    reports=ROOT/"reports"
    reports.mkdir(exist_ok=True)
    path=reports/("ga18-decompiler-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+".json")
    final="PASS" if checks and all(x["result"]=="PASS" for x in checks) else "FAIL"
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"w") as fp:
        json.dump(dict(schema=1,source_commit=args.source_sha,
                       started=started,finished=datetime.now(timezone.utc).isoformat(),
                       checks=checks,result=final,error=failed),fp,indent=2)
    print("REPORT="+str(path))
    print("RESULT="+final)
    return 0 if final=="PASS" else 1

if __name__=="__main__":
    raise SystemExit(main())
