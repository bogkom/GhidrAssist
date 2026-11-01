#!/usr/bin/env python3
"""GA-18 function/XREF read-only host smoke on the synthetic Ghidra fixture."""
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

def run():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source-sha",required=True)
    args=parser.parse_args()
    if len(args.source_sha)!=40 or not all(ch in "0123456789abcdef" for ch in args.source_sha):
        parser.error("Exact pinned Git SHA required")
    session=agent.load_session(ROOT/"session.json")
    checks=[]
    def check(name,ok,note):
        checks.append({"name":name,"result":"PASS" if ok else "FAIL","detail":note})
        print(checks[-1]["result"],name,note,flush=True)
    def call(method,params=None):
        result=agent.rpc(session,method,params)
        if result.get("schema")!=3 or result.get("program")!="synthetic-mmio.bin":
            raise RuntimeError("Not the expected isolated synthetic program")
        return result
    failure=None
    started=datetime.now(timezone.utc).isoformat()
    try:
        status=call("session.status")
        check("synthetic-ready",status.get("status")=="READY","existing test session")
        goto=call("listing.goto",{"address":"00000020"})
        check("function-navigation",goto.get("requested_address")=="00000020","fixture function entry")
        function=call("function.snapshot").get("function",{})
        check("function-identity",function.get("entry")=="00000020" and
              function.get("name")=="FUN_00000020" and
              function.get("body_addresses",0)>=1,"real active Ghidra Function")
        xrefs=call("function.xrefs",{"offset":0,"limit":10}).get("xrefs",{})
        check("xrefs-bounded",xrefs.get("entry")=="00000020" and
              xrefs.get("offset")==0 and xrefs.get("limit")==10 and
              isinstance(xrefs.get("rows"),list) and
              isinstance(xrefs.get("total"),int),"entry XREF list and pagination")
        beyond=call("function.xrefs",{"offset":xrefs.get("total",0),"limit":1}).get("xrefs",{})
        check("xrefs-page-end",beyond.get("rows")==[],"no results past last reference")
        try:
            agent.rpc(session,"function.xrefs",{"offset":-1,"limit":1000})
        except HTTPError as error:
            check("invalid-xref-page",error.code==400,"invalid pagination rejected")
        else:
            check("invalid-xref-page",False,"invalid pagination accepted")
    except Exception as error:
        failure=type(error).__name__+": "+str(error)
        check("fatal",False,failure)
    reports=ROOT/"reports"
    reports.mkdir(exist_ok=True)
    path=reports/("ga18-function-xrefs-"+datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")+".json")
    result={"schema":1,"suite":"ga18-function-xrefs-readonly",
            "source_commit":args.source_sha,"started_utc":started,
            "finished_utc":datetime.now(timezone.utc).isoformat(),
            "classification":"codex-host-api-test","checks":checks,"error":failure,
            "overall":"PASS" if checks and all(x["result"]=="PASS" for x in checks) else "FAIL"}
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,"w") as stream:
        json.dump(result,stream,indent=2)
    print("REPORT="+str(path),"RESULT="+result["overall"],sep="\n")
    return 0 if result["overall"]=="PASS" else 1

if __name__=="__main__":
    raise SystemExit(run())
