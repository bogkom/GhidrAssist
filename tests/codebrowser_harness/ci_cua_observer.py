#!/usr/bin/env python3
"""CI-only host observer. No native Codex/CUA, nonce, ACK or GUI PASS."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
from gui06_protocol import CLASS,TITLE,PROGRAM,ADDRESS,FUNCTION

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--workspace",required=True)
    p.add_argument("--run-id",required=True)
    p.add_argument("--timeout",type=int,required=True)
    p.add_argument("--mode",choices=("release","unavailable","window-changed"),required=True)
    a=p.parse_args()
    if not re.fullmatch("[a-f0-9]{32}",a.run_id):
        raise RuntimeError("INVALID_RUN_ID")
    d=Path(a.workspace)/"evidence"/("pilot-ghidra-"+a.run_id)
    ready=d/"cua-live-ready.json"
    end=time.monotonic()+a.timeout+20
    while not ready.is_file():
        if time.monotonic()>end:
            raise RuntimeError("NO_LIVE_CUA_READY")
        time.sleep(.1)
    obj=json.loads(ready.read_text())
    assert obj["action"]=="GA18_NATIVE_CUA_LIVE_READY"
    assert obj["run_id"]==a.run_id
    assert obj["window_class"]==CLASS and obj["window_title"]==TITLE
    assert obj["program"]==PROGRAM and obj["address"]==ADDRESS
    assert obj["function"]==FUNCTION and obj["decompiler_function"]==FUNCTION
    assert obj["native_cua_verified"] is False
    assert obj["native_nonce_ack"] is False and obj["formal_gui_pass"] is False
    xid=obj["window_id"]
    assert re.fullmatch(r"0x[0-9a-f]{8}",xid)
    props=subprocess.check_output(["xprop","-id",xid,"WM_CLASS","_NET_WM_NAME"],
                                  text=True,timeout=5)
    assert "CodeBrowserMmioMain" in props and TITLE in props
    if a.mode=="window-changed":
        subprocess.run(["wmctrl","-ir",xid,"-T","GA18_CHANGED_WINDOW"],
                       check=True,timeout=5)
        # X11 title actually changed, not merely a forged report field.
        return
    response={"schema":1,"run_id":a.run_id,"window_id":xid,
              "window_class":CLASS,"window_title":TITLE,
              "status":("CUA_UNAVAILABLE" if a.mode=="unavailable"
                        else "WINDOW_OBSERVATION_COMPLETE"),
              "native_cua_verified":False,"native_nonce_ack":False,
              "formal_gui_pass":False}
    fd=os.open(d/"cua-live-release.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,"w") as file:
        json.dump(response,file)
        file.write("\n")
    # Host-only signal is not native ACK. No interaction with Codex or CUA.

if __name__=="__main__":
    main()
