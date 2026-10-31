#!/usr/bin/env python3
"""CI-only external X11 observer for GA-18 GUI-06. Not a Supervisor worker.

Only operates on the ephemeral Xvfb display in the existing GitHub Actions
harness. The *actual* host bridge, permissions and native GUI worker remain
owned by bogkom/codex-supervisor PR #92.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from assertion_audit import png_info

WINDOW_CLASS="CodeBrowserMmioMain.CodeBrowserMmioMain"
WINDOW_TITLE="GhidrAssist isolated CodeBrowser MMIO: CodeBrowserFixture:/synthetic-mmio.bin"
CASE_ID="synthetic-codebrowser-001"
XID=re.compile(r"0x[0-9a-f]{1,16}\Z")
RUN=re.compile(r"[a-f0-9]{32}\Z")


def require(ok,message):
    if not ok:
        raise RuntimeError("BLOCKED_CI_EXTERNAL_X11: "+message)


def identity(window_id):
    p=subprocess.run(["wmctrl","-lx"],text=True,capture_output=True,
                     timeout=8,check=True)
    matches=[]
    for line in p.stdout.splitlines():
        fields=line.split(None,4)
        if len(fields)!=5:
            continue
        try:
            normalized=f"0x{int(fields[0],16):08x}"
        except ValueError:
            continue
        if fields[2]==WINDOW_CLASS and fields[4]==WINDOW_TITLE:
            matches.append(normalized)
    require(matches==[window_id],"XID/class/title not unique or changed")


def run(workspace,run_id,seconds):
    require(RUN.fullmatch(run_id) is not None,"bad run ID")
    root=Path(workspace)
    require(root.is_dir() and not root.is_symlink() and
            stat.S_IMODE(root.stat().st_mode)==0o700,
            "workspace must be real private 0700")
    evidence=root/"evidence"
    source=evidence/("pilot-ghidra-"+run_id)
    ready=source/"capture-ready.json"
    deadline=time.monotonic()+seconds
    while not ready.is_file():
        require(time.monotonic()<deadline,"READY timeout")
        time.sleep(0.1)
    signal=json.loads(ready.read_text())
    xid=signal["window_id"]
    require(signal["run_id"]==run_id and signal["case_id"]==CASE_ID and
            signal["window_class"]==WINDOW_CLASS and
            signal["window_title"]==WINDOW_TITLE and
            signal["program"]=="synthetic-mmio.bin" and
            signal["address"]=="0x00000020" and
            signal["function"]=="FUN_00000020" and
            XID.fullmatch(xid),"wrong READY identity")
    identity(xid)
    target=evidence/("pilot-x11-"+run_id)
    target.mkdir(mode=0o700,exist_ok=False)
    png=target/"ghidra-window.png"
    # The original bytes are produced by a SEPARATE process operating
    # on a live window; never reuse the JVM's Robot screenshot.
    fd=os.open(png,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    os.close(fd)
    begin=time.time_ns()
    subprocess.run(["import","-window",xid,"png:"+str(png)],
                   stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,
                   check=True,timeout=20)
    end=time.time_ns()
    identity(xid)
    raw=png.read_bytes()
    w,h=png_info(raw)
    digest=hashlib.sha256(raw).hexdigest()
    require(begin<=end and end-begin<=60*1_000_000_000,
            "capture outside bounded time")
    false_keys=("independent_semantic_visual_readback",
        "visual_readback_verified","native_computer_use_verified",
        "trusted_ghidra_provenance_verified","same_run_semantics_verified",
        "window_navigation_verified","native_nonce_ack","supervisor_ack",
        "formal_gui_pass","worker_changed","timer_changed",
        "model_turn_started")
    rec={
        "action":"GA18_SYNTHETIC_X11_HOST_BRIDGE",
        "applied":True,
        "window_id":xid,"wm_class":WINDOW_CLASS,"window_title":WINDOW_TITLE,
        "case_id":CASE_ID,"run_id":run_id,
        "source":"host-owned-readonly-x11",
        "result":"HOST_SYNTHETIC_X11_CAPTURED_PROVENANCE_PENDING",
        "identity_before_after_capture":True,
        "captured_screenshot_sha256":digest,
        "screenshot_width":w,"screenshot_height":h,
        "capture_start_epoch_ms":begin//1_000_000,
        "capture_end_epoch_ms":end//1_000_000,
        "relative_evidence_path":str(target.relative_to(root)),
        "original_image_relative_path":str(png.relative_to(root)),
        **{key:False for key in false_keys},
    }
    report=target/"bridge-capture.json"
    fd=os.open(report,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,"w") as stream:
        json.dump(rec,stream,sort_keys=True,separators=(",",":"))
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({"ci_only":True,"status":"HOST_X11_CAPTURED_STRUCTURAL_ONLY",
                       "run_id":run_id,"window_id":xid,"sha256":digest}))


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--workspace",required=True)
    p.add_argument("--run-id",required=True)
    p.add_argument("--timeout",type=int,default=60)
    a=p.parse_args()
    if not 5<=a.timeout<=180:
        p.error("timeout out of bounds")
    run(a.workspace,a.run_id,a.timeout)
