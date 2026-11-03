#!/usr/bin/env python3
"""Real Ghidra 12.1.4 CodeBrowser test on two synthetic firmware images ONLY."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import struct
import zlib
import subprocess
import sys
import tempfile
import zipfile
import uuid
import stat
import time

from assertion_audit import validate_files, sha256 as byte_sha256
from gui06_protocol import verify as verify_bridge, reserve_run, read_private_capture

ROOT = Path(__file__).resolve().parents[2]
VERSION = "12.1.4"
SRC = ROOT / "tests/codebrowser_harness/CodeBrowserMmioMain.java"


def sha256(file):
    h=hashlib.sha256()
    with file.open("rb") as f:
        for part in iter(lambda:f.read(1024*1024),b""):
            h.update(part)
    return h.hexdigest()


def fixture(path, with_simcr):
    data=bytearray(256)
    data[:8]=bytes.fromhex("0000100000000020")
    # Synthetic 68000: MOVE.W #$40CA,($00FFFA00).L ; RTS.
    data[0x20:0x2a]=(bytes.fromhex("33fc40ca00fffa004e75") if with_simcr
                       else bytes.fromhex("4e714e714e75"))
    path.write_bytes(data)


def zip_extension(source, destination):
    with zipfile.ZipFile(source) as z:
        names=z.namelist()
        if len(names)>10000 or "GhidrAssist/extension.properties" not in names:
            raise ValueError("Not a complete GhidrAssist extension ZIP")
        total=0
        for info in z.infolist():
            path=info.filename
            mode=(info.external_attr>>16)&0o170000
            if (not path.startswith("GhidrAssist/") or
                    path.startswith("/") or ".." in Path(path).parts or
                    "\\" in path or ":" in path or mode==0o120000):
                raise ValueError("Unsafe ZIP member")
            total+=info.file_size
            if total>250*1024*1024:
                raise ValueError("Oversized extension")
        props=z.read("GhidrAssist/extension.properties").decode("utf-8")
        if not re.search(r"(?m)^version=12\.1\.4\s*$",props):
            raise ValueError("Not a Ghidra 12.1.4 extension")
        z.extractall(destination)
    jar=destination/"GhidrAssist/lib/GhidrAssist.jar"
    if not jar.is_file() or jar.stat().st_size<1024:
        raise ValueError("GhidrAssist.jar missing from extension")


def subprocess_checked(cmd, cwd, env, log, timeout):
    with log.open("x") as stream:
        p=subprocess.run(cmd,cwd=cwd,env=env,stdout=stream,
                         stderr=subprocess.STDOUT,timeout=timeout)
    if p.returncode:
        raise RuntimeError(f"Command failed: {log.name}, exit={p.returncode}")


def validate_cua_hold(hold,captured,run_id):
    """Necessary host-window lifecycle integrity, NEVER native CUA/ACK proof."""
    checks={
        "result":hold.get("result")=="LIVE_CUA_WINDOW_RELEASED_STRUCTURAL_ONLY",
        "run_id":hold.get("run_id")==run_id,
        "native_cua":hold.get("native_cua_verified") is False,
        "native_ack":hold.get("native_nonce_ack") is False,
        "supervisor_ack":hold.get("supervisor_ack") is False,
        "formal_pass":hold.get("formal_gui_pass") is False,
        "pre_xid":hold.get("pre_window_id")==captured.get("window_id"),
        "post_xid":hold.get("post_window_id")==captured.get("window_id"),
        "program":hold.get("program")=="synthetic-mmio.bin",
        "address":hold.get("address")=="0x00000020",
        "listing":hold.get("function")=="FUN_00000020",
        "decompiler":hold.get("decompiler_function")=="FUN_00000020",
        "fresh_run":hold.get("source_run_id_reused") is False,
    }
    failed=[key for key,ok in checks.items() if not ok]
    if failed:
        raise RuntimeError("BLOCKED_CUA_HOLD_INVALID_POST_STATE: "+",".join(failed))
    return True


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--ghidra",required=True)
    ap.add_argument("--java-home",required=True)
    ap.add_argument("--extension-zip",required=True)
    ap.add_argument("--extension-sha256")
    ap.add_argument("--output",required=True)
    ap.add_argument("--timeout",type=int,default=300)
    ap.add_argument("--bridge-mode",choices=("off","ci","host"),default="off")
    ap.add_argument("--bridge-timeout",type=int,default=60)
    ap.add_argument("--automation-probe",action="store_true")
    ap.add_argument("--review-copy-probe",action="store_true",help="Separate isolated project-copy Review/Apply/Undo HTTP test")
    ap.add_argument("--cua-live",action="store_true",
                    help="Bounded live synthetic window for separate future native CUA")
    ap.add_argument("--cua-timeout",type=int,default=30)
    ap.add_argument("--cua-ci-response",choices=("none","release","unavailable",
                                                 "window-changed"),default="none",
                    help="CI-only synthetic host response; never a native CUA proof")
    args=ap.parse_args()
    if args.review_copy_probe and (not args.automation_probe or args.bridge_mode!="off" or args.cua_live):
        ap.error("--review-copy-probe requires --automation-probe, with bridge and CUA disabled")
    if args.timeout<90 or args.timeout>900:
        ap.error("timeout must be 90..900 seconds")
    if not 5<=args.bridge_timeout<=180:
        ap.error("bridge-timeout must be 5..180 seconds")
    if args.cua_live and args.bridge_mode!="off":
        ap.error("CUA hold is a separate mode; no previous X11 bridge replay")
    if not 5<=args.cua_timeout<=180:
        ap.error("cua-timeout must be 5..180 seconds")
    if args.cua_ci_response!="none" and not args.cua_live:
        ap.error("CI response requires --cua-live")
    run_id=uuid.uuid4().hex
    bridged=args.bridge_mode!="off" or args.cua_live
    target=Path(args.output).expanduser().absolute()
    if bridged:
        # Live output is a strict owner-private ga18-gui workspace.
        if (target.is_symlink() or not target.is_dir() or
                target.stat().st_uid!=os.getuid() or
                stat.S_IMODE(target.stat().st_mode)&0o077):
            ap.error("bridge requires existing owner-private 0700 workspace")
        evidence=target/"evidence"
        if evidence.exists():
            if (evidence.is_symlink() or not evidence.is_dir() or
                    evidence.stat().st_uid!=os.getuid() or
                    stat.S_IMODE(evidence.stat().st_mode)&0o077):
                ap.error("unsafe evidence root")
        else:
            evidence.mkdir(mode=0o700)
        try:
            out=reserve_run(target,run_id)
        except ValueError as exc:
            ap.error(str(exc))
    else:
        out=target
        if out.is_symlink() or (out.exists() and
                (not out.is_dir() or any(out.iterdir()))):
            ap.error("output must be empty non-symlink directory")
        out.mkdir(parents=True,exist_ok=True)
    os.umask(0o077)
    result={"schema":1,"status":"BLOCKED","test":"synthetic-codebrowser",
            "run_id":run_id,"bridge_mode":args.bridge_mode,
            "supervisor_ack":False,"human_visual_readback":"NOT_PERFORMED"}
    try:
        ghidra=Path(args.ghidra).resolve(strict=True)
        java=Path(args.java_home).resolve(strict=True)
        archive=Path(args.extension_zip).resolve(strict=True)
        if not ghidra.name.startswith("ghidra_12.1.4_PUBLIC"):
            raise RuntimeError("Ghidra 12.1.4 PUBLIC required")
        if not os.environ.get("DISPLAY"):
            raise RuntimeError("BLOCKED: no X11 DISPLAY")
        actual_sha=sha256(archive)
        if args.extension_sha256 and actual_sha!=args.extension_sha256.lower():
            raise RuntimeError("Extension ZIP SHA-256 mismatch")
        result["extension_sha256"]=actual_sha
        with tempfile.TemporaryDirectory(prefix="ga-codebrowser-only-") as root:
            work=Path(root)
            for name in ("home","project","cache","classes","index"):
                (work/name).mkdir()
            settings=work/"settings"
            user=os.environ.get("USER","ghidra-ci")
            ext=settings/(user+"-ghidra")/"ghidra_12.1.4_PUBLIC"/"Extensions"
            ext.mkdir(parents=True)
            zip_extension(archive,ext)
            fixture(work/"synthetic-mmio.bin",True)
            fixture(work/"guard-other.bin",False)
            env=dict(os.environ)
            env["JAVA_HOME"]=str(java)
            env["PATH"]=str(java/"bin")+os.pathsep+env.get("PATH","")
            env["JAVA_TOOL_OPTIONS"]=(
                f"-Dapplication.settingsdir={settings} "
                f"-Dapplication.cachedir={work/'cache'} "
                f"-Duser.home={work/'home'}")
            headless=ghidra/"support/analyzeHeadless"
            for name in ("synthetic-mmio.bin","guard-other.bin"):
                cmd=[str(headless),str(work/"project"),"CodeBrowserFixture",
                     "-import",str(work/name),"-loader","BinaryLoader",
                     "-processor","68000:BE:32:CPU32","-cspec","default",
                     "-noanalysis"]
                subprocess_checked(cmd,work,env,out/(name+".import.log"),180)
            project=work/"project"/"CodeBrowserFixture.gpr"
            if not project.is_file():
                raise RuntimeError("Synthetic Ghidra project was not created")
            case_id="synthetic-codebrowser-001"
            conf={"ghidra":str(ghidra),"project_dir":str(work/"project"),
                  "index":str(work/"index"),"run_id":run_id,"case_id":case_id,
                  "bridge_timeout":args.bridge_timeout if args.bridge_mode!="off" else 0,
                  "cua_hold_seconds":args.cua_timeout if args.cua_live else 0,
                  "automation_probe":args.automation_probe}
            conf_path=work/"config.json"
            conf_path.write_text(json.dumps(conf),encoding="utf-8")
            jars=sorted(set(ghidra.rglob("*.jar")) | set(ext.rglob("*.jar")))
            cp=os.pathsep.join(map(str,jars))
            subprocess_checked([str(java/"bin/javac"),"-cp",cp,
                "-d",str(work/"classes"),str(SRC),
                str(SRC.parent/"CodeBrowserAssertionReceipt.java"),
                str(SRC.parent/"CodeBrowserCuaHold.java")],
                work,env,out/"compile.log",120)
            if args.automation_probe:
                # Exercise the production opt-in HTTP server in the same JVM
                # as the existing real Swing/CodeBrowser fixture.
                token=uuid.uuid4().hex+uuid.uuid4().hex
                env["JAVA_TOOL_OPTIONS"] += (
                    " -Dghidrassist.automation.enabled=true"
                    " -Dghidrassist.automation.ready="+str(out/"api-ready.json")+
                    " -Dghidrassist.automation.allowProgramSwitch=true")
                if args.review_copy_probe:
                    env["JAVA_TOOL_OPTIONS"] += (
                        " -Dghidrassist.automation.writeMode=AUTO_SAFE"
                        " -Dghidrassist.automation.reviewCopy=true"
                        " -Dghidrassist.automation.reviewCopyProject="+str(project)+
                        " -Dghidrassist.automation.reviewCopyProgram=/synthetic-mmio.bin"
                        " -Dghidrassist.automation.reviewCopySha256="+sha256(work/"synthetic-mmio.bin"))
                else:
                    env["JAVA_TOOL_OPTIONS"] += " -Dghidrassist.automation.syntheticWrites=true"
            if args.automation_probe:
                env["GHIDRASSIST_AUTOMATION_TOKEN"]=token
            cmd=[str(java/"bin/java"),
                 "-Djava.system.class.loader=ghidra.GhidraClassLoader",
                 "-Djava.awt.headless=false",
                 f"-Dapplication.settingsdir={settings}",
                 f"-Dapplication.cachedir={work/'cache'}",
                 f"-Duser.home={work/'home'}",
                 "-cp",str(work/"classes")+os.pathsep+cp,
                 "CodeBrowserMmioMain",str(conf_path),str(out)]
            with (out/"java.log").open("x") as log:
                process=subprocess.Popen(cmd,cwd=work,env=env,
                    stdout=log,stderr=subprocess.STDOUT,
                    start_new_session=True)
                observer=None
                try:
                    if args.automation_probe:
                        # Wait for the actual production server before dispatching.
                        deadline=time.monotonic()+45
                        while not (out/"api-ready.json").is_file():
                            if process.poll() is not None:
                                raise RuntimeError("Ghidra exited before HTTP Automation ready")
                            if time.monotonic()>deadline:
                                raise RuntimeError("HTTP Automation readiness timed out")
                            time.sleep(0.05)
                        receipt=json.loads((out/"api-ready.json").read_text())
                        if receipt.get("schema")!=3 or not receipt.get("port"):
                            raise RuntimeError("Invalid HTTP Automation ready receipt")
                        from urllib.request import Request,urlopen
                        payload=json.dumps({"method":"ui.snapshot","params":{}}).encode()
                        request=Request(
                            "http://127.0.0.1:%d/rpc"%receipt["port"],data=payload,
                            headers={"Authorization":"Bearer "+token,
                                     "Content-Type":"application/json"},method="POST")
                        with urlopen(request,timeout=20) as reply:
                            snapshot=json.loads(reply.read())
                        if (snapshot.get("schema")!=3 or
                                snapshot.get("program")!="synthetic-mmio.bin" or
                                "hardware" not in snapshot.get("ui",{})):
                            raise RuntimeError("Production HTTP Swing snapshot invalid")
                        (out/"api-snapshot.json").write_text(json.dumps(snapshot,indent=2))
                        def http_call(method,params=None):
                            message=json.dumps({"method":method,"params":params or {}}).encode()
                            call=Request(
                                "http://127.0.0.1:%d/rpc"%receipt["port"],
                                data=message,
                                headers={"Authorization":"Bearer "+token,
                                         "Content-Type":"application/json"},
                                method="POST")
                            with urlopen(call,timeout=30) as reply:
                                return json.loads(reply.read())
                        # Idempotent same-project open, with no reload/DB edit.
                        current_open=http_call("project.program.open",
                            {"path":"/synthetic-mmio.bin"})
                        if (current_open.get("opened_program")!="synthetic-mmio.bin" or
                                current_open.get("active") is not True):
                            raise RuntimeError("Project program-open did not preserve active fixture")
                        from urllib.error import HTTPError
                        for unsafe_path in ("/../guard-other.bin","/missing.bin"):
                            try:
                                http_call("project.program.open",{"path":unsafe_path})
                            except HTTPError as error:
                                if error.code!=400: raise
                            else:
                                raise RuntimeError("Unsafe/missing project program path accepted")
                        policy=http_call("session.status")
                        if (policy.get("write_mode")!="AUTO_SAFE" or
                                policy.get("production_writes_enabled") is not False or
                                policy.get("synthetic_write_pilot_enabled") is not (not args.review_copy_probe) or
                                policy.get("review_copy_enabled") is not args.review_copy_probe):
                            raise RuntimeError("Synthetic write policy not correctly scoped: "+str(policy))
                        started=http_call("hardware.analyze")
                        if started.get("schema")!=3:
                            raise RuntimeError("HTTP Analyze failed")
                        deadline=time.monotonic()+45
                        while True:
                            state=http_call("hardware.task").get("task",{})
                            if state.get("state")=="COMPLETED":
                                break
                            if state.get("state")!="RUNNING" or time.monotonic()>deadline:
                                raise RuntimeError("HTTP hardware task did not complete: "+str(state))
                            time.sleep(0.08)
                        rows=http_call("hardware.mmio.rows",
                                       {"filter":"SIMCR","offset":0,"limit":10})
                        table=rows.get("table",{})
                        if table.get("total")!=1 or len(table.get("rows",[]))!=1:
                            raise RuntimeError("Expected one source-only SIMCR MMIO site: "+str(table))
                        site=table["rows"][0]
                        if site.get("register")!="SIMCR":
                            raise RuntimeError("Wrong MMIO register in HTTP table")
                        pc=site["pc"]
                        navigated=http_call("listing.goto",{"address":pc})
                        if navigated.get("requested_address","").lower()!=pc.lower().removeprefix("0x"):
                            raise RuntimeError("HTTP Listing navigation mismatch: "+str(navigated))
                        listing=http_call("listing.snapshot")
                        if int(listing.get("address","0"),16)!=int(pc,16):
                            raise RuntimeError("HTTP Listing did not reach SIMCR reference")
                        # Production HTTP traversal, same actual CodeBrowser Program.
                        paths_reply=http_call("analysis.paths",
                            {"origin":"reset","max_depth":4,"offset":0,"limit":10})
                        graph=paths_reply.get("paths",{})
                        if (graph.get("root","").lower().removeprefix("0x")!="00000020" or
                                graph.get("reachable_count")!=1 or
                                graph.get("total_paths")!=1 or
                                len(graph.get("paths",[]))!=1):
                            raise RuntimeError("HTTP direct-call traversal invalid: "+str(graph))
                        evidence=graph["paths"][0]
                        if (int(evidence.get("write_site","0"),16)!=0x20 or
                                int(evidence.get("mmio_target","0"),16)!=0xFFFA00 or
                                evidence.get("call_sites")!=[]):
                            raise RuntimeError("HTTP MMIO write evidence invalid: "+str(evidence))
                        second_page=http_call("analysis.paths",
                            {"origin":"entry","entry":"00000020",
                             "max_depth":4,"offset":1,"limit":1}).get("paths",{})
                        if second_page.get("total_paths")!=1 or second_page.get("paths")!=[]:
                            raise RuntimeError("HTTP paths pagination invalid")
                        # Read-only Review gates: generic CPU32 must not
                        # inherit MC68332 proposals; explicit selection does
                        # not edit the Ghidra database.
                        from urllib.error import HTTPError
                        try:
                            http_call("hardware.review.preview",{"offset":0,"limit":10})
                        except HTTPError as error:
                            if error.code != 400:
                                raise
                        else:
                            raise RuntimeError("Generic CPU32 received concrete Review proposals")
                        selected=http_call("hardware.profile.select",
                                           {"profile":"MC68332_USER_SELECTED"})
                        if "MC68332" not in selected.get("ui",{}).get("hardware",{}).get("profile",""):
                            raise RuntimeError("Explicit hardware profile not selected")
                        http_call("hardware.analyze")
                        deadline=time.monotonic()+45
                        while True:
                            review_task=http_call("hardware.task").get("task",{})
                            if review_task.get("state")=="COMPLETED":
                                break
                            if review_task.get("state")!="RUNNING" or time.monotonic()>deadline:
                                raise RuntimeError("MC68332 Review prerequisite analysis incomplete")
                            time.sleep(0.08)
                        # Real CodeBrowser / HTTP API: safe control and evidence
                        # endpoints (never mutate the Ghidra database).
                        changed=http_call("ui.tab.select",{"tab":"Hardware Analysis"})
                        if changed.get("ui",{}).get("selected_tab")!="Hardware Analysis":
                            raise RuntimeError("Tab selection did not reach Swing UI")
                        try:
                            http_call("ui.tab.select",{"tab":"nonexistent"})
                        except HTTPError as error:
                            if error.code!=400: raise
                        else:
                            raise RuntimeError("Unknown UI tab was accepted")
                        for method in ("analysis.report","analysis.export"):
                            page=http_call(method,{"format":"markdown","offset":0,"limit":128}).get("report",{})
                            if (page.get("format")!="markdown" or
                                    not 0<len(page.get("text",""))<=128 or
                                    page.get("total_characters",0)<len(page["text"]) or
                                    not page.get("revision")):
                                raise RuntimeError("Hardware evidence page invalid: "+str(page))
                            end=http_call(method,{"format":"markdown",
                                "offset":page["total_characters"],"limit":128}).get("report",{})
                            if end.get("text")!="" or end.get("more") is not False:
                                raise RuntimeError("End-of-report page invalid")
                        try:
                            http_call("analysis.report",{"format":"markdown","offset":0,"limit":8193})
                        except HTTPError as error:
                            if error.code!=400: raise
                        else:
                            raise RuntimeError("Unbounded report page was accepted")
                        try:
                            http_call("hardware.cancel")
                        except HTTPError as error:
                            if error.code!=400: raise
                        else:
                            raise RuntimeError("Cancellation incorrectly accepted without a task")
                        reviewed=http_call("hardware.review.preview",{"offset":0,"limit":10})
                        proposals=reviewed.get("review",{})
                        if (not proposals.get("total") or not proposals.get("rows") or
                                "PREVIEW ONLY" not in proposals.get("scope","")):
                            raise RuntimeError("Concrete read-only Review failed: "+str(proposals))
                        selected_row=http_call("ui.table.select",
                            {"table":"hardware.mmio","row":0}).get("selection",{})
                        if (selected_row.get("table")!="hardware.mmio" or
                                selected_row.get("row")!=0 or
                                selected_row.get("selected") is not True or
                                not selected_row.get("pc")):
                            raise RuntimeError("MMIO JTable selection failed: "+str(selected_row))
                        try:
                            http_call("ui.table.select",{"table":"hardware.mmio","row":999999})
                        except HTTPError as error:
                            if error.code!=400: raise
                        else:
                            raise RuntimeError("Out-of-range JTable selection accepted")
                        candidates=[row for row in proposals["rows"]
                                    if row.get("kind")=="MEMORY" and row.get("state")=="READY"
                                    and row.get("selected_by_default") and
                                    not row.get("name","").startswith("CS") and
                                    "CANDIDATE" not in row.get("name","")]
                        if not candidates:
                            raise RuntimeError("No safe synthetic memory item for Apply")
                        chosen=candidates[0]
                        prepare_method=("hardware.review.prepare" if args.review_copy_probe else "hardware.apply.prepare")
                        apply_method=("hardware.review.apply" if args.review_copy_probe else "hardware.apply.commit")
                        undo_method=("hardware.review.undo" if args.review_copy_probe else "hardware.apply.undo")
                        prepared=http_call(prepare_method,{"index":chosen["index"]})["approval"]
                        if args.review_copy_probe:
                            if (prepared.get("project_program_path")!="/synthetic-mmio.bin" or
                                    prepared.get("source_sha256","").lower()!=sha256(work/"synthetic-mmio.bin") or
                                    "WORKING COPY" not in prepared.get("scope","")):
                                raise RuntimeError("Review-copy approval was not tied to exact source/program")

                        try:
                            http_call(apply_method,{"token":"invalid","name":prepared["name"]})
                        except HTTPError as error:
                            if error.code!=400: raise
                        else:
                            raise RuntimeError("Wrong approval token accepted")
                        try:
                            http_call(apply_method,
                                      {"token":prepared["token"],"name":prepared["name"]})
                        except HTTPError as error:
                            if error.code!=400: raise
                        else:
                            raise RuntimeError("Consumed approval token accepted")
                        prepared=http_call(prepare_method,{"index":chosen["index"]})["approval"]
                        applied=http_call(apply_method,
                                          {"token":prepared["token"],"name":prepared["name"]})["apply"]
                        if applied.get("changed")!=1 or applied.get("skipped")!=0:
                            raise RuntimeError("Synthetic Apply outcome mismatch")
                        # Ensure the transaction actually mapped memory, and
                        # Undo actually removed that new block (not just a flag).
                        region_start=chosen["location"].split("..",1)[0]
                        created=http_call("listing.goto",{"address":region_start})
                        if not created.get("requested_address"):
                            raise RuntimeError("Applied region is not mapped")
                        try:
                            http_call(prepare_method,{"index":chosen["index"]})
                        except HTTPError as error:
                            if error.code!=400: raise
                        else:
                            raise RuntimeError("Stacked Apply was not blocked")
                        undid=http_call(undo_method)["undo"]
                        if undid.get("undone") is not True:
                            raise RuntimeError("Synthetic Ghidra Undo unsuccessful")
                        try:
                            http_call("listing.goto",{"address":region_start})
                        except HTTPError as error:
                            if error.code!=400: raise
                        else:
                            raise RuntimeError("Undo left synthetic module memory mapped")
                        try:
                            http_call(undo_method)
                        except HTTPError as error:
                            if error.code!=400: raise
                        else:
                            raise RuntimeError("Second Undo incorrectly succeeded")
                        (out/"api-apply-undo.json").write_text(json.dumps(
                            {"schema":3,"approval_name":prepared["name"],"apply":applied,
                             "undo":undid,"wrong_token_rejected":True,
                             "consumed_token_rejected":True,"second_undo_rejected":True},indent=2))
                        http_call("hardware.profile.select",{"profile":"CPU32_SURVEY"})
                        (out/"api-review-preview.json").write_text(json.dumps(
                            {"schema":3,"concrete_preview":proposals,
                             "generic_blocked":True,"database_edits":False},indent=2))

                        active=http_call("function.snapshot").get("function",{})
                        if (active.get("entry") not in ("00000020","0x00000020") or
                                active.get("name")!="FUN_00000020" or
                                active.get("body_addresses",0)<1):
                            raise RuntimeError("Active CodeBrowser function mismatch: "+str(active))
                        links=http_call("function.xrefs",{"offset":0,"limit":10}).get("xrefs",{})
                        if (links.get("entry") not in ("00000020","0x00000020") or
                                links.get("rows") is None or links.get("limit")!=10):
                            raise RuntimeError("Active function XREF snapshot invalid: "+str(links))
                        (out/"api-function-xrefs.json").write_text(json.dumps(
                            {"schema":3,"function":active,"xrefs":links},indent=2))
                        requested=http_call("decompiler.start").get("decompiler",{})
                        if requested.get("state")!="RUNNING" or not requested.get("task_id"):
                            raise RuntimeError("Decompiler task did not start")
                        decomp={}
                        for _ in range(40):
                            decomp=http_call("decompiler.status",{"offset":0,"limit":128}).get("decompiler",{})
                            if decomp.get("state")!="RUNNING":
                                break
                            time.sleep(0.25)
                        if decomp.get("state")!="COMPLETED":
                            raise RuntimeError("Decompiler task not complete: "+str(decomp))
                        if "FUN_00000020" not in decomp.get("text","") and not decomp.get("total_characters",0)>0:
                            raise RuntimeError("Decompiler empty function result")
                        if len(decomp.get("text",""))>128:
                            raise RuntimeError("Decompiler pagination limit exceeded")
                        tail=http_call("decompiler.status",
                                       {"offset":decomp["total_characters"],"limit":128}).get("decompiler",{})
                        if tail.get("text")!="":
                            raise RuntimeError("Decompiler end page not empty")
                        (out/"api-decompiler.json").write_text(json.dumps(
                            {"schema":3,"task":requested,"first_page":decomp,"end_page":tail},indent=2))
                        merged=http_call("analysis.bundle").get("analysis",{})
                        if (merged.get("entry") not in ("00000020","0x00000020") or
                                merged.get("name")!="FUN_00000020" or
                                not isinstance(merged.get("incoming_entry_xrefs"),list) or
                                not isinstance(merged.get("mmio_reference_candidates"),list) or
                                merged.get("decompiler",{}).get("state")!="RUNNING"):
                            raise RuntimeError("Unified analysis bundle invalid: "+str(merged))
                        (out/"api-analysis-bundle.json").write_text(json.dumps(
                            {"schema":3,"bundle":merged},indent=2))
                        (out/"api-hardware-e2e.json").write_text(json.dumps(
                            {"schema":3,"task":state,"mmio":table,
                             "navigation":navigated,"listing":listing},indent=2))

                        with (out/"automation-controller.log").open("x") as controller_log:
                            observer=subprocess.Popen(
                                [sys.executable,str(SRC.parent/"automation_controller.py"),
                                 "--directory",str(out)],cwd=work,env=env,
                                stdout=controller_log,stderr=subprocess.STDOUT,
                                start_new_session=True)
                        code=process.wait(timeout=args.timeout)
                    elif args.cua_live and args.cua_ci_response!="none":
                        with (out/"cua-observer.log").open("x") as observer_log:
                            observer=subprocess.Popen(
                                [sys.executable,str(SRC.parent/"ci_cua_observer.py"),
                                 "--workspace",str(target),"--run-id",run_id,
                                 "--mode",args.cua_ci_response,
                                 "--timeout",str(args.cua_timeout)],
                                cwd=work,env=env,stdout=observer_log,
                                stderr=subprocess.STDOUT,start_new_session=True)
                        code=process.wait(timeout=args.timeout)
                    elif args.bridge_mode=="ci":
                        # Distinct disposable CI process observes live X11.
                        # Actual Wyse bridge remains Supervisor-owned.
                        with (out/"observer.log").open("x") as observer_log:
                            observer=subprocess.Popen(
                                [sys.executable,str(SRC.parent/"ci_x11_observer.py"),
                                 "--workspace",str(target),"--run-id",run_id,
                                 "--timeout",str(args.bridge_timeout)],
                                cwd=work,env=env,stdout=observer_log,
                                stderr=subprocess.STDOUT,start_new_session=True)
                            code=process.wait(timeout=args.timeout)
                    else:
                        code=process.wait(timeout=args.timeout)
                    if code:
                        raise RuntimeError(f"Real CodeBrowser Java test exit {code}")
                    if observer is not None and observer.wait(timeout=10):
                        raise RuntimeError("CI external X11 observer failed")
                finally:
                    if observer is not None:
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(observer.pid,signal.SIGTERM)
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(observer.pid,signal.SIGKILL)
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid,signal.SIGTERM)
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid,signal.SIGKILL)
            if args.automation_probe:
                observed=json.loads((out/"automation-java-result.json").read_text())
                final=json.loads((out/"automation-4-response.json").read_text())
                if (observed.get("external_automation_probe") is not True or
                        observed.get("automation_protocol_schema")!=2 or
                        final.get("schema")!=2 or final.get("sequence")!=4 or
                        final.get("action")!="listing.snapshot" or
                        int(final.get("listing_address","0"),16)!=0x20):
                    raise RuntimeError("External v2 automation contract incomplete")
                result.update(status="PASSED_HARDWARE_AUTOMATION_V2",
                              ghidra_version=VERSION,synthetic_only=True,
                              automation_protocol_schema=2,
                              assertions=["ui.snapshot","hardware.analyze",
                                          "listing.goto","listing.snapshot"],
                              supervisor_ack=False,formal_gui_pass=False)
                (out/"result.json").write_text(json.dumps(result,indent=2)+"\\n",
                                              encoding="utf-8")
                print(json.dumps(result,indent=2))
                return 0
            if not (out/"tool-template.xml").is_file():
                raise RuntimeError("Persisted GhidraTool template XML missing")
            # A completely new JVM/application initialization must read the
            # saved template; same-process reloading alone is insufficient.
            with (out/"restart-java.log").open("x") as restart_log:
                restarted=subprocess.Popen(cmd+["restore"],cwd=work,env=env,
                    stdout=restart_log,stderr=subprocess.STDOUT,
                    start_new_session=True)
                try:
                    code=restarted.wait(timeout=args.timeout)
                    if code:
                        raise RuntimeError(
                            f"Restarted CodeBrowser Java test exit {code}")
                finally:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(restarted.pid,signal.SIGTERM)
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(restarted.pid,signal.SIGKILL)
            restart=json.loads((out/"restart-results.json")
                               .read_text(encoding="utf-8"))
            for name in ("restart_process_verified","codebrowser_restored",
                         "ghidrassist_restored","no_repeated_plugin_prompt"):
                if restart.get(name) is not True:
                    raise RuntimeError("CodeBrowser restart failed: "+name)
            data=json.loads((out/"gui-results.json").read_text(encoding="utf-8"))
            # Receipt is emitted from the SAME Java JVM that navigated to
            # the actual synthetic Listing and captured the unmodified X11 PNG.
            # The verification here is structural consistency, NOT trusted
            # provenance, semantic visual readback or native GUI acceptance.
            try:
                proof=validate_files(out/"codebrowser-assertions.json",
                                     out/"ghidra-window.png",
                                     case_id=case_id,run_id=run_id)
            except ValueError as error:
                # Synthetic-only Ghidra window metadata, no private data.
                observed=json.loads((out/"codebrowser-assertions.json")
                                    .read_text(encoding="utf-8"))
                raise RuntimeError(
                    f"Assertion receipt invalid: {error}; X11={observed.get('window_id')!r}, "
                    f"WM_CLASS={observed.get('window_class')!r}, "
                    f"full_title={observed.get('window_title')!r}") from error
            if args.automation_probe:
                snapshot=json.loads((out/"automation-response.json").read_text())
                if not (snapshot.get("selected_tab")=="Hardware Analysis" and
                        snapshot.get("program")=="synthetic-mmio.bin" and
                        snapshot.get("mmio_enabled") is True and
                        snapshot.get("edt") is True):
                    raise RuntimeError("External hardware automation snapshot failed")
                result["hardware_automation_pilot"]="PASS"
            if args.cua_live:
                hold=json.loads((out/"cua-live-result.json").read_text())
                captured=json.loads((out/"codebrowser-assertions.json").read_text())
                validate_cua_hold(hold,captured,run_id)
                result["live_cua_hold_result"]=hold["result"]
            if args.bridge_mode!="off":
                ready=json.loads((out/"capture-ready.json").read_text())
                receipt=json.loads((out/"codebrowser-assertions.json").read_text())
                host_dir=evidence/("pilot-x11-"+run_id)
                bridge,bridge_json_raw,bridge_png_raw=read_private_capture(
                    evidence,run_id)
                verified=verify_bridge(
                    ready,receipt,bridge,bridge_png_raw,run_id)
                if not verified["structurally_correlated"]:
                    raise RuntimeError("GUI-06 structural correlation missing")
                # Four hashes are candidate pins only; the actual Supervisor
                # must independently hash the two original sources on host.
                digest_manifest={
                    "schema":1,"kind":"ga18-gui06-original-four-sha256",
                    "case_id":case_id,"run_id":run_id,
                    "window_id":receipt["window_id"],
                    "harness_json_sha256":sha256(out/"codebrowser-assertions.json"),
                    "harness_png_sha256":sha256(out/"ghidra-window.png"),
                    "bridge_json_sha256":byte_sha256(bridge_json_raw),
                    "bridge_png_sha256":byte_sha256(bridge_png_raw),
                    "independently_pinned_by_supervisor":False,
                    "visual_readback_verified":False,
                    "supervisor_ack":False,"formal_gui_pass":False,
                }
                (out/"four-original-sha256.json").write_text(
                    json.dumps(digest_manifest,indent=2)+"\n",
                    encoding="utf-8")
                saved_manifest=json.loads(
                    (out/"four-original-sha256.json").read_text(encoding="utf-8"))
                checks={
                    "harness_json_sha256":sha256(out/"codebrowser-assertions.json"),
                    "harness_png_sha256":sha256(out/"ghidra-window.png"),
                    "bridge_json_sha256":byte_sha256(bridge_json_raw),
                    "bridge_png_sha256":byte_sha256(bridge_png_raw),
                }
                if any(saved_manifest[key]!=value
                       for key,value in checks.items()):
                    raise RuntimeError("Four-source digest verification failed")
                # Reject a bridge that replaces any original after validation.
                _,rechecked_json,rechecked_png=read_private_capture(
                    evidence,run_id)
                if (rechecked_json!=bridge_json_raw or
                        rechecked_png!=bridge_png_raw):
                    raise RuntimeError("Bridge originals changed after verification")
                result["external_capture_correlated_structurally"]=True
                result["external_png_sha256"]=bridge["captured_screenshot_sha256"]
            if not proof["structural_evidence_consistent"]:
                raise RuntimeError("Incomplete in-process CodeBrowser receipt")
            original=out/"ghidra-window.png"
            # Legacy screenshot path must have identical original bytes.
            if sha256(original)!=sha256(out/"codebrowser-x11.png"):
                raise RuntimeError("Original X11 screenshot and compatibility copy differ")
            if data.get("same_run_receipt_created") is not True:
                raise RuntimeError("CodeBrowser did not emit authenticated-in-run receipt")
            # Independently check real X11 Robot screenshot evidence.
            # The PNG contents are still NOT a human/model visual readback.
            shot=out/"codebrowser-x11.png"
            raw=shot.read_bytes()
            if len(raw)<4096 or raw[:8]!=b"\x89PNG\r\n\x1a\n":
                raise RuntimeError("Missing or invalid real X11 PNG screenshot")
            length=struct.unpack(">I",raw[8:12])[0]
            if length!=13 or raw[12:16]!=b"IHDR":
                raise RuntimeError("X11 screenshot missing bounded PNG IHDR")
            if (zlib.crc32(raw[12:29]) & 0xffffffff)!=struct.unpack(
                    ">I",raw[29:33])[0]:
                raise RuntimeError("X11 screenshot IHDR checksum invalid")
            width,height=struct.unpack(">II",raw[16:24])
            if (width<640 or height<400 or width>8192 or height>8192 or
                    data.get("x11_screenshot_width")!=width or
                    data.get("x11_screenshot_height")!=height or
                    data.get("x11_screenshot_sha256")!=sha256(shot)):
                raise RuntimeError("X11 screenshot SHA-256 / dimensions invalid")
            if data.get("visual_readback_verified") is not False or (
                    data.get("human_visual_readback")!="NOT_PERFORMED"):
                raise RuntimeError("Synthetic screenshot cannot claim human visual verification")
            expected=("synthetic_simcr_site","hardware_analyze_gui",
                      "listing_navigation","stale_go_to_rejected",
                      "stale_double_click_rejected",
                      "listing_remained_second_program",
                      "read_only_analyze",
                      "synthetic_apply_undo_verified",
                      "review_gui_cancel_no_change",
                      "review_gui_consent_and_undo_verified",
                      "cs_review_never_auto_selected",
                      "conflict_alias_cs_windows_blocked",
                      "tool_template_saved",
                      "extension_metadata_serialized",
                      "tool_template_reloaded",
                      "no_new_extension_prompt_on_restore",
                      "window_identity_verified",
                      "codebrowser_listing_verified",
                      "x11_screenshot_captured")
            for name in expected:
                if data.get(name) is not True:
                    raise RuntimeError("Missing actual GUI evidence: "+name)
            if data.get("application_headless") or data.get("awt_headless"):
                raise RuntimeError("Headless simulation is not real CodeBrowser")
            result.update({"status":("LIVE_CUA_WINDOW_RELEASED_STRUCTURAL_ONLY"
                                     if args.cua_live else
                                     "PASSED_SYNTHETIC_CODEBROWSER"),
                           "ghidra_version":VERSION,
                           "synthetic_only":True,"assertions":list(expected),
                           "restart_process_verified":True,
                           "no_repeated_plugin_prompt":True,
                           "window_identity_verified":True,
                           "codebrowser_listing_verified":True,
                           "x11_screenshot_sha256":sha256(shot),
                           "x11_capture_proof_verified":True,
                           "assertions_report_sha256":sha256(out/"codebrowser-assertions.json"),
                           "same_run_structural_receipt":True,
                           "case_id":case_id,"run_id":run_id,
                           "trusted_ghidra_provenance_verified":False,
                           "same_run_semantics_verified":False,
                           "visual_readback_verified":False,
                           "supervisor_ack":False,"formal_gui_pass":False})
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired,
            zipfile.BadZipFile) as error:
        result["reason"]=str(error)[:400]
    finally:
        (out/"result.json").write_text(json.dumps(result,indent=2)+"\n",
                                       encoding="utf-8")
    print(json.dumps(result,indent=2))
    return 0 if result["status"] in (
        "PASSED_SYNTHETIC_CODEBROWSER",
        "LIVE_CUA_WINDOW_RELEASED_STRUCTURAL_ONLY") else 1


if __name__=="__main__":
    sys.exit(main())
