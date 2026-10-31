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

from assertion_audit import validate_files, sha256 as byte_sha256
from gui06_protocol import verify as verify_bridge, reserve_run

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
    args=ap.parse_args()
    if args.timeout<90 or args.timeout>900:
        ap.error("timeout must be 90..900 seconds")
    if not 5<=args.bridge_timeout<=180:
        ap.error("bridge-timeout must be 5..180 seconds")
    run_id=uuid.uuid4().hex
    bridged=args.bridge_mode!="off"
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
                  "bridge_timeout":args.bridge_timeout if bridged else 0}
            conf_path=work/"config.json"
            conf_path.write_text(json.dumps(conf),encoding="utf-8")
            jars=sorted(set(ghidra.rglob("*.jar")) | set(ext.rglob("*.jar")))
            cp=os.pathsep.join(map(str,jars))
            subprocess_checked([str(java/"bin/javac"),"-cp",cp,
                "-d",str(work/"classes"),str(SRC),
                str(SRC.parent/"CodeBrowserAssertionReceipt.java")],
                work,env,out/"compile.log",120)
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
                    if args.bridge_mode=="ci":
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
            if bridged:
                ready=json.loads((out/"capture-ready.json").read_text())
                receipt=json.loads((out/"codebrowser-assertions.json").read_text())
                host_dir=evidence/("pilot-x11-"+run_id)
                bridge=json.loads((host_dir/"bridge-capture.json").read_text())
                verified=verify_bridge(
                    ready,receipt,bridge,
                    (host_dir/"ghidra-window.png").read_bytes(),run_id)
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
                    "bridge_json_sha256":sha256(host_dir/"bridge-capture.json"),
                    "bridge_png_sha256":sha256(host_dir/"ghidra-window.png"),
                    "independently_pinned_by_supervisor":False,
                    "visual_readback_verified":False,
                    "supervisor_ack":False,"formal_gui_pass":False,
                }
                (out/"four-original-sha256.json").write_text(
                    json.dumps(digest_manifest,indent=2)+"\\n",
                    encoding="utf-8")
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
            result.update({"status":"PASSED_SYNTHETIC_CODEBROWSER",
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
    return 0 if result["status"]=="PASSED_SYNTHETIC_CODEBROWSER" else 1


if __name__=="__main__":
    sys.exit(main())
