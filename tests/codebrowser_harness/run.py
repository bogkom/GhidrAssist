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
import subprocess
import sys
import tempfile
import zipfile

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
    args=ap.parse_args()
    if args.timeout<90 or args.timeout>900:
        ap.error("timeout must be 90..900 seconds")
    out=Path(args.output).expanduser()
    if out.is_symlink() or (out.exists() and
            (not out.is_dir() or any(out.iterdir()))):
        ap.error("output must be an empty non-symlink directory")
    out.mkdir(parents=True,exist_ok=True)
    result={"schema":1,"status":"BLOCKED","test":"synthetic-codebrowser",
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
            conf={"ghidra":str(ghidra),"project_dir":str(work/"project"),
                  "index":str(work/"index")}
            conf_path=work/"config.json"
            conf_path.write_text(json.dumps(conf),encoding="utf-8")
            jars=sorted(set(ghidra.rglob("*.jar")) | set(ext.rglob("*.jar")))
            cp=os.pathsep.join(map(str,jars))
            subprocess_checked([str(java/"bin/javac"),"-cp",cp,
                "-d",str(work/"classes"),str(SRC)],
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
                try:
                    code=process.wait(timeout=args.timeout)
                    if code:
                        raise RuntimeError(f"Real CodeBrowser Java test exit {code}")
                finally:
                    # Launcher may exit with a descendant JVM still in PGID.
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid,signal.SIGTERM)
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid,signal.SIGKILL)
            data=json.loads((out/"gui-results.json").read_text(encoding="utf-8"))
            expected=("synthetic_simcr_site","hardware_analyze_gui",
                      "listing_navigation","stale_go_to_rejected",
                      "stale_double_click_rejected",
                      "listing_remained_second_program",
                      "read_only_analyze","tool_template_saved",
                      "extension_metadata_serialized",
                      "tool_template_reloaded",
                      "no_new_extension_prompt_on_restore")
            for name in expected:
                if data.get(name) is not True:
                    raise RuntimeError("Missing actual GUI evidence: "+name)
            if data.get("application_headless") or data.get("awt_headless"):
                raise RuntimeError("Headless simulation is not real CodeBrowser")
            result.update({"status":"PASSED_SYNTHETIC_CODEBROWSER",
                           "ghidra_version":VERSION,
                           "synthetic_only":True,"assertions":list(expected)})
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
