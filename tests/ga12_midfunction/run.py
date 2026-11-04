#!/usr/bin/env python3
"""Real synthetic Ghidra three-JVM partial-function restart and invalidation."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE=Path(__file__).parent
LEGACY=HERE.parent/"ga11_headless"/"run.py"
spec=importlib.util.spec_from_file_location("_ga11_test_helpers",LEGACY)
helper=importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra",required=True)
    parser.add_argument("--java-home",required=True)
    parser.add_argument("--extension-zip",required=True)
    parser.add_argument("--extension-sha256",required=True)
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    out=Path(args.output).absolute()
    if out.is_symlink() or (out.exists() and
            (not out.is_dir() or any(out.iterdir()))):
        parser.error("output must be an empty ordinary directory")
    out.mkdir(parents=True,exist_ok=True)
    summary={"schema":1,"status":"BLOCKED","synthetic_only":True,
             "ghidra_version":"12.1.4","runtime":"real Ghidra headless",
             "supervisor_pass":False}
    try:
        ghidra=Path(args.ghidra).resolve(strict=True)
        java=Path(args.java_home).resolve(strict=True)
        archive=Path(args.extension_zip).resolve(strict=True)
        if not ghidra.name.startswith("ghidra_12.1.4_PUBLIC"):
            raise ValueError("Wrong Ghidra distribution")
        if helper.digest(archive)!=args.extension_sha256.lower():
            raise ValueError("Extension ZIP SHA mismatch")
        summary["extension_sha256"]=args.extension_sha256
        with tempfile.TemporaryDirectory(prefix="ga12-real-ghidra-") as temp:
            work=Path(temp)
            for name in ("home","cache","project","classes","durable"):
                (work/name).mkdir()
            settings=work/"settings"
            extension=settings/"ci-ghidra"/"ghidra_12.1.4_PUBLIC"/"Extensions"
            extension.mkdir(parents=True)
            jar=helper.install(archive,extension)
            helper.fixture(work/"vectors-full.bin")
            env=dict(os.environ)
            env["USER"]="ci"
            env["JAVA_HOME"]=str(java)
            env["PATH"]=str(java/"bin")+os.pathsep+env.get("PATH","")
            env["JAVA_TOOL_OPTIONS"]=(
                f"-Dapplication.settingsdir={settings} "
                f"-Dapplication.cachedir={work/'cache'} "
                f"-Duser.home={work/'home'} -Djava.awt.headless=true")
            helper.call([str(ghidra/"support/analyzeHeadless"),
                str(work/"project"),"Ga11Vectors","-import",
                str(work/"vectors-full.bin"),"-loader","BinaryLoader",
                "-processor","68000:BE:32:CPU32","-cspec","default",
                "-noanalysis"],work,env,out/"import.log",timeout=240)
            if not (work/"project/Ga11Vectors.gpr").is_file():
                raise RuntimeError("Synthetic Ghidra project missing")
            jars=sorted(set(ghidra.rglob("*.jar"))|set(extension.rglob("*.jar")))
            cp=os.pathsep.join(str(x) for x in jars)
            helper.call([str(java/"bin/javac"),"-cp",cp,"-d",
                str(work/"classes"),str(HERE/"Ga12FixedPointRealGhidraMain.java")],
                work,env,out/"compile.log")
            keys={}
            for phase in ("write","read","edit"):
                helper.call([str(java/"bin/java"),
                    "-Djava.system.class.loader=ghidra.GhidraClassLoader",
                    "-Djava.awt.headless=true",
                    f"-Dapplication.settingsdir={settings}",
                    f"-Dapplication.cachedir={work/'cache'}",
                    f"-Duser.home={work/'home'}",
                    f"-Dghidrassist.ga12.durable.dir={work/'durable'}",
                    "-cp",str(work/"classes")+os.pathsep+cp,
                    "Ga12FixedPointRealGhidraMain",str(ghidra),
                    str(work/"project"),str(out),str(work/"durable"),phase],
                    work,env,out/("integration-"+phase+".log"),timeout=240)
                proof=json.loads((out/("ga12-midfunction-"+phase+".json")).read_text())
                if proof["phase"]!=phase or not proof["real_ghidra"]:
                    raise RuntimeError("Missing real-Ghidra phase proof")
                if proof["whole_stage_reused"] or not proof["program_unchanged"]:
                    raise RuntimeError("Partial stage used full report or modified Program")
                keys[phase]=(proof["project_id_sha256"],proof["input_sha256"])
                if phase=="read" and keys[phase]!=keys["write"]:
                    raise RuntimeError("Persisted Ghidra Program content key changed after reopen")
                if phase=="edit" and (keys[phase][0]!=keys["write"][0] or
                        keys[phase][1]==keys["write"][1]):
                    raise RuntimeError("Changed input is not distinguishable from saved Listing")
                if phase=="write" and (not proof["interrupted"] or
                        proof["worklist_saved"]<1):
                    raise RuntimeError("First process did not cancel after a saved function")
                if phase=="read" and proof["worklist_restored"]<1:
                    raise RuntimeError("New JVM did not restore completed function")
                if phase=="edit" and proof["worklist_restored"]!=0:
                    raise RuntimeError("Edited Ghidra Listing accepted stale function")
            summary.update({"status":"PASSED_SYNTHETIC_REAL_GHIDRA_HEADLESS",
                "restart_processes":3,
                "partial_iteration_cancelled":True,"reopened_worklist_restored":True,
                "edited_worklist_invalidated":True,
                "source_data":"synthetic-only",
                "tested_stage":"pending fixed-point worklist within interrupted function"})
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error:
        summary["error_type"]=type(error).__name__
        summary["reason"]=str(error)[:600]
        raise
    finally:
        (out/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")

if __name__=="__main__":
    main()
