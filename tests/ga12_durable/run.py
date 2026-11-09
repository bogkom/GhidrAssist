#!/usr/bin/env python3
"""Real isolated Ghidra 12.1.4 PUBLIC GA-12 restart checkpoint regression."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys

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
                str(work/"classes"),str(HERE/"Ga12DurableRealGhidraMain.java")],
                work,env,out/"compile.log")
            for phase in ("write","read","edit"):
                helper.call([str(java/"bin/java"),
                    "-Djava.system.class.loader=ghidra.GhidraClassLoader",
                    "-Djava.awt.headless=true",
                    f"-Dapplication.settingsdir={settings}",
                    f"-Dapplication.cachedir={work/'cache'}",
                    f"-Duser.home={work/'home'}",
                    f"-Dghidrassist.ga12.durable.dir={work/'durable'}",
                    "-cp",str(work/"classes")+os.pathsep+cp,
                    "Ga12DurableRealGhidraMain",str(ghidra),
                    str(work/"project"),str(out),str(work/"durable"),phase],
                    work,env,out/("integration-"+phase+".log"),timeout=240)
                proof=json.loads((out/("ga12-"+phase+".json")).read_text())
                if proof["phase"]!=phase or not proof["ghidra_real"]:
                    raise RuntimeError("Missing real-Ghidra phase proof")
                if proof["reused"]!=(phase=="read"):
                    raise RuntimeError("Stage did not behave after restart")
                if phase!="edit" and not proof["program_modification_unchanged"]:
                    raise RuntimeError("Read-only real Ghidra Program modified")
                if not proof["checkpoint_exists"]:
                    raise RuntimeError("Durable disk snapshot missing")
            # GA-12 V2: a SECOND isolated Program with byte-exact real
            # CPU32 RESET/JSR/MOVEC witnesses, fully separate from vectors.
            source_file=work/"synthetic-reset-indirect-vbr.bin"
            helper.call([sys.executable,
                str(HERE.parent.parent/"tools/generate-synthetic-reset-indirect-vbr.py"),
                "--output",str(source_file)],
                work,env,out/"source-generator.log",timeout=30)
            helper.call([str(ghidra/"support/analyzeHeadless"),
                str(work/"project"),"Ga12SourceV2","-import",
                str(source_file),"-loader","BinaryLoader",
                "-processor","68000:BE:32:CPU32","-cspec","default",
                "-noanalysis",
                "-scriptPath",str(HERE.parent.parent/"tools/ghidra_scripts"),
                "-postScript","GA12BootstrapDurableSourceV2.java"],
                work,env,out/"source-import-bootstrap.log",timeout=240)
            bootstrap=(out/"source-import-bootstrap.log").read_text(
                encoding="utf-8",errors="replace")
            if ("GA12 SOURCE V2 REAL GHIDRA BOOTSTRAP PASS: functions=5"
                    not in bootstrap):
                raise RuntimeError(
                    "Actual Ghidra source fixture bootstrap did not PASS")
            if not (work/"project/Ga12SourceV2.gpr").is_file():
                raise RuntimeError("Real Ghidra V2 source project not saved")
            helper.call([str(java/"bin/javac"),"-cp",cp,"-d",
                str(work/"classes"),
                str(HERE/"Ga12DurableSourceV2RealGhidraMain.java")],
                work,env,out/"source-compile.log",timeout=120)
            source_proofs={}
            for source_phase in ("source-write","source-read","source-v1",
                                 "source-edit","source-profile"):
                helper.call([str(java/"bin/java"),
                    "-Djava.system.class.loader=ghidra.GhidraClassLoader",
                    "-Djava.awt.headless=true",
                    f"-Dapplication.settingsdir={settings}",
                    f"-Dapplication.cachedir={work/'cache'}",
                    f"-Duser.home={work/'home'}",
                    f"-Dghidrassist.ga12.durable.dir={work/'durable'}",
                    "-cp",str(work/"classes")+os.pathsep+cp,
                    "Ga12DurableSourceV2RealGhidraMain",str(ghidra),
                    str(work/"project"),str(out),str(work/"durable"),
                    source_phase],work,env,
                    out/("integration-"+source_phase+".log"),timeout=240)
                evidence=json.loads((out/("ga12-"+source_phase+".json"))
                    .read_text(encoding="utf-8"))
                if (evidence["phase"]!=source_phase or
                        not evidence["ghidra_real"] or
                        not evidence["checkpoint_exists"] or
                        evidence["reused"] !=
                        (source_phase in ("source-read","source-v1")) or
                        evidence["source_inventory_retained"] !=
                        (source_phase not in ("source-v1","source-profile"))):
                    raise RuntimeError(
                        "Cross-JVM source inventory/checkpoint did not retain/refuse")
                if source_phase in ("source-write","source-read","source-edit"):
                    if (evidence["source_pairs"]!=2 or
                            evidence["omitted_indirect"]!=1):
                        raise RuntimeError("Missing bounded native V2 source pairs")
                if source_phase!="source-edit" and not evidence["revision_unchanged"]:
                    raise RuntimeError("Read-only source restore mutated Program")
                source_proofs[source_phase]=evidence
            initial=source_proofs["source-write"]
            restored=source_proofs["source-read"]
            legacy=source_proofs["source-v1"]
            changed=source_proofs["source-edit"]
            generic=source_proofs["source-profile"]
            if not (initial["effective_input_sha256"]==
                    restored["effective_input_sha256"]==
                    legacy["effective_input_sha256"] and
                    initial["import_sha256"]==
                    restored["import_sha256"]==
                    changed["import_sha256"]==
                    legacy["import_sha256"]==
                    generic["import_sha256"] and
                    initial["effective_input_sha256"]!=
                    changed["effective_input_sha256"] and
                    initial["selected_mc68332"] and
                    restored["selected_mc68332"] and
                    legacy["selected_mc68332"] and
                    changed["selected_mc68332"] and
                    not generic["selected_mc68332"]):
                raise RuntimeError(
                    "Cross-JVM input/full-fingerprint/profile isolation failed")
            summary.update({"status":"PASSED_SYNTHETIC_REAL_GHIDRA_HEADLESS",
                "restart_processes":3,
                "cold_computed":True,"reopened_reused":True,
                "edited_recomputed":True,
                "source_data":"synthetic-only",
                "tested_stage":"completed CFG Report",
                "v2_source_processes":5,
                "v2_source_cold_computed":True,
                "v2_source_reopened_reused":True,
                "v1_legacy_cfg_only_reused":True,
                "v1_source_inventory_refused":True,
                "edited_v2_input_recomputed":True,
                "generic_cpu32_profile_refused":True,
                "byte_verified_jsr_movec_pairs":2,
                "unknown_indirect_sources":1})
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as error:
        summary["error_type"]=type(error).__name__
        summary["reason"]=str(error)[:600]
        raise
    finally:
        (out/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")

if __name__=="__main__":
    main()
