#!/usr/bin/env python3
"""Run real Ghidra 12.1.4 PUBLIC GA-11 service integration on ONLY synthetic files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile

SOURCE=Path(__file__).with_name("Ga11VectorHeadlessMain.java")

def digest(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for part in iter(lambda:f.read(1024*1024),b""):
            h.update(part)
    return h.hexdigest()

def fixture(path, short=False):
    data=bytearray(48 if short else 4096)
    def word(slot,value):
        if 4*slot+4<=len(data):
            data[slot*4:slot*4+4]=value.to_bytes(4,"big")
    word(0,0x1000)
    word(1,0x400)
    word(2,0x400)  # Real Ghidra function entry
    word(3,0x402)  # Interior of same Function body
    word(4,0x600)  # Mapped nonfunction
    word(5,0x9000) # Unmapped
    word(6,0x401)  # Odd
    word(7,0)
    word(8,0xffffffff)
    if not short:
        for n in range(20,55):
            word(n,0x9000+2*n)  # >32 nonempty entries forces row cap
        data[0x400:0x406]=bytes.fromhex("4e714e714e75")
        # Separate synthetic MMIO routine for optional GA-18 hardware checks.
        data[0x500:0x50a]=bytes.fromhex("33fc40ca00fffa004e75")
        # Conditional CSBAR source candidates: two contradictory complete
        # words plus a real register-indirect STORE with UNKNOWN A0 target.
        data[0x520:0x52a]=bytes.fromhex("33fc387c00fffa4c4e75")
        data[0x530:0x53a]=bytes.fromhex("33fc387e00fffa4c4e75")
        data[0x540:0x544]=bytes.fromhex("30804e75")
    path.write_bytes(data)

def install(zip_path,target):
    with zipfile.ZipFile(zip_path) as z:
        paths=z.infolist()
        if len(paths)>10000 or not any(
                i.filename=="GhidrAssist/extension.properties" for i in paths):
            raise ValueError("Incomplete extension ZIP")
        count=0
        for i in paths:
            path=i.filename
            mode=(i.external_attr>>16)&0o170000
            if (not path.startswith("GhidrAssist/") or
                    ".." in Path(path).parts or "\\" in path or ":" in path
                    or path.startswith("/") or mode==0o120000):
                raise ValueError("Unsafe extension ZIP path")
            count+=i.file_size
            if count>250*1024*1024:raise ValueError("Oversized extension")
        props=z.read("GhidrAssist/extension.properties").decode("utf-8")
        if not re.search(r"(?m)^version=12\.1\.4\s*$",props):
            raise ValueError("Extension version must be 12.1.4")
        z.extractall(target)
    jar=target/"GhidrAssist/lib/GhidrAssist.jar"
    if not jar.is_file() or jar.stat().st_size<1024:
        raise ValueError("Extension jar missing")
    return jar

def call(command,cwd,env,log,timeout=180):
    with log.open("x",encoding="utf-8") as out:
        result=subprocess.run(command,cwd=cwd,env=env,
                              stdout=out,stderr=subprocess.STDOUT,
                              timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"Command failed exit={result.returncode}: {log.name}")

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra",required=True)
    parser.add_argument("--java-home",required=True)
    parser.add_argument("--extension-zip",required=True)
    parser.add_argument("--extension-sha256",required=True)
    parser.add_argument("--output",required=True)
    parser.add_argument("--strict-entry",action="store_true")
    parser.add_argument("--ga18-mode",choices=("none","overview","cache","startup","csbar"),
                        default="none",help="Run GA-07/12 or GA-02/03 genuine headless source-evidence checks")
    args=parser.parse_args()
    out=Path(args.output).absolute()
    if out.is_symlink() or (out.exists() and
        (not out.is_dir() or any(out.iterdir()))):
        parser.error("output must be an empty ordinary directory")
    out.mkdir(parents=True,exist_ok=True)
    summary={"schema":1,"status":"BLOCKED","synthetic_only":True,
             "supervisor_ack":False,"strict_entry":args.strict_entry}
    try:
        ghidra=Path(args.ghidra).resolve(strict=True)
        java=Path(args.java_home).resolve(strict=True)
        package=Path(args.extension_zip).resolve(strict=True)
        if not ghidra.name.startswith("ghidra_12.1.4_PUBLIC"):
            raise ValueError("Wrong Ghidra installation")
        sha=digest(package)
        if sha!=args.extension_sha256.lower():
            raise ValueError("Actual extension ZIP SHA-256 does not match CI build")
        summary["extension_sha256"]=sha
        with tempfile.TemporaryDirectory(prefix="ga11-headless-") as temp:
            work=Path(temp)
            for name in ("home","cache","project","classes"):
                (work/name).mkdir()
            settings=work/"settings"
            ext=settings/("ci-ghidra")/"ghidra_12.1.4_PUBLIC"/"Extensions"
            ext.mkdir(parents=True)
            jar=install(package,ext)
            fixture(work/"vectors-full.bin")
            fixture(work/"vectors-short.bin",short=True)
            env=dict(os.environ)
            env["USER"]="ci"
            env["JAVA_HOME"]=str(java)
            env["PATH"]=str(java/"bin")+os.pathsep+env.get("PATH","")
            env["JAVA_TOOL_OPTIONS"]=(
                f"-Dapplication.settingsdir={settings} "
                f"-Dapplication.cachedir={work/'cache'} "
                f"-Duser.home={work/'home'} -Djava.awt.headless=true")
            headless=ghidra/"support/analyzeHeadless"
            for file in ("vectors-full.bin","vectors-short.bin"):
                call([str(headless),str(work/"project"),"Ga11Vectors",
                     "-import",str(work/file),"-loader","BinaryLoader",
                     "-processor","68000:BE:32:CPU32","-cspec","default",
                     "-noanalysis"],work,env,out/(file+".import.log"))
            check=work/"project/Ga11Vectors.gpr"
            if not check.is_file():
                raise RuntimeError("Ghidra headless importer did not create project")
            jars=sorted(set(ghidra.rglob("*.jar"))|set(ext.rglob("*.jar")))
            cp=os.pathsep.join(str(x) for x in jars)
            call([str(java/"bin/javac"),"-cp",cp,"-d",
                  str(work/"classes"),str(SOURCE)],work,env,out/"compile.log")
            call([str(java/"bin/java"),
                  "-Djava.system.class.loader=ghidra.GhidraClassLoader",
                  "-Djava.awt.headless=true",
                  f"-Dapplication.settingsdir={settings}",
                  f"-Dapplication.cachedir={work/'cache'}",
                  f"-Duser.home={work/'home'}",
                  "-cp",str(work/"classes")+os.pathsep+cp,
                  "Ga11VectorHeadlessMain",
                  str(ghidra),str(work/"project"),str(out),
                  str(args.strict_entry).lower(),
                  args.ga18_mode],
                 work,env,out/"integration.log",
                 timeout=240)
            proof=json.loads((out/"result.json").read_text())
            required=("function_entry_and_body_verified",
                      "production_flow_integration_verified",
                      "read_only_analyze_verified","no_runtime_vbr_isr_claim")
            if proof.get("state")!="PASSED_SYNTHETIC_REAL_GHIDRA_HEADLESS":
                raise RuntimeError("Missing genuine Ghidra integration PASS")
            for key in required:
                if proof.get(key) is not True:
                    raise RuntimeError("Missing proof: "+key)
            if proof.get("truncated_image_unreadable")!=244:
                raise RuntimeError("Missing truncated mapping proof")
            if args.ga18_mode != "none":
                mode_fields={
                    "overview":("synthetic_simcr_detected",
                        "overview_three_parts_verified","cpu32_scope_conservative"),
                    "cache":("cfg_stage_first_computed","cfg_stage_cache_reused",
                        "cfg_stage_clear_invalidated","cfg_stage_scope_isolated"),
                    "startup":("simcr_real_listing_pcode_verified",
                        "simcr_local_first_only_verified",
                        "listing_cfg_reconciliation_verified"),
                    "csbar":("csbar_real_literal_proposal_manual_only",
                        "csbar_real_conflicting_literals_blocked",
                        "unknown_store_all_cs_windows_blocked"),
                }
                required_extra=mode_fields[args.ga18_mode]+(
                    "read_only_analysis_verified",)
                for key in required_extra:
                    if proof.get(key) is not True:
                        raise RuntimeError("Missing GA-18 real Ghidra proof: "+key)
                summary["ga18_mode"]=args.ga18_mode
                summary["ga18_hardware_verified"]=True
            summary.update({"status":"PASSED_SYNTHETIC_REAL_GHIDRA_HEADLESS",
                            "ghidra_version":"12.1.4",
                            "validated_fields":list(required),
                            "source":"self-built extension and synthetic fixture"})
    except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired,
            zipfile.BadZipFile) as exc:
        summary["reason"]=str(exc)[:400]
    (out/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
    print(json.dumps(summary,indent=2))
    return 0 if summary["status"]=="PASSED_SYNTHETIC_REAL_GHIDRA_HEADLESS" else 1

if __name__=="__main__":
    sys.exit(main())
