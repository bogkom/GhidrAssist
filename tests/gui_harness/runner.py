#!/usr/bin/env python3
"""Disposable Ghidra 12.1.4 GUI regression, without Project Manager/CodeBrowser.

Only accepts synthetic firmware, a user-selected extension ZIP, a local Ghidra
distribution and a JDK. NO copying of Ghidra user settings, RAG catalogs,
production projects, downloaded models, credentials, or archives.
"""
from __future__ import annotations

import argparse
import contextlib
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_GHIDRA = "12.1.4"
LANGUAGE = "68000:BE:32:CPU32"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        for part in iter(lambda: source.read(1024 * 1024), b""):
            h.update(part)
    return h.hexdigest()


def verify_extension(archive: Path, destination: Path) -> None:
    """Strict no-links, no-traversal unzip; never extract to a user directory."""
    with zipfile.ZipFile(archive) as package:
        members = package.infolist()
        if not members or len(members) > 10000:
            raise RuntimeError("Extension ZIP has no files or too many members")
        total = 0
        for member in members:
            name = member.filename
            parts = Path(name).parts
            if (not parts or parts[0] != "GhidrAssist" or
                    Path(name).is_absolute() or
                    any(p in ("..", "") for p in parts) or "\\" in name or
                    ":" in name or name.startswith("/") or
                    ((member.external_attr >> 16) & 0o170000) == 0o120000):
                raise RuntimeError("Unsafe extension ZIP entry")
            total += member.file_size
            if total > 250 * 1024 * 1024:
                raise RuntimeError("Excessively large extension ZIP")
        names = {x.filename for x in members}
        if "GhidrAssist/extension.properties" not in names:
            raise RuntimeError("Not a GhidrAssist extension ZIP")
        props = package.read("GhidrAssist/extension.properties").decode("utf-8")
        if not re.search(r"(?m)^version=12\.1\.4\s*$", props):
            raise RuntimeError("Extension is not pinned to Ghidra 12.1.4")
        package.extractall(destination)


def output_directory(name: str) -> Path:
    p = Path(name).expanduser()
    if p.is_symlink() or (p.exists() and (not p.is_dir() or any(p.iterdir()))):
        raise RuntimeError("Output must be a new or empty, nonsymlink directory")
    p.mkdir(parents=True, exist_ok=True)
    return p.resolve()


def run_logged(cmd: list[str], *, cwd: Path, env: dict[str, str],
               log: Path, timeout: int) -> None:
    with log.open("x", encoding="utf-8") as stream:
        result = subprocess.run(cmd, cwd=cwd, env=env, stdout=stream,
                                stderr=subprocess.STDOUT, timeout=timeout,
                                check=False)
    if result.returncode:
        raise RuntimeError(f"Fixture command failed ({result.returncode}): {log.name}")


def stop_owned(process: subprocess.Popen) -> None:
    """Only terminate the process group created by our own start_new_session."""
    if process.poll() is not None:
        return
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)


def x11_capture(out: Path) -> dict:
    """Actual X11 window capture; pixel metadata is NOT manual visual review."""
    if not all(shutil.which(name) for name in ("xwininfo", "import", "identify")):
        return {"status": "BLOCKED_MISSING_X11_CAPTURE_TOOLS",
                "human_visual_readback": "NOT_PERFORMED"}
    try:
        # The Ghidra docking frame can prefix the tool name with a
        # disposable program/project title. xwininfo -name requires an
        # EXACT title and incorrectly misses a valid prefixed frame.
        tree = subprocess.run(
            ["xwininfo", "-root", "-tree"],
            capture_output=True, text=True, timeout=5, check=True)
        ids = re.findall(
            r'(?im)^\\s*(0x[0-9a-f]+)\\s+"[^"\\n]*GhidrAssist isolated GUI regression[^"\\n]*"',
            tree.stdout)
        if len(ids) != 1:
            raise RuntimeError(
                "Expected exactly one named isolated GhidrAssist X11 window; "
                f"found {len(ids)}")
        image = out / "actual-x11.png"
        subprocess.run(["import", "-silent", "-window", ids[0], str(image)],
                       capture_output=True, timeout=15, check=True)
        size = subprocess.run(
            ["identify", "-format", "%w %h", str(image)],
            capture_output=True, text=True, timeout=5, check=True)
        width, height = map(int, size.stdout.strip().split())
        if width < 200 or height < 200 or image.stat().st_size < 1024:
            raise RuntimeError("Empty/small X11 image")
        return {"status": "X11_CAPTURED_PIXEL_METADATA_CHECKED",
                "width": width, "height": height,
                "sha256": digest(image),
                "human_visual_readback": "NOT_PERFORMED"}
    except (OSError, subprocess.SubprocessError, ValueError, RuntimeError) as error:
        return {"status": "BLOCKED_X11_READBACK", "reason": str(error)[:240],
                "human_visual_readback": "NOT_PERFORMED"}


def fixture_binary(path: Path) -> None:
    # Entirely synthetic: initial SP, reset vector, empty 68000 NOP/RTE stub.
    # This file is not the user's firmware, and cannot identify an MCU.
    data = bytearray(256)
    data[0:8] = bytes.fromhex("0000100000000020")
    data[0x20:0x26] = bytes.fromhex("4e714e714e75")
    path.write_bytes(data)


def verify_outcome(out: Path, mode: str) -> dict:
    report = json.loads((out / "gui-results.json").read_text(encoding="utf-8"))
    if report.get("mode") != mode or report.get("application_headless") or report.get("awt_headless"):
        raise RuntimeError("Ghidra GUI was not proven active")
    for key in ("window_showing", "query_showing", "ran_on_edt",
                "program_open", "swing_render"):
        if report.get(key) is not True:
            raise RuntimeError(f"GUI smoke assertion missing: {key}")
    if mode == "policy":
        for field in ("policy_editor_detached", "narrow_toolbar_unclipped",
                      "conversation_new_reset", "conversation_switch_reset",
                      "cancel_plan_retains_settings", "narrow_status_wrapped"):
            if report.get(field) is not True:
                raise RuntimeError("GUI policy regression: " + field)
        expected = {
            "GUI_ALLOW": ["REJECTED"],
            "GUI_ASYNC": ["SUCCEEDED", "SUCCEEDED"],
            "GUI_ALIAS_BUDGET": ["SUCCEEDED", "REJECTED"],
            "GUI_STATIC_DUP": ["SUCCEEDED", "REJECTED"],
        }
        for name, states in expected.items():
            row = report.get("cases", {}).get(name)
            if not row:
                raise RuntimeError("Unexecuted GUI policy scenario: " + name)
            actual = [j["state"] for j in row.get("journal", [])]
            if actual != states or not row.get("window_showing") or not row.get("edt"):
                raise RuntimeError(f"GUI policy evidence mismatch for {name}: {actual}")
    return {"mode": mode, "swing_checked": True,
            "policy_cases_checked": 4 if mode == "policy" else 0}


def execute(args: argparse.Namespace) -> dict:
    ghidra = Path(args.ghidra).expanduser().resolve(strict=True)
    java_home = Path(args.java_home).expanduser().resolve(strict=True)
    extension = Path(args.extension_zip).expanduser().resolve(strict=True)
    if not (ghidra / "support" / "analyzeHeadless").is_file() or \
            "ghidra_12.1.4_PUBLIC" not in ghidra.name:
        raise RuntimeError("Specify an extracted Ghidra 12.1.4 PUBLIC installation")
    java = java_home / "bin" / "java"
    javac = java_home / "bin" / "javac"
    if not java.is_file() or not javac.is_file():
        raise RuntimeError("JDK java/javac unavailable")
    if not os.environ.get("DISPLAY"):
        raise RuntimeError("BLOCKED_NO_X11_DISPLAY (not skipped or PASSED)")
    if not zipfile.is_zipfile(extension):
        raise RuntimeError("Extension ZIP is not a valid ZIP")
    actual_sha = digest(extension)
    if args.extension_sha256 and actual_sha != args.extension_sha256.lower():
        raise RuntimeError("Extension SHA-256 mismatch")
    out = output_directory(args.output)
    result = {"schema": 1, "status": "BLOCKED", "mode": args.mode,
              "ghidra_version": EXPECTED_GHIDRA, "extension_sha256": actual_sha,
              "human_visual_readback": "NOT_PERFORMED"}
    try:
        with tempfile.TemporaryDirectory(prefix="ga-gui-isolated-") as base:
            work = Path(base)
            settings = work / "settings"
            extdir = (settings / f"{getpass.getuser()}-ghidra" /
                      "ghidra_12.1.4_PUBLIC" / "Extensions")
            extdir.mkdir(parents=True)
            verify_extension(extension, extdir)
            for name in ("home", "cache", "project", "classes"):
                (work / name).mkdir()
            sample = work / "TEST_BINARY.bin"
            fixture_binary(sample)
            env = dict(os.environ)
            env["JAVA_HOME"] = str(java_home)
            env["PATH"] = str(java_home / "bin") + os.pathsep + env.get("PATH", "")
            env["JAVA_TOOL_OPTIONS"] = (
                f"-Dapplication.settingsdir={settings} "
                f"-Dapplication.cachedir={work / 'cache'} "
                f"-Duser.home={work / 'home'}")
            config = {"ghidra": str(ghidra), "project_dir": str(work / "project"),
                      "project_name": "GuiFixture", "program": sample.name,
                      "run_id": "synthetic-gui-regression", "index": str(work / "index"),
                      "mode": args.mode}
            (work / "index").mkdir()
            config_file = work / "config.json"
            config_file.write_text(json.dumps(config), encoding="utf-8")
            ghcmd = [str(ghidra / "support" / "analyzeHeadless"),
                     str(work / "project"), "GuiFixture", "-import", str(sample),
                     "-loader", "BinaryLoader",
                     "-processor", LANGUAGE, "-cspec", "default", "-noanalysis"]
            run_logged(ghcmd, cwd=work, env=env, log=out / "import.log", timeout=180)
            if not (work / "project" / "GuiFixture.gpr").exists():
                raise RuntimeError("Synthetic Ghidra project was not created")
            jars = sorted(set(ghidra.rglob("*.jar")) | set(extdir.rglob("*.jar")))
            cp = os.pathsep.join(map(str, jars))
            source = ROOT / "tests" / "gui_harness" / "GuiIntegrationMain.java"
            run_logged([str(javac), "-cp", cp, "-d", str(work / "classes"),
                        str(source)], cwd=work, env=env,
                       log=out / "compile.log", timeout=120)
            from controlled_llm import ControlledLLM
            with ControlledLLM(out) as llm:
                gui_command = [str(java),
                    "-Djava.system.class.loader=ghidra.GhidraClassLoader",
                    "-Djava.awt.headless=false",
                    f"-Dapplication.settingsdir={settings}",
                    f"-Dapplication.cachedir={work / 'cache'}",
                    f"-Duser.home={work / 'home'}",
                    "-cp", str(work / "classes") + os.pathsep + cp,
                    "GuiIntegrationMain", str(config_file), llm.endpoint, str(out)]
                with (out / "gui-process.log").open("x") as log:
                    process = subprocess.Popen(gui_command, cwd=work, env=env,
                        stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                    try:
                        deadline = time.monotonic() + args.timeout
                        while not (out / "window.ready").exists():
                            if process.poll() is not None:
                                raise RuntimeError("GUI exited before readiness")
                            if time.monotonic() >= deadline:
                                raise RuntimeError("GUI startup timed out")
                            time.sleep(.1)
                        captured = (x11_capture(out) if args.capture_x11 else
                                    {"status": "NOT_REQUESTED",
                                     "human_visual_readback": "NOT_PERFORMED"})
                        (out / "window.probed").write_text("done", encoding="utf-8")
                        remaining = max(1, deadline - time.monotonic())
                        code = process.wait(timeout=remaining)
                        if code != 0:
                            raise RuntimeError(f"GUI returned code {code}")
                    finally:
                        stop_owned(process)
            result.update(verify_outcome(out, args.mode))
            result["x11"] = captured
            result["status"] = "PASSED_SWING_AND_POLICY" if args.mode == "policy" else "PASSED_SWING_SMOKE"
            if args.capture_x11 and captured["status"] != "X11_CAPTURED_PIXEL_METADATA_CHECKED":
                result["status"] = "BLOCKED_X11_CAPTURE"
            return result
    finally:
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n",
                                         encoding="utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra", required=True)
    parser.add_argument("--java-home", required=True)
    parser.add_argument("--extension-zip", required=True)
    parser.add_argument("--extension-sha256")
    parser.add_argument("--output", required=True)
    parser.add_argument("--mode", choices=("smoke", "policy"), default="smoke")
    parser.add_argument("--capture-x11", action="store_true")
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args(argv)
    if not 30 <= args.timeout <= 900:
        parser.error("--timeout must be within 30..900")
    try:
        result = execute(args)
        print(json.dumps(result, indent=2))
        return 0 if result["status"].startswith("PASSED_") else 1
    except (OSError, RuntimeError, subprocess.TimeoutExpired,
            zipfile.BadZipFile, ValueError) as error:
        print("BLOCKED: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
