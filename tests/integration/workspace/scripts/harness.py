"""Isolated Ghidra processes used by the regression runner and pytest fixtures."""
from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def dump(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def fingerprint(path):
    path = Path(path)
    files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    digest = hashlib.sha256()
    for item in files:
        digest.update(str(item.relative_to(path) if path.is_dir() else item.name).encode())
        with item.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    return digest.hexdigest()


def read_rag_catalog(preferences):
    # Only this RAG property is copied. Never load API credentials into a fixture.
    text = Path(preferences).read_text()
    key = "GhidrAssist.RAGLibraries.v1="
    line = next((line[len(key):] for line in text.splitlines() if line.startswith(key)), None)
    if line is None:
        raise RuntimeError("BLOCKED: RAG library catalog is absent from source preferences")
    value = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m[1], 16)), line)
    value = re.sub(r"\\(.)", lambda m: {"n": "\n", "t": "\t", "r": "\r"}.get(m[1], m[1]), value)
    json.loads(value)
    return value


def prepare_environment(work, ghidra, project_gpr, index, preferences):
    work = Path(work)
    project_gpr, index = Path(project_gpr), Path(index)
    if not project_gpr.is_file() or not project_gpr.with_suffix(".rep").is_dir():
        raise RuntimeError(f"BLOCKED: source project missing: {project_gpr}")
    if not index.is_dir():
        raise RuntimeError(f"BLOCKED: source Lucene index missing: {index}")
    config = {"work": str(work), "ghidra": str(ghidra), "project_name": project_gpr.stem,
              "program": "ECU_FLASH 512KB.bin", "environments": {}}
    catalog = work / "rag-catalog.json"
    catalog.write_text(read_rag_catalog(preferences))
    shutil.copytree(index, work / "index")
    config.update(index=str(work / "index"), catalog=str(catalog))
    zips = {}
    for repo in ("GhidrAssist", "GhidrAssistMCP"):
        candidates = sorted((ROOT / "repos" / repo / "dist").glob("*.zip"), key=lambda p: p.stat().st_mtime)
        if not candidates:
            raise RuntimeError(f"BLOCKED: build the {repo} extension first (dist/*.zip missing)")
        zips[repo] = candidates[-1]
    config["extension_sha256"] = {name: fingerprint(path) for name, path in zips.items()}
    config["extension_archives"] = {name: str(path) for name, path in zips.items()}
    for name in ("mcp", "rag", "agentic"):
        base = work / name
        project = base / "project"
        project.mkdir(parents=True)
        (base / "home").mkdir()
        (base / "cache").mkdir()
        shutil.copy2(project_gpr, project / project_gpr.name)
        shutil.copytree(project_gpr.with_suffix(".rep"), project / project_gpr.with_suffix(".rep").name)
        settings = base / "settings"
        extensions = settings / f"{getpass.getuser()}-ghidra" / "ghidra_12.1.4_PUBLIC" / "Extensions"
        extensions.mkdir(parents=True)
        for archive in zips.values():
            with zipfile.ZipFile(archive) as package:
                for member in package.namelist():
                    target = (extensions / member).resolve()
                    if not target.is_relative_to(extensions.resolve()):
                        raise RuntimeError("Invalid extension archive path")
                package.extractall(extensions)
        config["environments"][name] = {"base": str(base), "project": str(project), "settings": str(settings)}
    return config


def ghidra_command(config, environment, scripts):
    state = config["environments"][environment]
    command = [str(Path(config["ghidra"]) / "support" / "analyzeHeadless"), state["project"],
               config["project_name"], "-process", config["program"], "-noanalysis", "-readOnly",
               "-scriptPath", str(ROOT / "scripts")]
    for script, args in scripts:
        command += ["-postScript", script, *map(str, args)]
    env = dict(os.environ)
    env["JAVA_HOME"] = os.getenv("GHIDRA_JAVA_HOME", "/usr/lib/jvm/java-25-openjdk-amd64")
    env["PATH"] = env["JAVA_HOME"] + "/bin:" + env.get("PATH", "")
    env["JAVA_TOOL_OPTIONS"] = (f"-Dapplication.settingsdir={state['settings']} "
        f"-Dapplication.cachedir={state['base']}/cache -Duser.home={state['base']}/home")
    return command, env, state["base"]


def stop_process(process, grace=5):
    # A dead shell may leave Java children in the session it created.
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
    # Reap/terminate descendants even when their shell exited first.
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            fields = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
            if fields[0] != 'Z' and int(fields[2]) == process.pid:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                break
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue


def process_identity(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return {"start_ticks": fields[19], "pgid": int(fields[2])}
    except (FileNotFoundError, ProcessLookupError):
        return None


def cleanup_probe_groups(run):
    """Recover test-owned child sessions when pytest itself was interrupted."""
    cleaned = []
    for manifest in Path(run).rglob("*.process.json"):
        info = json.loads(manifest.read_text())
        if info.get("exit_code") is not None:
            continue
        pid = info["pid"]
        identity = process_identity(pid)
        if identity is not None and identity != info.get("identity"):
            cleaned.append({"pid": pid, "action": "identity_changed_no_signal"})
            continue
        # The group belongs to this recorded start_new_session=True invocation.
        with contextlib.suppress(ProcessLookupError):
            os.killpg(pid, signal.SIGTERM)
        time.sleep(.2)
        with contextlib.suppress(ProcessLookupError):
            os.killpg(pid, signal.SIGKILL)
        cleaned.append({"pid": pid, "action": "terminated_owned_probe_session"})
    return cleaned


def run_probe(config, environment, script, args, log, timeout=180):
    command, env, cwd = ghidra_command(config, environment, [(script, args)])
    started = time.monotonic()
    with Path(log).open("x") as stream:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=stream,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        record = {"command": command, "pid": process.pid, "identity": process_identity(process.pid),
                  "exit_code": None, "started_at": utc()}
        dump(str(log) + ".process.json", record)
        try:
            code = process.wait(timeout=timeout)
        finally:
            stop_process(process)
            record.update(exit_code=process.returncode, duration_seconds=time.monotonic() - started,
                          finished_at=utc())
            dump(str(log) + ".process.json", record)
    if code:
        raise RuntimeError(f"BLOCKED: Ghidra exited {code}; see {log}")
    return record


def load_config():
    filename = os.getenv("HARNESS_CONFIG")
    if not filename:
        raise RuntimeError("BLOCKED: run scripts/run_suite.py to prepare an isolated environment")
    return json.loads(Path(filename).read_text())


class PortLease:
    """Reserve a free loopback port; serialize cooperating regression runners."""
    def __init__(self, preferred=18080):
        self.lock = None
        self.socket = None
        for port in (preferred, 0) if preferred else (0,):
            reservation = socket.socket()
            try:
                # Match the HTTP server's restart semantics: TIME_WAIT is not a listener.
                # The separate flock still serializes cooperating reservations.
                reservation.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                reservation.bind(("127.0.0.1", port))
                chosen = reservation.getsockname()[1]
                lock = open(f"/tmp/ghidrassist-regression-port-{chosen}.lock", "a")
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    lock.close()
                    reservation.close()
                    continue
                self.port, self.lock, self.socket = chosen, lock, reservation
                break
            except OSError:
                reservation.close()
        if self.lock is None:
            raise RuntimeError("BLOCKED: no free MCP port could be reserved")

    def release_socket(self):
        if self.socket:
            self.socket.close()
            self.socket = None

    def close(self):
        self.release_socket()
        if self.lock:
            self.lock.close()
            self.lock = None


async def initialize_mcp(url):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client
    async with streamable_http_client(url) as (read, write, _):
        async with ClientSession(read, write) as session:
            initialized = await session.initialize()
            listing = await session.list_tools()
            return {"initialized": initialized.model_dump(mode="json"),
                    "tool_names": [t.name for t in listing.tools], "url": url, "time": utc()}


class MCPProcess:
    def __init__(self, config, run, preferred_port=18080):
        self.config, self.run = config, Path(run)
        self.events = []
        self.lease = PortLease(preferred_port)
        self.url = f"http://127.0.0.1:{self.lease.port}/mcp"
        self.sentinel = Path(config["work"]) / "mcp-finished"
        self.process = None
        self.stream = None

    def record(self, kind, **fields):
        self.events.append({"kind": kind, "time": utc(), **fields})
        dump(self.run / "mcp-lifecycle.json", self.events)

    def start(self, timeout=120):
        scripts = [("GhidraSnapshot.java", [self.run / "ghidra-snapshot.json"]),
                   ("GAMCPStartServerScript.java", ["host=127.0.0.1", f"port={self.lease.port}",
                       "wait=true", f"completion_file={self.sentinel}"])]
        command, env, cwd = ghidra_command(self.config, "mcp", scripts)
        self.stream = (self.run / "mcp-headless.log").open("x")
        self.lease.release_socket()
        self.process = subprocess.Popen(command, cwd=cwd, env=env, stdout=self.stream,
                                        stderr=subprocess.STDOUT, start_new_session=True)
        self.record("started", pid=self.process.pid, command=command, url=self.url)
        deadline = time.monotonic() + timeout
        last_error = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                self.record("unexpected_exit", exit_code=self.process.returncode)
                raise RuntimeError(f"BLOCKED: MCP/Ghidra exited before readiness ({self.process.returncode})")
            try:
                with socket.create_connection(("127.0.0.1", self.lease.port), timeout=.2):
                    pass
                # Confirm this process logged a successful bind before talking to its port.
                if "Headless MCP server ready on" not in (self.run / "mcp-headless.log").read_text():
                    time.sleep(.2)
                    continue
                readiness = asyncio.run(asyncio.wait_for(initialize_mcp(self.url), timeout=5))
                if not readiness["tool_names"]:
                    raise RuntimeError("MCP initialized without tools")
                dump(self.run / "mcp-readiness.json", readiness)
                self.record("ready", tool_count=len(readiness["tool_names"]))
                return
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(.3)
        self.record("startup_timeout", last_error=last_error)
        raise RuntimeError(f"BLOCKED: MCP readiness timed out after {timeout}s: {last_error}")

    def close(self, grace=20):
        try:
            if self.process:
                self.sentinel.touch()
                self.record("completion_requested")
                try:
                    self.process.wait(timeout=grace)
                except subprocess.TimeoutExpired:
                    self.record("forced_stop")
                    stop_process(self.process)
                # The launcher can exit before a Java descendant; always sweep
                # the session we own, including after an unexpected parent exit.
                stop_process(self.process)
                closed = False
                for _ in range(20):
                    try:
                        with socket.create_connection(("127.0.0.1", self.lease.port), timeout=.2):
                            pass
                    except OSError:
                        closed = True
                        break
                    time.sleep(.1)
                self.record("stopped", exit_code=self.process.returncode, port_closed=closed)
        finally:
            if self.stream:
                self.stream.close()
            self.lease.close()
