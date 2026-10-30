"""Deterministic loopback-only OpenAI-compatible fake for Query/policy tests.

No real model, API key, user chat, firmware or network connection is needed.
Never log original prompts or any credentials; log only scenario/control status.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import threading
import time


class ControlledLLM:
    def __init__(self, output: Path):
        self.output = Path(output)
        self.rounds = {}
        self.lock = threading.Lock()
        self.events = []
        parent = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                if self.client_address[0] not in ("127.0.0.1", "::1"):
                    self.send_error(403)
                    return
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if size <= 0 or size > 2 * 1024 * 1024:
                        self.send_error(413)
                        return
                    data = json.loads(self.rfile.read(size))
                    reply = parent.respond(data)
                    raw = ("data: " + json.dumps(reply) +
                           "\n\ndata: [DONE]\n\n").encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Content-Length", str(len(raw)))
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(raw)
                except (ValueError, KeyError, TypeError) as exc:
                    parent.event("error", type=type(exc).__name__)
                    self.send_error(400)

        self.http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.http.serve_forever,
                                       daemon=True, name="ga-fake-model")

    @property
    def endpoint(self):
        return f"http://127.0.0.1:{self.http.server_port}/v1/"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.http.shutdown()
        self.http.server_close()
        self.thread.join(timeout=5)
        (self.output / "controlled-model-events.json").write_text(
            json.dumps(self.events, indent=2) + "\n", encoding="utf-8")

    def event(self, kind, **data):
        with self.lock:
            self.events.append({"kind": kind, **data})

    @staticmethod
    def answer(message):
        return {"choices": [{"index": 0, "delta": {"role": "assistant",
                "content": message}, "finish_reason": "stop"}]}

    def respond(self, data: dict):
        case = data.get("model")
        if case not in ("GUI_ALLOW", "GUI_ASYNC",
                        "GUI_ALIAS_BUDGET", "GUI_STATIC_DUP"):
            raise ValueError("Unapproved regression model ID")
        messages = data.get("messages", [])
        tools = data.get("tools")
        full_text = "\n".join(str(message.get("content") or "")
                              for message in messages if isinstance(message, dict))
        synthesis = "Verified tool executions recorded by dispatcher:" in full_text
        self.event("request", case=case, tools=bool(tools),
                   synthesis=synthesis)
        if synthesis:
            self.event("synthesis", case=case)
            return self.answer(f"Case {case}: only actually verified tool execution "
                               "results may be reported. No physical MCU is inferred.")
        if not tools:
            return self.answer("1. Execute the requested tool using the configured "
                               "task policy. Only report verified execution results.")
        gate = self.output / f"{case}.registered"
        deadline = time.monotonic() + 20
        while not gate.exists():
            if time.monotonic() >= deadline:
                raise ValueError("Fixture tool registry not ready")
            time.sleep(0.025)
        with self.lock:
            round_no = self.rounds.get(case, 0)
            self.rounds[case] = round_no + 1
        calls = {
            "GUI_ALLOW": [[("ga_search_documents",
                            {"query": "synthetic", "scope": "all"})], []],
            "GUI_ASYNC": [[("get_task_status", {"task_id": "task-1"})],
                          [("get_task_status", {"task_id": "task-1"})], []],
            "GUI_ALIAS_BUDGET": [[("get_gui_fact", {"key": "a"})],
                                 [("get_gui_fact_alias", {"key": "b"})], []],
            "GUI_STATIC_DUP": [[("get_gui_fact", {"key": "a"})],
                               [("get_gui_fact_alias", {"key": "a"})], []],
        }[case]
        requested = calls[round_no] if round_no < len(calls) else []
        if not requested:
            return self.answer("Analysis ended; source evidence is limited to "
                               "the actual dispatcher journal.")
        proposed = []
        for index, (name, arguments) in enumerate(requested):
            self.event("tool_proposed", case=case, tool=name, round=round_no)
            proposed.append({"index": index,
                "id": f"{case}_{round_no}_{index}",
                "type": "function",
                "function": {"name": name, "arguments": json.dumps(arguments)}})
        return {"choices": [{"index": 0,
            "delta": {"role": "assistant", "tool_calls": proposed},
            "finish_reason": "tool_calls"}]}
