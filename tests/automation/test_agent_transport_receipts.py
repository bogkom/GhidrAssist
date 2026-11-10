#!/usr/bin/env python3
"""GA-18 local session, launcher and wire-response refusal (synthetic only)."""
import importlib.machinery
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def load(path, name):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    module = types.ModuleType(name)
    module.__file__ = str(path)
    loader.exec_module(module)
    return module


client = load(ROOT / "tools/ghidrassist-agent", "ga18_strict_wire_client")
launcher = load(ROOT / "tools/ghidrassist-agent-start", "ga18_strict_wire_launcher")
TOKEN = "a" * 64


class SessionAndWire(unittest.TestCase):
    def test_valid_generated_minimal_and_extended_sessions(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "session.json"
            for value in (
                {"schema": 3, "port": 37351, "token": TOKEN},
                {"schema": 3, "port": 37351, "token": TOKEN,
                 "pid": 1234, "mode": "test", "write_mode": "READ_ONLY"},
            ):
                target.write_text(json.dumps(value), encoding="utf-8")
                self.assertEqual(client.load_session(target), value)
                self.assertEqual(launcher._read_local_receipt(target), value)

    def test_client_rejects_bad_port_token_duplicate_and_oversized_receipt(self):
        cases = [
            {"schema": True, "port": 37351, "token": TOKEN},
            {"schema": 3, "port": True, "token": TOKEN},
            {"schema": 3, "port": 37351.5, "token": TOKEN},
            {"schema": 3, "port": "37351", "token": TOKEN},
            {"schema": 3, "port": 65536, "token": TOKEN},
            {"schema": 3, "port": 0, "token": TOKEN},
            {"schema": 3, "port": 37351, "token": ""},
            {"schema": 3, "port": 37351, "token": "bad\\r\\nBearer"},
            {"schema": 3, "port": 37351, "token": {"secret": TOKEN}},
        ]
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "session.json"
            for data in cases:
                with self.subTest(data=data):
                    file.write_text(json.dumps(data), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        client.load_session(file)
            raw = json.dumps({"schema": 3, "port": 37351,
                              "token": TOKEN})
            injections = [
                raw.replace('"port": 37351',
                            '"port": true, "port": 37351'),
                raw.replace('"token":',
                            '"\\u0074oken": "forged", "token":'),
                raw.replace('"schema": 3', '"schema": 3.0, "schema": 3'),
            ]
            for forged in injections:
                with self.subTest(forged=forged[:80]):
                    file.write_text(forged, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "Duplicate"):
                        client.load_session(file)
            file.write_bytes(raw.encode() + b" " * client.SESSION_MAX_BYTES)
            with self.assertRaisesRegex(ValueError, "oversized"):
                client.load_session(file)

    def test_rpc_one_bounded_loopback_request_accepts_normal_object(self):
        session = {"port": 37351, "token": TOKEN}
        def response(request, timeout):
            self.assertEqual(timeout, 45)
            self.assertEqual(request.full_url, "http://127.0.0.1:37351/rpc")
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(request.get_header("Authorization"), "Bearer " + TOKEN)
            self.assertEqual(json.loads(request.data),
                             {"method": "session.status", "params": {}})
            return io.BytesIO(b'{"status":"READY","schema":3}')
        with patch.object(client, "urlopen", side_effect=response):
            self.assertEqual(client.rpc(session, "session.status"),
                             {"status": "READY", "schema": 3})

    def test_rpc_refuses_ambiguous_invalid_and_oversized_response(self):
        session = {"port": 37351, "token": TOKEN}
        data = [
            b'{"result":1, "result":2}',
            b'{"\\u0072esult":1, "result":2}',
            b'{"result":NaN}',
            b'{"result":1e99999}',
            b'{"result":true}'+b" " * client.RPC_RESPONSE_MAX_BYTES,
            b'["not an object"]',
            b'{"result":"\\xff"}',
            b"[" * 66 + b"]" * 66,
            b'',
        ]
        for raw in data:
            with self.subTest(length=len(raw), fragment=raw[:32]):
                with patch.object(client, "urlopen",
                                  return_value=io.BytesIO(raw)):
                    with self.assertRaises(ValueError):
                        client.rpc(session, "status", {})
        with patch.object(client, "urlopen",
                          return_value=io.BytesIO(b'{"ok":true}')):
            with self.assertRaises(ValueError):
                client.rpc(session, "method", {"bad": float("nan")})

    def test_launcher_receipts_refuse_duplicate_keys_and_bad_payloads(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "ready.json"
            valid = {"schema": 3, "port": 37243, "pid": 1234}
            file.write_text(json.dumps(valid), encoding="utf-8")
            self.assertEqual(launcher._read_local_receipt(file), valid)
            for raw in (
                b'{"schema":3,"port":1,"port":37243,"pid":1234}',
                b'{"schema":3,"port":1,"pid":NaN}',
                b'{"schema":3,"port":1,"pid":1e99999}',
                b'{"schema":3,"port":1,"pid":' + b"9" * 65 + b"}",
                b'[]',
                b'{"ok":true}' + b" " * launcher.LOCAL_RECEIPT_MAX_BYTES,
            ):
                with self.subTest(raw=raw[:48]):
                    file.write_bytes(raw)
                    with self.assertRaises(ValueError):
                        launcher._read_local_receipt(file)
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                launcher._parse_unambiguous_json(
                    b'{"\\u0070id":-1,"pid":1234}')


if __name__ == "__main__":
    unittest.main(verbosity=2)
