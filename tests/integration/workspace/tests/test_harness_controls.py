"""Exercise port collisions, startup death and forced shutdown with real processes."""
import json
import socket
import sys
import pytest
from scripts import harness


def test_occupied_port_is_not_reused():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        occupied = listener.getsockname()[1]
        lease = harness.PortLease(occupied)
        try:
            assert lease.port != occupied
            assert listener.getsockname()[1] == occupied
        finally:
            lease.close()


def test_stopped_server_port_can_be_reserved_during_time_wait():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    port = listener.getsockname()[1]
    client = socket.create_connection(('127.0.0.1', port))
    connection, _ = listener.accept()
    connection.shutdown(socket.SHUT_WR)
    assert client.recv(1) == b''
    client.close()
    connection.close()
    listener.close()
    lease = harness.PortLease(port)
    try:
        assert lease.port == port, 'A closed listener in TIME_WAIT is not an occupied server'
    finally:
        lease.close()


def test_two_cooperating_leases_never_share_a_port():
    first = harness.PortLease(0)
    second = harness.PortLease(first.port)
    try:
        assert second.port != first.port
    finally:
        second.close()
        first.close()


def test_unexpected_startup_exit_is_detected_and_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(harness, 'ghidra_command', lambda *_: ([sys.executable, '-c', 'raise SystemExit(7)'], None, str(tmp_path)))
    server = harness.MCPProcess({'work': str(tmp_path)}, tmp_path, 0)
    try:
        with pytest.raises(RuntimeError, match='exited before readiness'):
            server.start(timeout=2)
    finally:
        server.close(grace=.1)
    records = json.loads((tmp_path / 'mcp-lifecycle.json').read_text())
    assert any(e['kind'] == 'unexpected_exit' and e['exit_code'] == 7 for e in records)
    assert records[-1]['kind'] == 'stopped'
    assert records[-1]['port_closed']


def test_startup_timeout_forces_cleanup(tmp_path, monkeypatch):
    monkeypatch.setattr(harness, 'ghidra_command', lambda *_: ([sys.executable, '-c', 'import time; time.sleep(60)'], None, str(tmp_path)))
    server = harness.MCPProcess({'work': str(tmp_path)}, tmp_path, 0)
    try:
        with pytest.raises(RuntimeError, match='timed out'):
            server.start(timeout=.2)
    finally:
        server.close(grace=.1)
    records = json.loads((tmp_path / 'mcp-lifecycle.json').read_text())
    assert any(e['kind'] == 'forced_stop' for e in records)
    assert server.process.poll() is not None
    assert records[-1]['port_closed']


def test_shell_exit_does_not_leave_a_java_like_child(tmp_path, monkeypatch):
    child_pid = tmp_path / 'child.pid'
    source = ("import subprocess,sys; "
              "p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
              f"open({str(child_pid)!r},'w').write(str(p.pid)); raise SystemExit(7)")
    monkeypatch.setattr(harness, 'ghidra_command', lambda *_: ([sys.executable, '-c', source], None, str(tmp_path)))
    server = harness.MCPProcess({'work': str(tmp_path)}, tmp_path, 0)
    try:
        with pytest.raises(RuntimeError, match='exited before readiness'):
            server.start(timeout=2)
    finally:
        server.close(grace=.1)
    pid = int(child_pid.read_text())
    import time
    from pathlib import Path
    for _ in range(30):
        try:
            state = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
        except FileNotFoundError:
            state = 'Z'
        if state == 'Z':
            break
        time.sleep(.05)
    assert state == 'Z', 'A child process survived its parent shell and cleanup'


def test_interrupted_pytest_probe_registry_is_cleaned(tmp_path):
    import subprocess
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)
    harness.dump(tmp_path / 'probe.log.process.json', {'pid': process.pid,
        'identity': harness.process_identity(process.pid), 'exit_code': None})
    try:
        actions = harness.cleanup_probe_groups(tmp_path)
        process.wait(timeout=2)
        assert process.returncode != 0
        assert actions == [{'pid': process.pid, 'action': 'terminated_owned_probe_session'}]
    finally:
        harness.stop_process(process)


def test_six_pass_twenty_unexecuted_is_not_full_success(tmp_path, monkeypatch):
    from scripts import run_suite
    monkeypatch.setattr(run_suite, 'ROOT', tmp_path)
    monkeypatch.setattr(run_suite.subprocess, 'check_output', lambda *a, **k: '')
    data = {'tests': []}
    for filename, total, outcome in [('test_snapshot_unittest', 4, 'passed'), ('test_native_rag', 2, 'passed'),
                                     ('test_mcp_contract', 14, 'skipped'), ('test_agentic_cases', 6, 'skipped')]:
        for index in range(total):
            data['tests'].append({'nodeid': f'tests/{filename}.py::case_{index}', 'outcome': outcome,
                'call': {'duration': .01, 'longrepr': 'BLOCKED: no environment' if outcome == 'skipped' else ''}})
    strict_dir = tmp_path / 'strict'
    strict_dir.mkdir()
    strict = run_suite.report(strict_dir, 'strict', True, data, [], {}, None, harness.utc(), 0)
    assert strict['counts'] == {'PASS': 6, 'FAIL': 0, 'SKIP': 0, 'BLOCKED': 20, 'NOT_IMPLEMENTED': 0}
    assert strict['run_status'] == 'FAIL'
    assert strict['exit_code'] == 1
    assert set(strict['required_group_gaps']) == {'real_mcp', 'agentic_mode'}
    partial_dir = tmp_path / 'partial'
    partial_dir.mkdir()
    partial = run_suite.report(partial_dir, 'partial', False, data, [], {}, None, harness.utc(), 0)
    assert partial['run_status'] == 'INCOMPLETE'
