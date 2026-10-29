#!/usr/bin/env python3
"""Own the complete isolated MCP → pytest → shutdown regression run."""
from __future__ import annotations
import argparse
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import traceback
import uuid

# Allow both `python scripts/run_suite.py` and import from pytest.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.harness import ROOT, MCPProcess, cleanup_probe_groups, dump, fingerprint, prepare_environment, stop_process, utc

STATUSES = ('PASS', 'FAIL', 'SKIP', 'BLOCKED', 'NOT_IMPLEMENTED')
REQUIRED = ('real_mcp', 'ghidra_snapshots', 'native_rag', 'agentic_mode')
REQUIRED_MINIMUM = {'real_mcp': 14, 'ghidra_snapshots': 4, 'native_rag': 2, 'agentic_mode': 7}


def group(node):
    for filename, name in [('test_mcp_contract', 'real_mcp'), ('test_snapshot', 'ghidra_snapshots'),
                           ('test_native_rag', 'native_rag'), ('test_agentic', 'agentic_mode')]:
        if filename in node:
            return name
    if 'test_decompiler_contract' in node: return 'decompiler_contract'
    if 'test_gui_integration' in node or 'test_task_tool_editor' in node: return 'gui_integration'
    if 'test_real_llm_transport' in node: return 'transport_contracts'
    if 'test_real_llm' in node: return 'real_llm'
    return 'production_contracts' if 'test_production_selftests' in node else 'harness_controls'


def normalize(test, run):
    node = test['nodeid']
    stages = [test.get(k) or {} for k in ('setup', 'call', 'teardown')]
    reason = '\n'.join(str(x.get('longrepr', '')) for x in stages).strip()
    outcome = test.get('outcome', 'error')
    if outcome == 'passed':
        status = 'PASS'
    elif outcome == 'skipped':
        status = 'NOT_IMPLEMENTED' if 'NOT_IMPLEMENTED:' in reason else 'BLOCKED' if 'BLOCKED:' in reason else 'SKIP'
    elif outcome == 'error' and 'BLOCKED:' in reason:
        status = 'BLOCKED'
    else:
        status = 'FAIL'
    metadata = test.get('metadata') or {}
    result = {'nodeid': node, 'group': group(node), 'status': status,
              'duration_seconds': sum(s.get('duration', 0) for s in stages),
              'assertion_message': reason or None, **metadata}
    if '[' in node and result['group'] == 'real_mcp':
        path = run / 'raw-mcp' / (node.rsplit('[', 1)[-1].rstrip(']') + '.json')
        if path.exists():
            raw = json.loads(path.read_text())
            result.update(expected_value=raw['expected'], received_value=raw['actual_for_assertion'],
                          raw_evidence=str(path.relative_to(run)))
    if result['group'] == 'agentic_mode' and (run / 'agentic/results.json').exists():
        name = node.rsplit('[', 1)[-1].rstrip(']') if '[' in node else 'VERTICAL'
        native = json.loads((run / 'agentic/results.json').read_text()).get('cases', {}).get(name, {})
        result['native_execution_duration_seconds'] = native.get('duration_seconds')
        result.setdefault('raw_evidence', 'agentic/trace.json')
    if result['group'] == 'real_llm':
        result.setdefault('raw_evidence', 'real-llm/results.json')
    if result['group'] == 'gui_integration':
        result.setdefault('raw_evidence', 'gui/gui-results.json')
    if result['group'] == 'decompiler_contract':
        result.setdefault('raw_evidence', 'decompiler-contract.json')
    if status == 'FAIL':
        result.setdefault('expected_value', 'All assertions in the executed test must hold; see assertion_message')
        result.setdefault('received_value', reason)
    return result


def report(run, run_id, strict, pytest_data, infrastructure, config, server, started, pytest_code):
    if (run / 'checksums.json').exists():
        raise RuntimeError(f'Refusing to overwrite finalized run {run_id}')
    tests = [normalize(t, run) for t in pytest_data.get('tests', [])]
    counts = {status: sum(t['status'] == status for t in tests) for status in STATUSES}
    groups = {name: {status: sum(t['group'] == name and t['status'] == status for t in tests)
                     for status in STATUSES} for name in (*REQUIRED, 'harness_controls', 'production_contracts', 'gui_integration', 'real_llm', 'decompiler_contract', 'transport_contracts')}
    gaps = [name for name in REQUIRED if sum(t['group'] == name and t['status'] in ('PASS', 'FAIL') for t in tests) < REQUIRED_MINIMUM[name]
            or any(t['group'] == name and t['status'] in ('SKIP', 'BLOCKED', 'NOT_IMPLEMENTED') for t in tests)]
    failure = bool(counts['FAIL'] or infrastructure or pytest_code != 0 or (strict and (gaps or counts['BLOCKED'] or counts['NOT_IMPLEMENTED'] or counts['SKIP'])))
    issue_lines = ['# Executed regression findings', '',
        'Deterministic Agentic and GUI tests use a controlled response source. The optional real_llm group separately reports actual local-model execution or an explicit infrastructure block. Transport unit tests do not count as model execution.', '',
        'GhidrAssist production changes are identified by the recorded branch and commits. Original ECU411 data is unchanged. All evidence below belongs to this run.', '']
    descriptions = {
        'GA-04': 'A model-proposed tool outside the explicit prompt restriction is dispatched. The controller has no enforced tool-name allowlist for this objective.',
        'GA-05': 'Two identical model proposals produce one real execution. Duplicate suppression is verified separately from forwarding of the rejection reason.',
        'GA-06': 'The registry denies the update (zero executions), but the final model claim of success is delivered without verification.',
        'GA-07': 'The prompt gives one call per tool; the controller executes the first fixture tool twice with different arguments. Per-tool limits are not enforced.',
        'GA-08': 'The first async status read returns PENDING. A necessary second identical poll is deduplicated, preventing observation of COMPLETED.',
        'GA-09': 'The real native RAG response contains pagination metadata; the production evidence cache truncates it before final synthesis.',
    }
    for test in tests:
        if test['group'] not in ('real_mcp', 'agentic_mode') or test['status'] not in ('PASS', 'FAIL'):
            continue
        node = test['nodeid']
        description = 'The complete reference output still differs under the headless decompiler configuration. Keep the original assertion; this is not yet classified as an MCP pagination bug.'
        if test['group'] == 'agentic_mode':
            description = next((value for key, value in descriptions.items() if key in node),
                               'The vertical flow completes through the real provider, controller and registry, and the final fact/count are backed by an actual tool result.')
            if 'rejection_reason' in node:
                description = ('The actual dispatcher returns an error reason, but ConversationalToolHandler serializes ToolResult.getContent() '
                               'instead of getContentOrError(). Error results have null content, so the model receives an empty tool message. '
                               'The test-only recording registry observes the unchanged super.execute result; it does not repair delivery.')
        if test['status'] == 'PASS':
            description = 'The executed contract passed with exact expected/received values retained in summary.json. '
            if 'GA-04' in node or 'GA-07' in node:
                description += ('Restrictions are supplied as an explicit ToolExecutionPolicy. '
                    'The former prompt-only test input did not represent controller policy; arbitrary natural language is deliberately not parsed. '
                    'Behavioral assertions were retained, and unrestricted/global/zero/empty policy controls are tested separately.')
            elif 'verified_final' in node or 'GA-06' in node:
                description += 'Rejected, failed and mixed attempts are reported from the actual journal; unverified model synthesis is withheld.'
        issue_lines += [f'## {test["status"]}: {node}', '', description, '',
                        f'Evidence: [{test.get("raw_evidence")}]({test.get("raw_evidence")})', '']
    issue_lines += ['## Contract and remaining limits', '',
        'GA-04/07 now exercise explicit structured policy input. The existing free-form GUI prompt does not infer arbitrary allowlists or per-tool budgets. '
        'After any rejected, failed or pending attempt, final free-form synthesis is withheld and replaced by the journal report; a successful-only answer remains unchanged. '
        'Unverified synthesis is buffered before UI delivery. The GUI integration group exercises the visible Query UI, EDT and real PluginTool; external model reliability belongs to the optional real_llm group. '
        'The three MCP reference-length assertions remain unchanged and unresolved. A repeatable native decompiler contract compares complete MCP data before and after pagination; MCP pagination now uses actual newline separators.', '']
    (run / 'production-issues.md').write_text('\n'.join(issue_lines))
    repos = {}
    for name in ('GhidrAssist', 'GhidrAssistMCP'):
        path = ROOT / 'repos' / name
        def git(*args):
            return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()
        repos[name] = {'head': git('rev-parse', 'HEAD'), 'branch': git('branch', '--show-current'),
                       'working_tree_changes': git('status', '--porcelain')}
    result = {'run_id': run_id, 'started_at': started, 'finished_at': utc(), 'strict': strict,
              'run_status': 'FAIL' if failure else 'INCOMPLETE' if gaps else 'PASS', 'exit_code': 1 if failure else 0,
              'pytest_exit_code': pytest_code, 'counts': counts, 'groups': groups, 'tests': tests,
              'required_group_gaps': gaps, 'infrastructure': infrastructure,
              'infrastructure_status': 'BLOCKED' if infrastructure else 'PASS',
              'mcp': {'url': server.url if server else None, 'lifecycle': 'mcp-lifecycle.json',
                      'readiness': 'mcp-readiness.json'},
              'repositories': repos, 'environment': config,
              'baseline_run': '20261027T102614.814219Z-4cacec9a',
              'historical_results': {'counts': {'PASS': 15, 'FAIL': 3, 'SKIP': 6},
                'included_in_current_counts': False, 'source': 'user-provided prior live run; legacy artifacts remain in evidence/'},
              'artifacts': sorted(str(p.relative_to(run)) for p in run.rglob('*') if p.is_file())}
    dump(run / 'summary.json', result)
    lines = [f'# Regression {run_id}', '', f"Status: **{result['run_status']}**. Strict: {strict}.", '',
             ' | '.join(f'{key}: {value}' for key, value in counts.items()), '',
             '| Group | PASS | FAIL | SKIP | BLOCKED | NOT_IMPLEMENTED |', '|---|---:|---:|---:|---:|---:|']
    for name, values in groups.items():
        lines.append('| ' + name + ' | ' + ' | '.join(str(values[s]) for s in STATUSES) + ' |')
    lines += ['', 'Historical 15 PASS / 3 FAIL / 6 SKIP is excluded from this run.', '', '## Infrastructure', '']
    lines += [f'- {x}' for x in infrastructure] or ['No environment failures.']
    lines += ['', '## Executed assertions and limitations', '']
    for test in tests:
        lines.append(f"- **{test['status']}** `{test['nodeid']}` ({test['duration_seconds']:.3f}s)")
        if test['status'] != 'PASS':
            lines += ['', f"  Expected: `{str(test.get('expected_value', 'Execution of this test'))[:800]}`", '',
                      f"  Received: `{str(test.get('received_value', test.get('assertion_message')))[:1200]}`", '',
                      f"  Assertion: `{str(test.get('assertion_message'))[:1600]}`", '']
        if test.get('raw_evidence'):
            lines.append(f"  Evidence: [{test['raw_evidence']}]({test['raw_evidence']})")
    lines += ['', '## Raw evidence', '', *[f'- [{p}]({p})' for p in result['artifacts']], '']
    (run / 'summary.md').write_text('\n'.join(lines))
    dump(run / 'checksums.json', {str(p.relative_to(run)): fingerprint(p)
                                for p in sorted(run.rglob('*')) if p.is_file()})
    # A mutable pointer only; no legacy report is overwritten.
    dump(ROOT / 'evidence' / 'latest.json', {'run_id': run_id,
        'summary_json': str((run / 'summary.json').relative_to(ROOT)),
        'summary_markdown': str((run / 'summary.md').relative_to(ROOT)), 'run_status': result['run_status']})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--strict', action='store_true', help='fail if a required group is absent or incomplete')
    parser.add_argument('--allow-partial', action='store_false', dest='strict', help='diagnostic mode; incomplete coverage is labelled INCOMPLETE')
    parser.set_defaults(strict=True)
    parser.add_argument('--port', type=int, default=18080, help='preferred loopback MCP port; 0 selects any free port')
    parser.add_argument('--startup-timeout', type=float, default=120)
    parser.add_argument('--suite-timeout', type=float, default=900)
    parser.add_argument('--keep-workdir', action='store_true')
    parser.add_argument('--without-mcp', action='store_true', help='targeted diagnostic run; do not start MCP')
    parser.add_argument('--test-path', action='append', default=[], help='pytest file/node selection; repeatable')
    parser.add_argument('--select', help='pytest -k expression for targeted validation')
    parser.add_argument('--real-llm', action='store_true', help='enable optional free local LLM scenarios; never use paid providers')
    parser.add_argument('--llm-repeats', type=int, default=1)
    parser.add_argument('--agentic-cases', help='comma-separated controlled Agentic scenarios')
    parser.add_argument('--ghidra', default=os.getenv('GHIDRA_INSTALL_DIR', '/home/namok/Kompilacja/ReverseEngineering/ghidra_12.1.4_PUBLIC'))
    parser.add_argument('--project', default=os.getenv('GHIDRA_PROJECT_GPR', '/home/namok/Projekty/Samochody/ECU411-2.1.2.gpr'))
    parser.add_argument('--index', default=os.getenv('RAG_SOURCE_INDEX', '/home/namok/.config/GhidrAssist/LuceneIndex'))
    parser.add_argument('--preferences', default=os.getenv('RAG_SOURCE_PREFERENCES', '/home/namok/.config/ghidra/ghidra_12.1.4_PUBLIC/preferences'))
    args = parser.parse_args()
    if args.llm_repeats < 1 or args.llm_repeats > 20: parser.error('--llm-repeats must be 1..20')
    if not 0 <= args.port <= 65535:
        parser.error('--port must be 0..65535')
    run_id = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ') + '-' + uuid.uuid4().hex[:8]
    run = ROOT / 'evidence' / 'runs' / run_id
    run.mkdir(parents=True, exist_ok=False)
    started = utc()
    config, server, pytest_process, pytest_code = {}, None, None, 2
    infrastructure, pytest_data = [], {}
    work = Path(tempfile.mkdtemp(prefix=f'ghidrassist-{run_id}-'))
    protected = {'project_gpr': Path(args.project), 'project_rep': Path(args.project).with_suffix('.rep'),
                 'rag_index': Path(args.index), 'preferences': Path(args.preferences)}
    for legacy in (ROOT / 'evidence').iterdir():
        if legacy.is_file() and legacy.name != 'latest.json':
            protected['legacy/' + legacy.name] = legacy
    source_manifest = {}
    for directory in ('scripts', 'tests'):
        for source in (ROOT / directory).rglob('*'):
            if source.is_file() and '__pycache__' not in source.parts:
                relative = source.relative_to(ROOT)
                destination = run / 'harness-source' / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
                source_manifest[str(relative)] = fingerprint(source)
    dump(run / 'harness-source-manifest.json', source_manifest)
    before = {}
    print(f'RUN_ID={run_id}\nEVIDENCE={run}', flush=True)
    # SIGTERM and Ctrl-C use the same cleanup path as exceptions.
    previous_term = signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        for dependency in ('pytest', 'pytest_jsonreport', 'mcp'):
            if importlib.util.find_spec(dependency) is None:
                raise RuntimeError(f'BLOCKED: Python dependency {dependency} is missing')
        before = {name: fingerprint(path) for name, path in protected.items()}
        dump(run / 'protected-before.json', before)
        config = prepare_environment(work, Path(args.ghidra), Path(args.project), Path(args.index), Path(args.preferences))
        config.update(run_id=run_id, evidence=str(run), source_preferences=args.preferences, real_llm=args.real_llm, llm_repeats=args.llm_repeats)
        dump(run / 'environment.json', config)
        if not args.without_mcp:
            server = MCPProcess(config, run, args.port)
            server.start(args.startup_timeout)
        env = dict(os.environ, MCP_URL=server.url if server else 'http://127.0.0.1:0/mcp', EVIDENCE_DIR=str(run),
                   HARNESS_CONFIG=str(run / 'environment.json'), GHIDRA_SNAPSHOT=str(run / 'ghidra-snapshot.json'))
        if args.real_llm:
            env['GHIDRASSIST_REAL_LLM']='1'
            env['GHIDRASSIST_LLM_REPEATS']=str(args.llm_repeats)
        if args.agentic_cases:
            env['AGENTIC_SCENARIOS'] = args.agentic_cases
        cases = json.loads((ROOT / 'tests' / 'mcp_cases.json').read_text())['cases']
        tools = {case['tool'] for case in cases.values()} | {'get_task_status'}
        env['MCP_READONLY_TOOLS'] = ','.join(sorted(tools))
        command = [sys.executable, '-m', 'pytest', '-q', '--json-report',
                   f'--json-report-file={run / "pytest-report.json"}', f'--junitxml={run / "junit.xml"}']
        command += args.test_path
        if args.select:
            command += ['-k', args.select]
        dump(run / 'pytest-command.json', {'command': command, 'MCP_URL': env['MCP_URL']})
        with (run / 'pytest.log').open('x') as stream:
            pytest_process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=stream,
                                              stderr=subprocess.STDOUT, start_new_session=True)
            deadline = time.monotonic() + args.suite_timeout
            while pytest_process.poll() is None:
                if server and server.process.poll() is not None:
                    server.record('unexpected_exit_during_pytest', exit_code=server.process.returncode)
                    raise RuntimeError('BLOCKED: MCP/Ghidra unexpectedly exited during pytest')
                if time.monotonic() > deadline:
                    raise RuntimeError(f'BLOCKED: full suite timeout after {args.suite_timeout}s')
                time.sleep(.2)
            pytest_code = pytest_process.returncode
    except BaseException as exc:
        infrastructure.append(f'{type(exc).__name__}: {exc}')
        (run / 'runner-error.log').write_text(traceback.format_exc())
    finally:
        if pytest_process:
            stop_process(pytest_process)
        dump(run / 'probe-cleanup.json', cleanup_probe_groups(run))
        if server:
            try:
                server.close()
                if server.events and server.events[-1]['kind'] == 'stopped' and not server.events[-1]['port_closed']:
                    infrastructure.append('BLOCKED: owned MCP port remained open after shutdown')
            except Exception as exc:
                infrastructure.append(f'BLOCKED: shutdown failed: {exc}')
        raw = run / 'pytest-report.json'
        if raw.exists():
            pytest_data = json.loads(raw.read_text())
        if before:
            after = {name: fingerprint(path) for name, path in protected.items()}
            dump(run / 'protected-after.json', after)
            if before != after:
                infrastructure.append('FAIL: source project, index or source preferences changed during the run')
        if not args.keep_workdir:
            shutil.rmtree(work)
        signal.signal(signal.SIGTERM, previous_term)
    result = report(run, run_id, args.strict, pytest_data, infrastructure, config, server, started, pytest_code)
    print(json.dumps({'status': result['run_status'], 'counts': result['counts'],
                      'required_group_gaps': result['required_group_gaps'], 'report': str(run / 'summary.md')}, indent=2))
    return result['exit_code']


if __name__ == '__main__':
    raise SystemExit(main())
