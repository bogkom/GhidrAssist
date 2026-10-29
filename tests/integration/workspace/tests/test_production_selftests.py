"""Production contract tests compiled by the final GhidrAssist build."""
import json
import os
from pathlib import Path
import subprocess
import pytest
from scripts.harness import ROOT, dump, load_config, stop_process, process_identity

@pytest.mark.parametrize('class_name', [
    'ghidrassist.apiprovider.APIProviderDiagnosticsSelfTest',
    'ghidrassist.tools.registry.ToolExecutionPolicySelfTest',
    'ghidrassist.tools.registry.ToolAliasBudgetSelfTest',
    'ghidrassist.tools.registry.ToolExecutionJournalSelfTest',
    'ghidrassist.tools.context.ToolResultContextSelfTest',
])
def test_production_contract(class_name, evidence_check):
    try:
        config = load_config()
    except RuntimeError as error:
        pytest.skip(str(error))
    directory = Path(config['evidence']) / 'production-contracts'
    directory.mkdir(exist_ok=True)
    repo = ROOT / 'repos/GhidrAssist'
    class_file = repo / 'build/classes/java/test' / (class_name.replace('.', '/') + '.class')
    assert class_file.exists(), f'Compile production contract tests before this run: {class_file}'
    cp = os.pathsep.join(map(str, [repo / 'build/classes/java/test', repo / 'build/classes/java/main',
        *sorted((repo / 'lib').glob('*.jar')), *sorted(Path(config['ghidra']).rglob('*.jar'))]))
    java_home = os.getenv('GHIDRA_JAVA_HOME', '/usr/lib/jvm/java-25-openjdk-amd64')
    home = Path(config['work']) / 'contract-home'
    home.mkdir(exist_ok=True)
    command = [java_home + '/bin/java', '-Djava.awt.headless=true', '-Duser.home=' + str(home), '-cp', cp, class_name]
    label = class_name.rsplit('.', 1)[-1]
    log = directory / (label + '.log')
    with log.open('x') as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, start_new_session=True)
        manifest = directory / (label + '.process.json')
        process_record = {'pid': process.pid, 'identity': process_identity(process.pid), 'exit_code': None}
        dump(manifest, process_record)
        try:
            code = process.wait(timeout=30)
        finally:
            stop_process(process)
            process_record['exit_code'] = process.returncode
            dump(manifest, process_record)
    dump(directory / (label + '.json'), {'command': command, 'exit_code': code})
    evidence_check(label, code, 0, raw=str(log.relative_to(Path(config['evidence']))))
    evidence_check(label + '_completion', log.read_text(), label + ' PASS', contains=True,
                   raw=str(log.relative_to(Path(config['evidence']))))
