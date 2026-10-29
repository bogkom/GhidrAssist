"""Visible Swing editor regression with a large MCP-shaped inventory; no model calls."""
import json,os,subprocess
from pathlib import Path
import pytest
from scripts.harness import ROOT,load_config,dump,stop_process,process_identity


def test_task_tool_editor(evidence_check):
    config=load_config()
    if not os.getenv('DISPLAY'):pytest.skip('BLOCKED: no X display for visible Swing editor')
    out=Path(config['evidence'])/'task-tool-editor';out.mkdir()
    repo=ROOT/'repos/GhidrAssist'
    cp=os.pathsep.join(map(str,[repo/'build/classes/java/test',repo/'build/classes/java/main',*sorted((repo/'lib').glob('*.jar')),*sorted(Path(config['ghidra']).rglob('*.jar'))]))
    state=config['environments']['agentic']
    command=['/usr/lib/jvm/java-25-openjdk-amd64/bin/java','-Djava.awt.headless=false','-Duser.home='+state['base']+'/home','-cp',cp,'ghidrassist.ui.common.TaskToolPolicyPanelSelfTest',str(out)]
    with (out/'process.log').open('x') as log:
        p=subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        record={'pid':p.pid,'identity':process_identity(p.pid),'exit_code':None};dump(out/'editor.process.json',record)
        try:code=p.wait(timeout=90)
        finally:stop_process(p);record['exit_code']=p.returncode;dump(out/'editor.process.json',record)
    evidence_check('visible_editor_exit',code,0,raw='task-tool-editor/process.log')
    result=json.loads((out/'editor-results.json').read_text())
    evidence_check('large_inventory_count',result['inventory'],320,raw='task-tool-editor/editor-results.json')
    evidence_check('editor_contracts',result['status'],'PASS',raw='task-tool-editor/editor-results.json')
