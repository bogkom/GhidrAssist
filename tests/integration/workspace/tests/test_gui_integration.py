"""A real Ghidra GUI configuration, PluginTool and normal Query/Approve Swing path."""
import json,os,subprocess,time
from pathlib import Path
import pytest
from scripts.harness import ROOT,load_config,dump,stop_process,process_identity
from scripts.controlled_llm import ControlledLLM

@pytest.fixture(scope='module')
def gui_result():
    try: config=load_config()
    except RuntimeError as error: pytest.skip(str(error))
    if not os.getenv('DISPLAY'): pytest.skip('BLOCKED: no X display for actual Ghidra Swing integration')
    run=Path(config['evidence']);out=run/'gui';out.mkdir()
    state=config['environments']['agentic']
    extensions=Path(state['settings'])
    jars=[*sorted(Path(config['ghidra']).rglob('*.jar')),*sorted(extensions.rglob('*.jar'))]
    classes=Path(config['work'])/'gui-classes';classes.mkdir()
    cp=os.pathsep.join(map(str,jars));java='/usr/lib/jvm/java-25-openjdk-amd64/bin/'
    compile_cmd=[java+'javac','-cp',cp,'-d',str(classes),str(ROOT/'scripts/gui/GuiIntegrationMain.java')]
    compiled=subprocess.run(compile_cmd,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=60)
    (out/'compile.log').write_text(compiled.stdout)
    assert compiled.returncode==0, compiled.stdout
    class GuiModel(ControlledLLM):
        def respond(self,body,path):
            case=body.get('model','');text=str(body.get('messages',[]))
            if case.startswith('GUI_') and not body.get('tools') and 'Verified tool executions recorded by dispatcher:' not in text:
                self.record('model-requests',{'kind':'gui_planning','case_id':case,'body':body})
                return self.text_chunk('1. Run the task using the allowed tools and report verified outcomes.')
            if body.get('tools'):
                deadline=time.monotonic()+15
                while not (out/(case+'.registered')).exists():
                    if time.monotonic()>deadline:raise TimeoutError('GUI fixture provider registration timed out')
                    time.sleep(.02)
            return super().respond(body,path)
    env=dict(os.environ)
    command_base=[java+'java','-Djava.system.class.loader=ghidra.GhidraClassLoader','-Djava.awt.headless=false',
        '-Dapplication.settingsdir='+state['settings'],'-Dapplication.cachedir='+state['base']+'/cache',
        '-Duser.home='+state['base']+'/home','-cp',str(classes)+os.pathsep+cp,'GuiIntegrationMain',
        str(run/'environment.json')]
    with GuiModel(out) as model, (out/'gui-process.log').open('x') as log:
        command=command_base+[model.endpoint,str(out)]
        process=subprocess.Popen(command,cwd=state['base'],env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        manifest=out/'gui.process.json';record={'command':command,'pid':process.pid,'identity':process_identity(process.pid),'exit_code':None};dump(manifest,record)
        try:code=process.wait(timeout=300)
        finally:
            stop_process(process);record['exit_code']=process.returncode;dump(manifest,record)
    assert code==0, (out/'gui-process.log').read_text()[-6000:]
    result=json.loads((out/'gui-results.json').read_text())
    assert not result['application_headless'] and not result['awt_headless']
    return result

@pytest.mark.parametrize('case,expected', [('GUI_ALLOW',['REJECTED']),('GUI_BUDGET',['SUCCEEDED','REJECTED']),
    ('GUI_ASYNC',['SUCCEEDED','SUCCEEDED']),('GUI_ALIAS_BUDGET',['SUCCEEDED','REJECTED']),('GUI_STATIC_DUP',['SUCCEEDED','REJECTED'])])
def test_gui_task_policy(case,expected,gui_result,evidence_check):
    value=gui_result['cases'][case]
    evidence_check('real_gui_visible',value['window_showing'],True,raw='gui/gui-results.json')
    evidence_check('query_component_visible',value['query_showing'],True,raw='gui/gui-results.json')
    evidence_check('real_gui_edt',value['edt'],True,raw='gui/gui-results.json')
    evidence_check('dispatcher_states',[e['state'] for e in value['journal']],expected,raw='gui/gui-results.json')
    evidence_check('gui_feedback_states',[e[1] for e in value['gui_outcomes']],expected,raw='gui/gui-results.json')
    if case=='GUI_ALLOW':
        evidence_check('no_unverified_success_in_gui','executed successfully' in value['response_html'],False,raw='gui/gui-results.json')
    if case=='GUI_BUDGET':
        evidence_check('gui_native_page',str(value),'totalCharacters=2123',contains=True,raw='gui/gui-results.json')
    if case=='GUI_ASYNC':
        evidence_check('gui_async_complete',str(value),'COMPLETED',contains=True,raw='gui/gui-results.json')


def test_query_policy_ergonomics(gui_result,evidence_check):
    for label in ('policy_editor_detached','narrow_toolbar_unclipped','conversation_new_reset','conversation_switch_reset','cancel_plan_retains_settings','narrow_status_wrapped'):
        evidence_check(label,gui_result[label],True,raw='gui/gui-results.json')
    assert gui_result['narrow_query_width'] <= 360, gui_result['narrow_query_width']
