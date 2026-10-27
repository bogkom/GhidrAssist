"""Targeted, sequential Responses diagnostics using the existing GhidrAssist provider."""
import argparse, datetime, importlib.util, json, os, re, shutil, subprocess, tempfile
from pathlib import Path
from scripts.harness import ROOT, dump, prepare_environment, run_probe

STATE = Path('/tmp/ghidrassist-diagnostic-state.json')

def verify_mirrors():
    recorded=ROOT/'repos/GhidrAssist/tests/integration/workspace'
    for relative in ('scripts/AgenticProbe.java','scripts/harness.py','tests/test_real_llm.py'):
        if (ROOT/relative).read_bytes() != (recorded/relative).read_bytes():
            raise RuntimeError('Workspace harness differs from versioned regression bundle: '+relative)

def property_value(path, name):
    prefix=name+'='
    raw=next((s[len(prefix):] for s in Path(path).read_text().splitlines() if s.startswith(prefix)),None)
    if raw is None:return None
    raw=re.sub(r'\\u([0-9a-fA-F]{4})',lambda m:chr(int(m[1],16)),raw)
    return re.sub(r'\\(.)',lambda m:{'n':'\n','t':'\t','r':'\r'}.get(m[1],m[1]),raw)

def prepare():
    verify_mirrors()
    state=json.loads(STATE.read_text());out=Path(state['evidence'])
    work=Path(tempfile.mkdtemp(prefix='ghidrassist-responses-'+state['run_id']+'-'));work.chmod(0o700)
    preferences=Path('/home/namok/.config/ghidra/ghidra_12.1.4_PUBLIC/preferences')
    providers=json.loads(property_value(preferences,'GhidrAssist.APIProviders'))
    provider=next(p for p in providers if p['type']=='OPENAI_OAUTH' and p['name']=='ChatGPT Plus')
    secret=work/'provider.json'
    fd=os.open(secret,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'w') as stream:json.dump(provider,stream)
    config=prepare_environment(work,'/home/namok/Kompilacja/ReverseEngineering/ghidra_12.1.4_PUBLIC',
        '/home/namok/Projekty/Samochody/ECU411-2.1.2.gpr','/home/namok/.config/GhidrAssist/LuceneIndex',preferences)
    # An exact copy of installed binaries is loaded separately; installation is never changed.
    base=work/'installed';base.mkdir()
    for name in ('project','home','cache','settings'):(base/name).mkdir()
    shutil.copytree(work/'agentic/project',base/'project',dirs_exist_ok=True)
    extensions=base/'settings/namok-ghidra/ghidra_12.1.4_PUBLIC/Extensions';extensions.mkdir(parents=True)
    installed=Path('/home/namok/.config/ghidra/ghidra_12.1.4_PUBLIC/Extensions')
    for name in ('GhidrAssist','GhidrAssistMCP'):shutil.copytree(installed/name,extensions/name)
    config['environments']['installed']={'base':str(base),'project':str(base/'project'),'settings':str(base/'settings')}
    config.update(run_id=state['run_id'],evidence=str(out))
    dump(out/'environment.json',config)
    state.update(work=str(work),config=str(out/'environment.json'));dump(STATE,state)
    dump(out/'provider-public.json',{k:provider.get(k) for k in ('name','type','model','maxTokens','url','timeout','bypassProxy','disableTlsVerification')})
    print(json.dumps({'prepared':state['run_id'],'provider':provider['type'],'model':provider['model']}))

def run(label, scenarios):
    verify_mirrors()
    state=json.loads(STATE.read_text());out=Path(state['evidence'])/label;out.mkdir(exist_ok=False)
    cfg=json.loads(Path(state['config']).read_text());work=Path(state['work'])
    dump(out/'scenarios.json',scenarios)
    record=run_probe(cfg,'agentic','AgenticProbe.java',['DIRECT',out/'scenarios.json',out/'results.json',cfg['index'],cfg['catalog'],state['run_id'],work/'provider.json'],work/(label+'.private.log'),timeout=max(300,len(scenarios)*240+60))
    result=json.loads((out/'results.json').read_text())
    dump(out/'process-safe.json',{k:record[k] for k in ('exit_code','duration_seconds','started_at','finished_at')})
    print(json.dumps({'label':label,'cases':{k:{'status':v.get('status'),'harness_error':v.get('harness_error'),'tool_count':v.get('actual_dispatcher_count'),'http':[{f:c.get(f) for f in ('http_status','api_error','api_error_detail','input_tokens','output_tokens','duration_seconds')} for c in v.get('provider_http_calls',[])]} for k,v in result['cases'].items()}}))
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('mode',choices=['prepare','negative','e2e','matrix']);args=parser.parse_args()
    if args.mode=='prepare':prepare()
    elif args.mode=='negative':run('negative-original',[{'id':'NEGATIVE_ORIGINAL','prompt':'Call get_regression_fact with key alpha and report execution_count=N.','reasoning':'none','wire_safe_tools':False}])
    elif args.mode=='e2e':run('e2e',[{'id':'E2E','prompt':'Call ga_get_document_page exactly once with filename MC68332UM.pdf, page 256, scope all, offset 0, max_chars 600. Report returnedCharacters and PDF_PAGE and finish with execution_count=N backed by actual executions.','reasoning':'none','wire_safe_tools':True}])
    else:
        state=json.loads(STATE.read_text());gate=json.loads(Path(state['evidence'],'e2e/results.json').read_text())['cases']['E2E']
        assert gate['status']=='SUCCESS' and gate['actual_dispatcher_count']==1 and 'execution_count=1' in gate['answer'], 'End-to-end gate did not pass'
        spec=importlib.util.spec_from_file_location('scenario_source',ROOT/'tests/test_real_llm.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        scenarios=[dict(module.scenario(name,index),wire_safe_tools=True,reasoning='high') for index in (1,2) for name in module.CASES]
        run('matrix',scenarios)
