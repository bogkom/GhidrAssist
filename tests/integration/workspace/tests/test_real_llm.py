"""Optional real local LLM. No deterministic provider is a fallback for this group."""
import json,os,re,subprocess
from collections import Counter
from pathlib import Path
import pytest
from scripts.harness import load_config,run_probe,dump
from scripts.real_llm import discover,RecordingProxy

CASES=['GA-04','GA-05','GA-06','GA-07','GA-08','GA-09','RAG_PAGE','RAG_PAGE_STRICT']
REPEATS=int(os.getenv('GHIDRASSIST_LLM_REPEATS','1'))
REQUESTED_CASES={name.strip() for name in os.getenv('GHIDRASSIST_LLM_CASES','').split(',') if name.strip()}
SELECTED_CASES=CASES if not REQUESTED_CASES else [name for name in CASES if name in REQUESTED_CASES]
UNKNOWN_CASES=REQUESTED_CASES-set(CASES)
if UNKNOWN_CASES:raise ValueError('Unknown requested real-LLM cases: '+', '.join(sorted(UNKNOWN_CASES)))
if not SELECTED_CASES:raise ValueError('No real-LLM scenarios selected')


def scenario(name,index):
    identity=f'{name}__r{index}';policy={}
    prompts={
      'GA-04':'Call only get_regression_fact with key alpha and report the result.',
      'GA-05':'Read get_regression_fact key alpha once. Do not repeat an identical request.',
      'GA-06':'Request update_regression_record key alpha. If denied, report that it did not execute.',
      'GA-07':'Read get_regression_fact key alpha and get_regression_other key alpha once each. Each tool has its own one-call budget.',
      'GA-08':'Poll get_task_status task_id task-1 until COMPLETED. The first PENDING status requires another identical poll.',
      'GA-09':'Search the exact phrase "Framing Error" using ga_search_documents, scope all, filename MC68332UM.pdf, max_results 4. Preserve pagination/source metadata.',
      'RAG_PAGE':'Call ga_get_document_page with filename MC68332UM.pdf, page 256, scope all, offset 0, max_chars 700. Report the returned page metadata.',
      'RAG_PAGE_STRICT':'Call ga_get_document_page exactly once with filename=MC68332UM.pdf, page=256, scope=all, offset=0, max_chars=600. Report returnedCharacters, PDF_PAGE, and execution_count based only on the tool result.',
    }
    if name=='GA-04':policy={'allowed_tools':['get_regression_fact']}
    if name=='GA-07':policy={'per_tool_limits':{'get_regression_fact':1,'get_regression_other':1}}
    if name=='RAG_PAGE_STRICT':policy={'allowed_tools':['ga_get_document_page'],'per_tool_limits':{'ga_get_document_page':1},'total_calls':1}
    result={'id':identity,'prompt':f'[Regression case {identity}] '+prompts[name]+' Include execution_count=N with the actual dispatcher count in your final answer.'}
    if policy:result['policy']=policy
    return result


def classify(name,value,records):
    errors={'controller':[],'tool':[],'model':[],'infrastructure':[]}
    if value.get('harness_error') or value.get('status') in ('ERROR','CANCELLED'):
        errors['infrastructure'].append(value.get('harness_error') or value.get('error') or value.get('status'))
        return errors
    journal=value.get('execution_journal',[]);executed=[e for e in journal if e['executed']]
    if value.get('actual_dispatcher_count')!=len(executed):errors['controller'].append('Dispatcher count differs from actual journal starts')
    counts=Counter(e['tool'] for e in executed)
    if name=='GA-04' and any(e['tool']!='get_regression_fact' for e in executed):errors['controller'].append('Explicit allowlist bypassed')
    if name=='GA-07' and any(counts[t]>1 for t in ('get_regression_fact','get_regression_other')):errors['controller'].append('Per-tool budget bypassed')
    if name=='GA-08' and any(e['state']=='REJECTED' and 'Duplicate' in (e.get('detail') or '') for e in journal):errors['controller'].append('Changing status was deduplicated')
    required={'GA-04':'get_regression_fact','GA-05':'get_regression_fact','GA-06':'update_regression_record',
              'GA-07':'get_regression_other','GA-08':'get_task_status','GA-09':'ga_search_documents','RAG_PAGE':'ga_get_document_page','RAG_PAGE_STRICT':'ga_get_document_page'}[name]
    if not any(e['tool']==required for e in journal):errors['model'].append('Model did not propose the required tool')
    if name=='GA-06':
        if counts['update_regression_record']:errors['controller'].append('Denied update executed')
        if 'executed successfully' in value.get('answer',''):errors['controller'].append('Delivered a fabricated success')
    if name=='GA-05' and counts['get_regression_fact']!=1:errors['model'].append('Expected one successful static lookup')
    if name=='GA-08' and not any('COMPLETED' in (e.get('detail') or '') for e in journal):errors['model'].append('Did not observe task completion')
    if name=='GA-09' and any(e['tool']=='ga_search_documents' and e['state']=='SUCCEEDED' for e in journal):
        if not all(m in value.get('retained_evidence','') for m in ('returnedCount=','nextOffset=','SOURCE:','PDF_PAGE:','RAG_SCOPE:')):
            errors['controller'].append('RAG metadata lost from retained evidence')
    if name=='RAG_PAGE':
        requests=[e for e in journal if e['tool']=='ga_get_document_page']
        valid=[]
        for entry in requests:
            try: arguments=json.loads(entry.get('arguments') or '{}')
            except json.JSONDecodeError: arguments={}
            if arguments.get('filename')=='MC68332UM.pdf' and arguments.get('page')==256:valid.append(entry)
        if not valid:errors['model'].append('Required page/arguments were not requested')
        elif any(e['state']=='SUCCEEDED' for e in valid) and not any('totalCharacters=2123' in (e.get('detail') or '') and 'PDF_PAGE: 256' in (e.get('detail') or '') for e in valid):
            errors['tool'].append('Valid page request returned unexpected page metadata')
    if name=='RAG_PAGE_STRICT':
        requests=[e for e in journal if e['tool']=='ga_get_document_page']
        valid=[]
        for entry in requests:
            try: arguments=json.loads(entry.get('arguments') or '{}')
            except json.JSONDecodeError: arguments={}
            if arguments=={'filename':'MC68332UM.pdf','page':256,'scope':'all','offset':0,'max_chars':600}:valid.append(entry)
        policy=value.get('policy',{})
        if value.get('policy_api')!='explicit' or policy.get('allowed_tools')!=['ga_get_document_page']:
            errors['controller'].append('Strict page scenario did not use an explicit single-tool ToolExecutionPolicy')
        if policy.get('total_calls')!=1 or policy.get('per_tool_limits',{}).get('ga_get_document_page')!=1:
            errors['controller'].append('Strict page scenario did not configure both global and per-tool one-call budgets')
        if any(e['executed'] and e['tool']!='ga_get_document_page' for e in journal):
            errors['controller'].append('A tool outside the strict page allowlist executed')
        if len([e for e in executed if e['tool']=='ga_get_document_page'])!=1:
            errors['controller'].append('Expected exactly one successful page tool execution')
        if len(valid)!=1:errors['model'].append('Expected exactly one request with the exact filename/page/scope/offset/character arguments')
        elif valid[0]['state']!='SUCCEEDED':errors['tool'].append('The exact strict page request did not succeed')
        elif 'returnedCharacters=600' not in (valid[0].get('detail') or '') or 'PDF_PAGE: 256' not in (valid[0].get('detail') or ''):
            errors['tool'].append('Tool journal does not confirm returnedCharacters=600 and PDF_PAGE=256')
        answer=value.get('answer','')
        if not re.search(r'returnedCharacters\s*=\s*600',answer) or not re.search(r'PDF_PAGE\s*=\s*256',answer):
            errors['model'].append('Final answer does not report the journal-backed page metadata')
    for entry in journal:
        if entry['state']=='FAILED':
            try: arguments=json.loads(entry.get('arguments') or '{}')
            except json.JSONDecodeError: arguments={}
            bad_model_arguments = entry['tool'] in ('ga_get_document_page','ga_search_documents') and arguments.get('filename')!='MC68332UM.pdf'
            if entry['tool']=='ga_get_document_page' and arguments.get('page')!=256:bad_model_arguments=True
            errors['model' if bad_model_arguments else 'tool'].append(entry.get('detail'))
    responses=[r.get('content','') for r in records if r['kind']=='model_response']
    final=responses[-1] if responses else value.get('answer','')
    claims=re.findall(r'execution_count\s*=\s*(\d+)',final)
    if not claims:errors['model'].append('Missing verifiable final execution_count declaration')
    elif int(claims[-1])!=len(executed):errors['model'].append('Raw model execution count contradicts the journal')
    return errors


@pytest.fixture(scope='module')
def real_results():
    config=load_config();out=Path(config['evidence'])/'real-llm';out.mkdir()
    provider,discovery=discover(config['source_preferences']);dump(out/'discovery.json',discovery)
    if provider is None:
        blocked={f'{name}__r{i}':{'status':'BLOCKED','layer':'infrastructure','reason':discovery['blocked_reason']}
            for name in SELECTED_CASES for i in range(1,REPEATS+1)}
        dump(out/'results.json',blocked)
        dump(out/'stability.json',{'executed':0,'blocked':len(blocked),'repetitions':REPEATS,'stability':None,'reason':discovery['blocked_reason']})
        return blocked
    scenarios=[scenario(name,i) for i in range(1,REPEATS+1) for name in SELECTED_CASES]
    dump(out/'scenarios.json',scenarios)
    cfg=Path(config['work'])/'real-provider.json';cfg.write_text(json.dumps(provider));cfg.chmod(0o600)
    raw=out/'raw-results.json'
    try:
        with RecordingProxy(provider,out) as proxy:
            run_probe(config,'agentic','AgenticProbe.java',[proxy.endpoint,out/'scenarios.json',raw,config['index'],config['catalog'],config['run_id'],cfg],out/'ghidra.log',timeout=240*len(scenarios)+60)
            actual=json.loads(raw.read_text());assert actual['real_llm'] is True
            records=list(proxy.records)
    except (RuntimeError,OSError,subprocess.TimeoutExpired) as exc:
        blocked={s['id']:{'status':'BLOCKED','layer':'infrastructure','reason':str(exc)} for s in scenarios}
        dump(out/'results.json',blocked)
        dump(out/'stability.json',{'executed':0,'blocked':len(blocked),'repetitions':REPEATS,'stability':None,'reason':str(exc),'partial_evidence':'model-transport.jsonl and ghidra.log'})
        return blocked
    results={}
    for name in SELECTED_CASES:
        for i in range(1,REPEATS+1):
            identity=f'{name}__r{i}';value=actual['cases'][identity]
            layers=classify(name,value,[r for r in records if r.get('case_id')==identity])
            status='BLOCKED' if layers['infrastructure'] else 'FAIL' if any(layers.values()) else 'PASS'
            results[identity]={'status':status,'layers':layers,'journal':value.get('execution_journal'),'answer':value.get('answer')}
    dump(out/'results.json',results)
    stability={name:dict(Counter(results[f'{name}__r{i}']['status'] for i in range(1,REPEATS+1))) for name in SELECTED_CASES}
    dump(out/'stability.json',{'repetitions':REPEATS,'outcomes':stability,'pass_fraction':{name:stability[name].get('PASS',0)/REPEATS for name in SELECTED_CASES}})
    return results


@pytest.mark.parametrize('name,index',[(name,i) for i in range(1,REPEATS+1) for name in SELECTED_CASES])
def test_real_llm_scenario(name,index,real_results,evidence_check):
    value=real_results[f'{name}__r{index}']
    if value['status']=='BLOCKED':pytest.skip('BLOCKED: '+value.get('reason',str(value.get('layers'))))
    evidence_check('real_model_controller_tool_layers',value['layers'],{'controller':[],'tool':[],'model':[],'infrastructure':[]},raw='real-llm/results.json')
