"""Opt-in local-provider transport capture. Never generates a model response."""
import contextlib,datetime,http.server,ipaddress,json,re,threading,urllib.request,urllib.error,urllib.parse
from pathlib import Path


def property_value(path,key):
    text=Path(path).read_text();prefix=key+'='
    value=next((line[len(prefix):] for line in text.splitlines() if line.startswith(prefix)),None)
    if value is None:return None
    value=re.sub(r'\\u([0-9a-fA-F]{4})',lambda m:chr(int(m[1],16)),value)
    return re.sub(r'\\(.)',lambda m:{'n':'\n','t':'\t','r':'\r'}.get(m[1],m[1]),value)


def local_url(url):
    u=urllib.parse.urlparse(url)
    return u.scheme=='http' and u.hostname in ('127.0.0.1','localhost','::1') and not u.username and not u.password


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs):raise urllib.error.HTTPError(args[0].full_url,args[2],'Redirect refused',args[4],None)


def opener():
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())


def discover(preferences):
    providers=json.loads(property_value(preferences,'GhidrAssist.APIProviders') or '[]')
    evidence={'configured':[{'name':p.get('name'),'type':p.get('type'),'model':p.get('model'),
        'local':local_url(p.get('url',''))} for p in providers], 'probes':[], 'paid_provider_invoked':False}
    candidates=[dict(p) for p in providers if p.get('type') in ('LMSTUDIO','OLLAMA') and local_url(p.get('url',''))]
    candidates.sort(key=lambda p:p.get('type')!='LMSTUDIO')
    # An unconfigured LM Studio may be used only when its native local endpoint
    # identifies loaded LLMs. Do not treat an arbitrary OpenAI proxy as free.
    if not candidates:
        try:
            with opener().open('http://127.0.0.1:1234/api/v0/models',timeout=2) as response: models=json.load(response).get('data',[])
            loaded=[m for m in models if m.get('type')=='llm' and m.get('state')=='loaded']
            evidence['probes'].append({'url':'http://127.0.0.1:1234/api/v0/models','loaded_models':[m['id'] for m in loaded]})
            if loaded:candidates.append({'name':'Detected local LM Studio','type':'LMSTUDIO','model':loaded[0]['id'],'url':'http://127.0.0.1:1234/v1/','key':'','maxTokens':4096,'timeout':90,'bypassProxy':True,'disableTlsVerification':False})
        except Exception as error:evidence['probes'].append({'url':'http://127.0.0.1:1234/api/v0/models','error':str(error)})
    for candidate in candidates:
        u=urllib.parse.urlparse(candidate['url']);root=urllib.parse.urlunparse((u.scheme,u.netloc,'','','',''))
        endpoint=root+('/api/tags' if candidate['type']=='OLLAMA' else '/v1/models')
        try:
            headers={'Authorization':'Bearer '+candidate['key']} if candidate.get('key') else {}
            with opener().open(urllib.request.Request(endpoint,headers=headers),timeout=3) as response:data=json.load(response)
            ids=[m.get('name') for m in data.get('models',[])] if candidate['type']=='OLLAMA' else [m.get('id') for m in data.get('data',[])]
            evidence['probes'].append({'url':endpoint,'model_ids':ids})
            if not ids:continue
            if candidate.get('model') not in ids:
                evidence['probes'][-1]['error']='Configured model is not available';continue
            evidence['selected']={k:candidate.get(k) for k in ('name','type','model','url')}
            return candidate,evidence
        except Exception as error:evidence['probes'].append({'url':endpoint,'error':str(error)})
    evidence['blocked_reason']='No usable configured free local LLM or verified loaded LM Studio model. Paid/OAuth providers were not invoked.'
    return None,evidence


class RecordingProxy:
    """Transparent loopback-only relay; complete upstream bodies are kept verbatim."""
    def __init__(self,provider,directory):
        if provider.get('type') not in ('LMSTUDIO','OLLAMA') or not local_url(provider['url']):raise ValueError('Only local free LM Studio/Ollama providers are permitted')
        self.provider=provider;self.directory=Path(directory);self.records=[];self.lock=threading.Lock();self.local=threading.local()
        self.file=(self.directory/'model-transport.jsonl').open('x');owner=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                raw=self.rfile.read(int(self.headers.get('Content-Length','0')))
                try:body=json.loads(raw)
                except Exception:body={}
                match=re.search(r'\[Regression case ([^]]+)\]',str(body))
                owner.local.case_id=match[1] if match else None
                owner.record('model_request',body=body,path=self.path)
                for m in body.get('messages',[]):
                    if m.get('role')=='tool':owner.record('conversation_tool_response',message=m)
                source=urllib.parse.urlparse(owner.provider['url']);target=urllib.parse.urlunparse((source.scheme,source.netloc,self.path,'','',''))
                headers={'Content-Type':self.headers.get('Content-Type','application/json')}
                if self.headers.get('Authorization'):headers['Authorization']=self.headers['Authorization']
                try:
                    request=urllib.request.Request(target,data=raw,headers=headers,method='POST')
                    try:
                        response=opener().open(request,timeout=owner.provider.get('timeout') or 90)
                    except urllib.error.HTTPError as error:response=error
                    with response:
                        payload=response.read();status=response.code;content_type=response.headers.get('Content-Type','application/json')
                    owner.record('upstream_response',status=status,body=payload.decode('utf-8','replace'))
                    owner.parse_response(payload)
                    self.send_response(status);self.send_header('Content-Type',content_type);self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
                except Exception as error:
                    owner.record('infrastructure_error',error=str(error));self.send_error(502,str(error))
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler);self.server.daemon_threads=True
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
    def record(self,kind,**values):
        item={'time':datetime.datetime.now(datetime.timezone.utc).isoformat(),'kind':kind,'case_id':getattr(self.local,'case_id',None),**values}
        with self.lock:self.records.append(item);self.file.write(json.dumps(item,ensure_ascii=False)+'\n');self.file.flush()
    def parse_response(self,payload):
        text=payload.decode('utf-8','replace');chunks=[]
        if text.lstrip().startswith('data:'):
            for line in text.splitlines():
                if line.startswith('data: ') and line[6:]!='[DONE]':
                    with contextlib.suppress(json.JSONDecodeError):chunks.append(json.loads(line[6:]))
        else:
            try:chunks=[json.loads(text)]
            except json.JSONDecodeError:
                for line in text.splitlines():
                    with contextlib.suppress(json.JSONDecodeError):chunks.append(json.loads(line))
        calls={};content=[]
        for chunk in chunks:
            for choice in chunk.get('choices',[]):
                part=choice.get('delta') or choice.get('message') or {}
                if part.get('content'):content.append(part['content'])
                for pos,call in enumerate(part.get('tool_calls',[])):
                    index=call.get('index',pos);state=calls.setdefault(index,{'tool':'','arguments':'','call_id':None})
                    function=call.get('function',{});state['tool']+=function.get('name','');state['arguments']+=function.get('arguments','');state['call_id']=call.get('id') or state['call_id']
            # Ollama native chat protocol.
            message=chunk.get('message',{})
            if message.get('content'):content.append(message['content'])
            for call in message.get('tool_calls',[]):self.record('model_proposal',tool=call.get('function',{}).get('name'),arguments=call.get('function',{}).get('arguments'))
        for call in calls.values():self.record('model_proposal',**call)
        if content:self.record('model_response',content=''.join(content))
    @property
    def endpoint(self):
        path=urllib.parse.urlparse(self.provider['url']).path
        return f'http://127.0.0.1:{self.server.server_address[1]}'+(path if path.endswith('/') else path+'/')
    def __enter__(self):self.thread.start();return self
    def __exit__(self,*args):self.server.shutdown();self.server.server_close();self.thread.join(timeout=5);self.file.close()
