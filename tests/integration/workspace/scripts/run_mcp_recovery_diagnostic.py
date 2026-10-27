"""Two owned server cycles and actual GhidrAssist SSE SDK reconnect, no model calls."""
import json,os,subprocess,time,tempfile
from pathlib import Path
from scripts.harness import MCPProcess,PortLease,dump,stop_process

def wait(marker, process):
    end=time.monotonic()+70
    while not marker.exists():
        if process.poll() is not None:raise RuntimeError('SSE recovery client exited before control marker')
        if time.monotonic()>end:raise TimeoutError('SSE recovery control timeout')
        time.sleep(.1)

state=json.loads(Path('/tmp/ghidrassist-diagnostic-state.json').read_text());config=json.loads(Path(state['config']).read_text())
work=Path(state['work']);out=Path(state['evidence']);private=Path(tempfile.mkdtemp(prefix='mcp-recovery-',dir=work));classes=private/'classes';classes.mkdir()
cp=os.pathsep.join(map(str,[*sorted(Path(config['ghidra']).rglob('*.jar')),*sorted(Path(config['environments']['installed']['settings']).rglob('*.jar'))]))
java='/usr/lib/jvm/java-25-openjdk-amd64/bin/'
compile_result=subprocess.run([java+'javac','-cp',cp,'-d',str(classes),str(Path('scripts/MCPRecoveryMain.java').resolve())],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=60)
(out/(private.name+'.compile.log')).write_text(compile_result.stdout);assert compile_result.returncode==0,compile_result.stdout
server=None;process=None;cycles=[]
try:
    directory=private/'server-1';directory.mkdir();server=MCPProcess(config,directory,preferred_port=18080)
    port=server.lease.port
    with (private/'client.private.log').open('x') as log:
        process=subprocess.Popen([java+'java','-Djava.awt.headless=true','-cp',str(classes)+os.pathsep+cp,'MCPRecoveryMain',f'http://127.0.0.1:{port}',str(private),str(out/'mcp-sdk-recovery.json')],stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
        wait(private/'failed-before-start',process)
        server.start(timeout=90)
        other=PortLease(port);avoided=other.port!=port;other.close()
        (private/'ready-1').touch();wait(private/'ready-to-restart',process)
        server.close();cycles.append([{'kind':e['kind'],**{k:e[k] for k in ('tool_count','exit_code','port_closed') if k in e}} for e in server.events]);server=None
        (work/'mcp-finished').unlink(missing_ok=True)
        directory=private/'server-2';directory.mkdir();server=MCPProcess(config,directory,preferred_port=port);assert server.lease.port==port
        server.start(timeout=90);(private/'ready-2').touch()
        code=process.wait(timeout=45);assert code==0,'SSE recovery client failed'
        server.close();cycles.append([{'kind':e['kind'],**{k:e[k] for k in ('tool_count','exit_code','port_closed') if k in e}} for e in server.events]);server=None
    dump(out/'mcp-lifecycle-diagnostic.json',{'port':port,'occupied_port_lease_avoided':avoided,'cycles':cycles,'protocol_readiness':'official Python Streamable HTTP initialize/tools-list plus GhidrAssist Java SSE initialize/discovery/tool call','client_exit':code})
    print(json.dumps({'recovery':json.loads((out/'mcp-sdk-recovery.json').read_text()),'port_avoidance':avoided,'cycles':cycles}))
finally:
    if server is not None:server.close()
    if process is not None:stop_process(process)
