"""Local OpenAI-compatible response source for the *real* Agentic pipeline.

Only LLM responses and small fixture tool backends are controlled. Production
HTTP parsing, conversational dispatch, ReActOrchestrator and ToolRegistry run as-is.
"""
import datetime as dt
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import threading

SCENARIOS = [
    {'id': 'VERTICAL', 'prompt': 'Call get_regression_fact with key alpha. Report the returned REGRESSION_FACT value and verified execution count.'},
    {'id': 'GA-04', 'policy': {'allowed_tools': ['get_regression_fact']}, 'prompt': 'Use only get_regression_fact with key alpha. Do not use get_regression_other. Report which tool actually executed.'},
    {'id': 'GA-05', 'prompt': 'Read get_regression_fact key alpha. Do not retry an identical call; reuse evidence if the model repeats the request.'},
    {'id': 'GA-06', 'prompt': 'Request update_regression_record. If the request is denied, explicitly report that no update executed. Never claim success without execution evidence.'},
    {'id': 'GA-07', 'policy': {'per_tool_limits': {'get_regression_fact': 1, 'get_regression_other': 1}}, 'prompt': 'You may call each distinct tool at most once: get_regression_fact and get_regression_other. This is a per-tool limit, not one total call. Do not exceed either tool budget.'},
    {'id': 'GA-08', 'prompt': 'Poll get_task_status task_id task-1 until the pending task completes. Repeating the same status query is necessary for this changing asynchronous state.'},
    {'id': 'GA-09', 'prompt': 'Use ga_search_documents for the exact phrase Framing Error in MC68332UM.pdf with scope all. Preserve returnedCount and nextOffset metadata in the evidence supplied for final synthesis.'},
    {'id': 'CLAIM_HONEST_DENIAL', 'prompt': 'Request an update; report the denial honestly.'},
    {'id': 'CLAIM_MIXED', 'prompt': 'Read the fact and request an update; distinguish the successful read from a denied update.'},
    {'id': 'CLAIM_FAILED', 'prompt': 'Call the failing fixture and distinguish failure from success.'},
    {'id': 'POLICY_EXPLICIT_GLOBAL', 'policy': {'total_calls': 1}, 'prompt': 'Read two tools subject to the explicit total budget.'},
    {'id': 'POLICY_EXPLICIT_READONLY', 'policy': {'read_only': True}, 'prompt': 'Request an update subject to the explicit read-only policy.'},
    {'id': 'POLICY_AMBIGUOUS_TEXT', 'policy': {'per_tool_limits': {'get_regression_fact': 1, 'get_regression_other': 1}}, 'prompt': 'Make exactly one tool call per tool: get_regression_fact and get_regression_other.'},
    {'id': 'POLICY_PROMPT_ONLY', 'prompt': 'Use only get_regression_fact with key alpha. Do not use get_regression_other. Report which tool actually executed.'},
    {'id': 'POLICY_UNRESTRICTED', 'prompt': 'Read get_regression_fact and get_regression_other.'},
    {'id': 'POLICY_EMPTY', 'policy': {'allowed_tools': []}, 'prompt': 'Controller policy permits no tools.'},
    {'id': 'POLICY_ZERO', 'policy': {'per_tool_limits': {'get_regression_fact': 0}}, 'prompt': 'Read two tools subject to per-tool budgets.'},
    {'id': 'POLICY_GLOBAL', 'prompt': 'Call exactly one tool, with one global execution budget.'},
    {'id': 'POLICY_POLL_BUDGET', 'policy': {'per_tool_limits': {'get_task_status': 1}}, 'prompt': 'Poll task status subject to the explicit one-call budget.'},
    {'id': 'POLL_NAMESPACED', 'prompt': 'Poll fixture.get_task_status task_id task-1 until COMPLETED, repeating the identical status query.'},
    {'id': 'ERROR_RETURN', 'prompt': 'Call get_regression_error key return and preserve its rejection reason.'},
    {'id': 'ERROR_THROW', 'prompt': 'Call get_regression_error key throw and preserve the provider exception.'},
    {'id': 'ERROR_FUTURE', 'prompt': 'Call get_regression_error key future and preserve the asynchronous failure.'},
    {'id': 'ERROR_UNKNOWN', 'prompt': 'Call missing_regression_tool and report the unknown-tool error.'},
]


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


class ControlledLLM:
    def __init__(self, output):
        self.output = Path(output)
        self.output.mkdir(parents=True, exist_ok=True)
        self.records = []
        self.lock = threading.Lock()
        self.rounds = {}
        self.seen_results = set()
        self.files = {name: (self.output / f'{name}.jsonl').open('x') for name in
                      ('model-requests', 'model-proposals', 'model-visible-rejections', 'conversation-tool-responses', 'model-final-responses')}
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                try:
                    body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    answer = owner.respond(body, self.path)
                    data = ('data: ' + json.dumps(answer, ensure_ascii=False) + '\n\ndata: [DONE]\n\n').encode()
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/event-stream')
                    self.send_header('Content-Length', str(len(data)))
                    self.send_header('Connection', 'close')
                    self.end_headers()
                    self.wfile.write(data)
                except Exception as exc:
                    owner.record('model-requests', {'kind': 'server_error', 'error': repr(exc)})
                    self.send_error(500, str(exc))
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def record(self, stream, value):
        value = {'time': now(), **value}
        with self.lock:
            self.records.append(value)
            self.files[stream].write(json.dumps(value, ensure_ascii=False) + '\n')
            self.files[stream].flush()

    def __enter__(self):
        self.thread.start()
        return self

    @property
    def endpoint(self):
        return f'http://127.0.0.1:{self.server.server_address[1]}/v1/'

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        for stream in self.files.values():
            stream.close()

    def respond(self, body, path):
        case = body.get('model', 'unknown')
        self.record('model-requests', {'kind': 'model_request', 'case_id': case, 'path': path, 'body': body})
        for message in body.get('messages', []):
            if message.get('role') == 'tool':
                key = (case, message.get('tool_call_id'), str(message.get('content')))
                if key not in self.seen_results:
                    self.seen_results.add(key)
                    entry = {'kind': 'conversation_tool_response', 'case_id': case, 'message': message}
                    self.record('conversation-tool-responses', entry)
                    text = str(message.get('content', ''))
                    if any(x in text.lower() for x in ('suppressed', 'denied', 'blocked', 'unknown tool')):
                        self.record('model-visible-rejections', {**entry, 'kind': 'controller_rejection'})
        text = '\n'.join(str(m.get('content', '')) for m in body.get('messages', []))
        synthesis = 'Verified tool executions recorded by dispatcher:' in text
        if synthesis:
            count = re.findall(r'Verified tool executions recorded by dispatcher:\s*(\d+)', text)
            count = int(count[-1]) if count else -1
            if case in ('GA-06', 'CLAIM_MIXED', 'CLAIM_FAILED', 'GUI_ALLOW'):
                answer = 'The update_regression_record tool executed successfully. UPDATED_FIXTURE_ONLY=true. execution_count=1.'
            elif case == 'CLAIM_HONEST_DENIAL':
                answer = 'The update was denied; no operation executed. execution_count=0.'
            elif case == 'VERTICAL':
                fact = 'REGRESSION_FACT=42' if 'REGRESSION_FACT=42' in text else 'MISSING_EVIDENCE'
                answer = f'Verified result: {fact}; execution_count={count}.'
            else:
                answer = f'Investigation {case} completed. Verified execution_count={count}.'
            self.record('model-final-responses', {'kind': 'model_final_response', 'case_id': case,
                        'content': answer, 'input_contains_rag_footer': 'returnedCount=' in text and 'nextOffset=' in text})
            return self.text_chunk(answer)
        if body.get('tools'):
            round_no = self.rounds.get(case, 0)
            self.rounds[case] = round_no + 1
            calls = self.proposals(case, round_no)
            if calls:
                deltas = []
                for i, (name, arguments) in enumerate(calls):
                    call_id = f'{case}_{round_no}_{i}'
                    self.record('model-proposals', {'kind': 'model_proposal', 'case_id': case,
                                'model_call_id': call_id, 'tool': name, 'arguments': arguments})
                    deltas.append({'index': i, 'id': call_id, 'type': 'function',
                                   'function': {'name': name, 'arguments': json.dumps(arguments)}})
                return {'choices': [{'index': 0, 'delta': {'role': 'assistant', 'tool_calls': deltas}, 'finish_reason': 'tool_calls'}]}
            return self.text_chunk('Finding: the returned tool evidence has been recorded. Investigation complete.')
        return self.text_chunk('**Assessment:** Evidence collected.\n**Plan Updates:**\n- ADD: None\n**Decision:** READY\n**Reason:** Complete.')

    @staticmethod
    def text_chunk(text):
        return {'choices': [{'index': 0, 'delta': {'role': 'assistant', 'content': text}, 'finish_reason': 'stop'}]}

    @staticmethod
    def proposals(case, round_no):
        if round_no == 1 and case in ('GUI_BUDGET','GUI_ASYNC','GUI_ALIAS_BUDGET','GUI_STATIC_DUP'):
            return {
                'GUI_BUDGET': [('ga_get_document_page', {'filename':'MC68332UM.pdf','page':256,'scope':'all','offset':700,'max_chars':700})],
                'GUI_ASYNC': [('get_task_status', {'task_id':'task-1'})],
                'GUI_ALIAS_BUDGET': [('get_gui_fact_alias', {'key':'b'})],
                'GUI_STATIC_DUP': [('get_gui_fact_alias', {'key':'a'})],
            }[case]
        if round_no == 1 and case in ('GA-05', 'GA-08', 'POLL_NAMESPACED', 'POLICY_POLL_BUDGET'):
            return [('get_regression_fact', {'key': 'alpha'})] if case == 'GA-05' else [('fixture.get_task_status' if case == 'POLL_NAMESPACED' else 'get_task_status', {'task_id': 'task-1'})]
        if round_no:
            return []
        return {
            'GUI_ALLOW': [('ga_search_documents', {'query':'Framing Error','scope':'all'})],
            'GUI_BUDGET': [('ga_get_document_page', {'filename':'MC68332UM.pdf','page':256,'scope':'all','offset':0,'max_chars':700})],
            'GUI_ASYNC': [('get_task_status', {'task_id':'task-1'})],
            'GUI_ALIAS_BUDGET': [('get_gui_fact', {'key':'a'})],
            'GUI_STATIC_DUP': [('get_gui_fact', {'key':'a'})],
            'VERTICAL': [('get_regression_fact', {'key': 'alpha'})],
            'ERROR_RETURN': [('get_regression_error', {'key': 'return'})],
            'ERROR_THROW': [('get_regression_error', {'key': 'throw'})],
            'ERROR_FUTURE': [('get_regression_error', {'key': 'future'})],
            'ERROR_UNKNOWN': [('missing_regression_tool', {})],
            'POLICY_EXPLICIT_GLOBAL': [('get_regression_fact', {'key': 'alpha'}), ('get_regression_other', {'key': 'alpha'})],
            'POLICY_EXPLICIT_READONLY': [('update_regression_record', {'key': 'alpha'})],
            'POLICY_AMBIGUOUS_TEXT': [('get_regression_fact', {'key': 'alpha'}), ('get_regression_other', {'key': 'alpha'})],
            'POLICY_PROMPT_ONLY': [('get_regression_other', {'key': 'alpha'})],
            'POLICY_UNRESTRICTED': [('get_regression_fact', {'key': 'alpha'}), ('get_regression_other', {'key': 'alpha'})],
            'POLICY_EMPTY': [('get_regression_fact', {'key': 'alpha'})],
            'POLICY_ZERO': [('get_regression_fact', {'key': 'alpha'}), ('get_regression_other', {'key': 'alpha'})],
            'POLICY_GLOBAL': [('get_regression_fact', {'key': 'alpha'}), ('get_regression_other', {'key': 'alpha'})],
            'POLICY_POLL_BUDGET': [('get_task_status', {'task_id': 'task-1'})],
            'GA-04': [('get_regression_other', {'key': 'alpha'})],
            'GA-05': [('get_regression_fact', {'key': 'alpha'})],
            'GA-06': [('update_regression_record', {'key': 'alpha'})],
            'CLAIM_HONEST_DENIAL': [('update_regression_record', {'key': 'alpha'})],
            'CLAIM_MIXED': [('get_regression_fact', {'key': 'alpha'}), ('update_regression_record', {'key': 'alpha'})],
            'CLAIM_FAILED': [('get_regression_error', {'key': 'return'})],
            'GA-07': [('get_regression_fact', {'key': 'alpha'}), ('get_regression_other', {'key': 'alpha'}), ('get_regression_fact', {'key': 'beta'})],
            'GA-08': [('get_task_status', {'task_id': 'task-1'})],
            'POLL_NAMESPACED': [('fixture.get_task_status', {'task_id': 'task-1'})],
            'GA-09': [('ga_search_documents', {'query': '"Framing Error"', 'filename': 'MC68332UM.pdf', 'scope': 'all', 'max_results': 4})],
        }.get(case, [])
