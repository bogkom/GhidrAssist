# Optional real local LLM regression

The existing deterministic provider remains the reproducible controller test
baseline. The workspace runner additionally supports `--real-llm` and
`--llm-repeats N` (1..20). Example targeted invocation:

```
python3 scripts/run_suite.py --allow-partial --without-mcp --real-llm --llm-repeats 2 --test-path tests/test_real_llm.py
```

This loads an actually configured free local LMSTUDIO/OLLAMA provider, or a
loaded local LM Studio model verified through its native model endpoint. It
never falls back to an OAuth/paid API, an arbitrary OpenAI proxy or deterministic
model responses. Only loopback HTTP is relayed, environment proxies and redirects
are disabled, authorization headers are not logged, and temporary provider
configuration is removed with the isolated workspace. Original preferences,
project and RAG index are read/copy sources only.

The Java probe executes the real provider, ReActOrchestrator and ToolRegistry.
Prepared GA-04..GA-09 scenarios retain deterministic fixture backends where they
need a known fact, denial or changing asynchronous state; model choices are real.
The document-page scenario executes the actual native `ga_get_document_page`
against the copied index. No production code is adjusted for an individual model.

`tests/integration/real_llm.py` is a transparent transport recorder, not a model.
It retains upstream response bodies, proposals and model-visible tool responses.
The workspace adapter combines these with actual journal states, rejections,
raw final model declarations and delivered verified answers. Classification has
separate controller, model, tool and infrastructure fields. Structured final
`execution_count` declarations are checked against actual starts; arbitrary
semantic accuracy is not presented as automatically verified. Native errors from
invalid model arguments differ from valid requests failing in the tool.

Every repeat has a separate case identity, while task instructions remain the
same. Results and per-case outcome distributions are written to
`real-llm/results.json`, `real-llm/model-transport.jsonl` and
`real-llm/stability.json` in the current immutable evidence directory. With no
usable free local model, cases are BLOCKED, executed count is zero and stability
is null (not measured). Transport unit tests are reported separately and never
counted as real-model PASS results.
