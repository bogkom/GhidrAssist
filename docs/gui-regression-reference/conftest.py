import os
import socket
import pytest

@pytest.fixture(scope="session")
def mcp_url():
    return os.getenv("MCP_URL", "http://127.0.0.1:8080/mcp")

@pytest.fixture(scope="session")
def mcp_available(mcp_url):
    from urllib.parse import urlparse
    u = urlparse(mcp_url)
    try:
        with socket.create_connection((u.hostname, u.port or 80), timeout=1):
            return True
    except OSError:
        return False

@pytest.fixture(scope="session")
def mcp_session(mcp_url, mcp_available):
    if not mcp_available:
        pytest.skip(f"MCP endpoint not listening: {mcp_url}")
    pytest.importorskip("mcp")
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
    import asyncio

    class Session:
        async def call(self, fn):
            async with streamablehttp_client(mcp_url) as (read, write, _):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    return await fn(client)
    return Session()

@pytest.fixture
def evidence_check(request):
    """Record each executed assertion and its exact values in the JSON report."""
    def check(label, received, expected, *, contains=False, raw=None):
        metadata = getattr(request.node, 'regression_metadata', {})
        assertions = metadata.setdefault('assertions', [])
        passed = expected in received if contains else received == expected
        entry = {'label': label, 'expected_value': expected, 'received_value': received, 'passed': passed}
        if raw:
            metadata['raw_evidence'] = raw
        assertions.append(entry)
        if not passed:
            metadata.update(expected_value=expected, received_value=received)
        request.node.regression_metadata = metadata
        assert passed, f'{label}: expected {expected!r}; received {received!r}'
    return check

@pytest.hookimpl(optionalhook=True)
def pytest_json_runtest_metadata(item, call):
    return getattr(item, 'regression_metadata', {})


def pytest_ignore_collect(collection_path, config):
    # The optional real model group is collected only when explicitly requested.
    if collection_path.name == 'test_real_llm.py' and os.getenv('GHIDRASSIST_REAL_LLM') != '1':
        return True
