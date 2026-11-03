# Codex Wyse — GA-18 test-only, one run

You are a TESTER ONLY for bogkom/GhidrAssist, not a developer.
Do not change production code, GitHub, Ghidra profiles, firmware, or Supervisor.
Do not run a new Goal, nested Codex session, or Computer Use.
Use only the isolated synthetic Ghidra session already open in
$HOME/Projekty/Codex/ga-automation-test/session.json.
Execute exactly one Python test suite from this workspace:
python3 "$HOME/Projekty/Codex/ga-automation-test/ga18-wyse-api-smoke.py" --source-sha "$GA18_TEST_SOURCE_SHA"
If GA18_TEST_SOURCE_SHA is unavailable, read source_sha.txt in the same workspace.
Do not echo or copy the session JSON, bearer token, any firmware, or private logs.
The runner writes its own local 0600 JSON report to reports/. Do not upload it anywhere.
Read the report's classification and per-check results, give a short Polish final
message stating PASS/FAIL, number of checks, report path, and failures if any.
Do not claim formal Supervisor PASS.
