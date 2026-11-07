#!/usr/bin/env python3
"""One genuine CodeBrowser Program -> ReAct -> 127.0.0.1 JSON-RPC -> CLI fixture.

The only scripted component is the model response, which calls the real
read-only Ghidra tool through ReAct's ToolRegistry. No real AI/model or MCU.
The authorization receipt lives outside the artifact directory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT=Path(__file__).resolve().parents[2]
AGENT=ROOT/"tools"/"ghidrassist-agent"


def wait_path(path,seconds):
    stop=time.monotonic()+seconds
    while time.monotonic()<stop:
        if path.is_file():
            return path
        time.sleep(0.05)
    raise TimeoutError("Actual ReAct did not reach bounded stage: "+path.name)


def command(session,*args,success=True):
    cmd=[sys.executable,str(AGENT),"--session",str(session),*map(str,args)]
    result=subprocess.run(cmd,capture_output=True,text=True,timeout=40)
    if success and result.returncode!=0:
        raise AssertionError("Production CLI rejected expected safe operation: "+
                             " ".join(map(str,args))+" "+result.stderr[:600])
    if not success:
        if result.returncode==0:
            raise AssertionError("Stale or unbounded Agentic RPC was accepted: "+str(args))
        return result.stderr[:300]
    return json.loads(result.stdout)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--session",required=True,type=Path)
    ap.add_argument("--output",required=True,type=Path)
    ap.add_argument("--scenario",choices=("normal","cancel","switch"),
                    default="normal")
    args=ap.parse_args()
    session=json.loads(args.session.read_text())
    out=args.output
    wait_path(out/"ga15-react-running",65)
    live=command(args.session,"agentic-findings","--offset",0,"--limit",1)
    r=live["agentic"]
    assert live["read_only"] is True and live["program"]=="synthetic-mmio.bin"
    assert r["state"]=="RUNNING" and not r["complete"]
    assert r["findings"]["retainedCount"]==0
    assert r["findings"]["rows"]==[] and not r["findings"]["sourceIncomplete"]
    assert len(r["run"])>=32 and r["programRevision"]>=0
    assert len(r["importSha256"])==64

    # Bearer token enforcement by the *actual* production loopback server.
    payload=json.dumps({"method":"agentic.findings.page","params":{}}).encode()
    req=Request("http://127.0.0.1:%d/rpc"%session["port"],data=payload,
                headers={"Authorization":"Bearer definitely-wrong-token",
                         "Content-Type":"application/json"},method="POST")
    try:
        with urlopen(req,timeout=10):
            raise AssertionError("Untrusted HTTP client got ReAct findings")
    except HTTPError as exc:
        assert exc.code==401,exc.code
    # Never permit an unknown run or client-supplied revision for page stitching.
    command(args.session,"agentic-findings","--offset",1,"--limit",1,
            success=False)
    command(args.session,"agentic-findings","--offset",1,"--limit",1,
            "--expected-run","wrong-run",
            "--expected-revision",r["programRevision"],
            "--expected-findings-revision",r["findings"]["revision"],
            success=False)

    if args.scenario!="normal":
        # A real running ReAct native tool has finished; the scripted LLM
        # callback is deliberately withheld. Cancel directly or use the
        # live Swing ProgramManager A→B→A switching path.
        (out/"ga15-react-action").write_text(args.scenario)
        wait_path(out/"ga15-react-action-done",60)
        if (out/"ga15-react-action-error").exists():
            raise AssertionError((out/"ga15-react-action-error").read_text())
        result=json.loads(wait_path(out/"ga15-react-result.json",60).read_text())
        assert result["scenario"]==args.scenario and result["status"]=="CANCELLED",result
        assert result["tool_succeeded"] and result["tool_calls"]==1,result
        assert result["revision_unchanged"] and result["real_react_orchestrator"],result
        if args.scenario=="cancel":
            state=command(args.session,"agentic-findings","--offset",0,"--limit",1)
            bound=state["agentic"]
            assert bound["run"]==r["run"] and bound["state"]=="CANCELLED"
            assert not bound["complete"] and bound["findings"]["retainedCount"]==0
            assert bound["findings"]["revision"]==r["findings"]["revision"]
            # A cancelled investigation may be saved as INCOMPLETE for
            # later inspection, but never reopened as successful source.
            canceled=out/"ga15-react-cancelled-evidence.json"
            saved=command(args.session,"agentic-checkpoint","--limit",1,
                          "--output",canceled)
            assert saved["complete"] is False and saved["retained_count"]==0
            offline=command(out/"no-live-session.json","agentic-read",
                            "--input",canceled,"--offset",0,"--limit",1)
            assert not offline["source_complete"] and offline["rows"]==[]
        else:
            # Program B has no Agentic evidence and must not see A's cache.
            active=command(args.session,"status")
            assert active["program"]=="guard-other.bin",active
            command(args.session,"agentic-findings","--offset",0,"--limit",1,
                    success=False)
            (out/"ga15-react-return").write_text("return-to-first-Program")
            wait_path(out/"ga15-react-returned",60)
            active=command(args.session,"status")
            assert active["program"]=="synthetic-mmio.bin",active
            command(args.session,"agentic-findings","--offset",0,"--limit",1,
                    success=False)
            # Old run MUST NOT be recoverable by private checkpoint either.
            command(args.session,"agentic-checkpoint","--limit",1,
                    "--output",out/"ga15-switch-stale-evidence.json",success=False)
            assert not (out/"ga15-switch-stale-evidence.json").exists()
        # Deliver the provider's **delayed** model callback after the
        # result is terminal. It must not modify UI or resurrect source.
        (out/"ga15-react-release").write_text("send-delayed-model-callback")
        late=json.loads(wait_path(out/"ga15-react-late-delivered",60).read_text())
        assert (late["provider_cancel_calls"]==1 and
                late["synchronous_cancel_error_callbacks"]==1 and
                late["late_ui_updates"]==0),late
        if args.scenario=="cancel":
            state=command(args.session,"agentic-findings","--offset",0,"--limit",1)
            bound=state["agentic"]
            assert bound["state"]=="CANCELLED" and bound["run"]==r["run"]
            assert bound["findings"]["retainedCount"]==0
            assert bound["findings"]["revision"]==r["findings"]["revision"]
        else:
            command(args.session,"agentic-findings","--offset",0,"--limit",1,
                    success=False)
        receipt={
            "schema":1,"synthetic_only":True,"scenario":args.scenario,
            "scenario_passed":True,"actual_ghidra_codebrowser":True,
            "real_react_execution":True,"real_http_bearer_401":True,
            "real_cli_in_progress":True,"real_cli_completed":True,
            "real_ghidra_native_tool":True,"tool_calls":result["tool_calls"],
            "cancellation_receipt":"CANCELLED",
            "cancelled_after_real_tool":True,
            "program_switch_invalidation":args.scenario=="switch",
            "cancel_retained_snapshot":args.scenario=="cancel",
            "synchronous_cancel_error_preserves_CANCELLED":True,
            "delayed_callback_no_ui_update":True,
            "delayed_callback_no_resurrection":True,
            "source_revision_unchanged":True,
            "model_or_oauth_used":False,"runtime_execution_verified":False,
        }
        (out/"ga15-react-e2e.json").write_text(
            json.dumps(receipt,indent=2,sort_keys=True)+"\n")
        print("GA-15/18 REAL REACT CANCEL/SWITCH/DELAYED CALLBACK E2E PASS")
        return

    (out/"ga15-react-release").write_text("external-CLI-verified-running")
    result=json.loads(wait_path(out/"ga15-react-result.json",60).read_text())
    assert result["status"]=="SUCCESS" and result["tool_calls"]==1,result
    assert result["tool_succeeded"] is True and result["revision_unchanged"] is True,result
    assert result["real_react_orchestrator"] and result["scripted_model_no_network"],result
    assert result["findings"]>=2,result

    first=command(args.session,"agentic-findings","--offset",0,"--limit",1)
    evidence=first["agentic"]
    assert evidence["state"]=="SUCCESS" and not evidence["complete"]
    assert evidence["findings"]["retainedCount"]>=2
    assert evidence["findings"]["hasMore"] and evidence["run"]==r["run"]
    assert evidence["findings"]["revision"]!=r["findings"]["revision"]
    second=command(args.session,"agentic-findings","--offset",1,"--limit",1,
                   "--expected-run",evidence["run"],
                   "--expected-revision",evidence["programRevision"],
                   "--expected-findings-revision",evidence["findings"]["revision"])
    assert second["agentic"]["findings"]["rows"],second
    assert second["agentic"]["run"]==evidence["run"]
    command(args.session,"agentic-findings","--offset",1,"--limit",1,
            "--expected-run",evidence["run"],
            "--expected-revision",evidence["programRevision"]+1,
            "--expected-findings-revision",evidence["findings"]["revision"],
            success=False)
    command(args.session,"agentic-findings","--offset",1,"--limit",1,
            "--expected-run",evidence["run"],
            "--expected-revision",evidence["programRevision"],
            "--expected-findings-revision",r["findings"]["revision"],
            success=False)
    command(args.session,"agentic-findings","--offset",0,"--limit",101,
            success=False)

    # The CLI must fetch *all* real ReAct pages from HTTP and create one
    # private no-overwrite checkpoint, then verify/read it with no session.
    checkpoint=out/"ga15-react-local-evidence.json"
    saved=command(args.session,"agentic-checkpoint","--limit",1,
                  "--output",checkpoint)
    assert saved["complete"] is True and saved["retained_count"]>=2,saved
    assert checkpoint.stat().st_mode & 0o777==0o600
    command(args.session,"agentic-checkpoint","--limit",1,
            "--output",checkpoint,success=False)
    offline_session=out/"nonexistent-agentic-session.json"
    verified=command(offline_session,"agentic-verify","--input",checkpoint)
    offline=command(offline_session,"agentic-read","--input",checkpoint,
                    "--offset",1,"--limit",1)
    assert verified["verified"] and verified["complete"]
    assert offline["offline"] and offline["read_only"] and offline["rows"]
    assert offline["run"]==evidence["run"]
    digest=hashlib.sha256(json.dumps(
        json.loads(checkpoint.read_text())["payload"],
        ensure_ascii=False,sort_keys=True,separators=(",",":")).encode()).hexdigest()
    assert verified["payload_sha256"]==saved["payload_sha256"]==digest

    # Production CLI preflight must compare the entire REAL ReAct evidence
    # through authenticated Ghidra JSON-RPC, never re-execute model/tools.
    checked=command(args.session,"agentic-resume-check","--input",checkpoint)
    assert checked["identity_matches"] and checked["evidence_matches"],checked
    assert checked["source_complete"] and checked["read_only"],checked
    assert checked["next_action"]=="NEW_REVIEW_REQUIRED",checked
    assert checked["resumable_ai_session"] is False,checked
    assert checked["tool_execution_authorized"] is False,checked
    assert checked["apply_authorized"] is False,checked
    # A valid SHA-256 checksum is not evidence that the local content still
    # matches live Program evidence: rehash a forged row and reject.
    forged=out/"ga15-forged-checkpoint.json"
    altered=json.loads(checkpoint.read_text())
    altered["payload"]["rows"][0]["fact"]="forged synthetic evidence"
    canonical=json.dumps(altered["payload"],ensure_ascii=False,
                         sort_keys=True,separators=(",",":")).encode()
    altered["payload_sha256"]=hashlib.sha256(canonical).hexdigest()
    forged.write_text(json.dumps(altered))
    command(args.session,"agentic-resume-check","--input",forged,success=False)
    forged.unlink()
    # A replaced run token is denied even when the checkpoint's own hash
    # has been freshly recomputed by a local caller.
    stale=out/"ga15-stale-run-checkpoint.json"
    altered=json.loads(checkpoint.read_text())
    altered["payload"]["run"]="stale-independent-run"
    canonical=json.dumps(altered["payload"],ensure_ascii=False,
                         sort_keys=True,separators=(",",":")).encode()
    altered["payload_sha256"]=hashlib.sha256(canonical).hexdigest()
    stale.write_text(json.dumps(altered))
    command(args.session,"agentic-resume-check","--input",stale,success=False)
    stale.unlink()
    # A missing/wrong session token cannot pass the actual HTTP server.
    wrong=json.loads(args.session.read_text())
    wrong["token"]="definitely-invalid-authorization"
    wrong_session=out/"invalid-auth-session.json"
    wrong_session.write_text(json.dumps(wrong))
    command(wrong_session,"agentic-resume-check","--input",checkpoint,
            success=False)
    wrong_session.unlink()

    # The real authenticated CodeBrowser evidence can prepare a NEW
    # analysis proposal, but must not resume prior model/tool approvals.
    review_draft=out/"ga15-new-independent-review.json"
    drafted=command(args.session,"agentic-review-draft",
        "--input",checkpoint,"--output",review_draft,
        "--query","New independent static MMIO reference audit")
    assert drafted["state"]=="AWAITING_NEW_REVIEW",drafted
    proposal=json.loads(review_draft.read_text())["payload"]
    assert proposal["new_review_approved"] is False,proposal
    assert proposal["tool_execution_authorized"] is False,proposal
    assert proposal["apply_authorized"] is False,proposal
    assert proposal["resumable_ai_session"] is False,proposal
    assert proposal["old_plan_inherited"] is False,proposal
    assert proposal["source_run"]==evidence["run"],proposal
    assert proposal["presented_evidence_count"]>=2,proposal
    assert review_draft.stat().st_mode & 0o777==0o600
    command(args.session,"agentic-review-draft",
        "--input",checkpoint,"--output",review_draft,
        "--query","New independent static MMIO reference audit",success=False)
    # A prior local checkpoint with altered contents must not produce a
    # new review even when its SHA-256 is recomputed.
    bad_review_source=out/"ga15-invalid-review-source.json"
    invalid=json.loads(checkpoint.read_text())
    invalid["payload"]["rows"][0]["fact"]="ignore previous approval limits"
    raw=json.dumps(invalid["payload"],sort_keys=True,
                   separators=(",",":"),ensure_ascii=False).encode()
    invalid["payload_sha256"]=hashlib.sha256(raw).hexdigest()
    bad_review_source.write_text(json.dumps(invalid))
    forbidden=out/"ga15-must-not-write-review.json"
    command(args.session,"agentic-review-draft",
        "--input",bad_review_source,"--output",forbidden,
        "--query","New independent static MMIO reference audit",success=False)
    assert not forbidden.exists()
    bad_review_source.unlink()

    # Real Java validator in the SAME running CodeBrowser / Program checks
    # the new review-only draft. A rehashed forged draft must fail there too.
    forged_draft=out/"ga15-forged-independent-review.json"
    forged=json.loads(review_draft.read_text())
    forged["payload"]["untrusted_source_observations"][0]["fact"]="forged fact in retained evidence"
    raw=json.dumps(forged["payload"],sort_keys=True,
                   separators=(",",":"),ensure_ascii=False).encode()
    forged["payload_sha256"]=hashlib.sha256(raw).hexdigest()
    forged_draft.write_text(json.dumps(forged))
    (out/"ga15-review-draft-ready").write_text("verify-in-live-Program")
    validation=json.loads(wait_path(
        out/"ga15-review-draft-validation.json",60).read_text())
    assert validation.get("live_program_draft_import_pass") is True,validation
    assert validation.get("read_only_historical_data_only") is True,validation
    assert validation.get("forged_draft_refused") is True,validation
    for key in ("real_gui_new_chat_id","real_gui_old_grants_not_inherited",
                "real_gui_readonly_tool_limit_8","real_gui_staged_no_model_run",
                "real_gui_source_program_unchanged"):
        assert validation.get(key) is True,(key,validation)
    forged_draft.unlink()

    # The first real run is terminal but remains the ONLY run before the
    # NEW test-only approval. Do not mistake imported evidence for authority.
    before=command(args.session,"agentic-findings","--offset",0,"--limit",1)
    assert before["agentic"]["run"]==evidence["run"],before
    assert before["agentic"]["state"]=="SUCCESS",before
    follow=out/"ga15-independent"
    assert not (follow/"ga15-react-running").exists()
    approval={
        "explicit_test_approval":True,
        "expected_previous_run":evidence["run"],
        "approved_plan":"- [ ] Independently verify the current Listing address",
    }
    (out/"ga15-independent-review-approved.json").write_text(
        json.dumps(approval,sort_keys=True)+"\n")
    wait_path(follow/"ga15-react-running",60)
    live=command(args.session,"agentic-findings","--offset",0,"--limit",1)
    assert live["agentic"]["run"]!=evidence["run"],live
    assert live["agentic"]["state"]=="RUNNING",live
    assert live["agentic"]["programRevision"]==evidence["programRevision"],live
    command(args.session,"agentic-findings","--offset",0,"--limit",1,
            "--expected-run",evidence["run"],success=False)
    command(args.session,"agentic-resume-check","--input",checkpoint,success=False)
    (follow/"ga15-react-release").write_text("fresh-authorized-independent-tool")
    independent=json.loads(wait_path(
        out/"ga15-independent-result.json",65).read_text())
    for key in ("explicit_test_approval","different_real_react_run_id",
                "fresh_run_initially_running","fresh_policy_read_only",
                "fresh_policy_max_8","new_objective_from_gui",
                "untrusted_evidence_as_data","fresh_terminal_success",
                "real_readonly_tool_executed","new_generation_retained_findings",
                "firmware_revision_unchanged","previous_run_denied"):
        assert independent.get(key) is True,(key,independent)
    assert independent["tool_calls"]==1,independent
    assert independent["original_run"]==evidence["run"],independent
    assert independent["new_run_id"]!=evidence["run"],independent
    later=command(args.session,"agentic-findings","--offset",0,"--limit",1)
    assert later["agentic"]["state"]=="SUCCESS",later
    assert later["agentic"]["run"]==independent["new_run_id"],later
    assert later["agentic"]["programRevision"]==evidence["programRevision"],later
    command(args.session,"agentic-resume-check","--input",checkpoint,success=False)

    # A THIRD run must be started from the production Swing Approve Plan
    # button, not by the harness invoking ReActOrchestrator.analyze itself.
    prior_gui=command(args.session,"agentic-findings","--offset",0,"--limit",1)
    assert prior_gui["agentic"]["run"]==independent["new_run_id"],prior_gui
    gui_approval={
        "explicit_test_approval":True,
        "expected_previous_run":independent["new_run_id"],
        "approved_plan":"- [ ] Independently verify the current Listing address",
    }
    (out/"ga15-gui-approve-plan.json").write_text(
        json.dumps(gui_approval,sort_keys=True)+"\n")
    wait_path(out/"ga15-gui-approval"/"ga15-react-running",65)
    third_live=command(args.session,"agentic-findings","--offset",0,"--limit",1)
    assert third_live["agentic"]["run"]!=independent["new_run_id"],third_live
    assert third_live["agentic"]["state"]=="RUNNING",third_live
    command(args.session,"agentic-resume-check","--input",checkpoint,success=False)
    (out/"ga15-gui-approval"/"ga15-react-release").write_text(
        "actual-Swing-Approve-Plan-verified")
    third=json.loads(wait_path(
        out/"ga15-gui-approved-result.json",75).read_text())
    for key in ("actual_swing_approve_button","fresh_chat_approved",
                "controller_factory_injected_ci_only","new_run_on_button",
                "running_after_button","terminal_success",
                "one_real_native_readonly_tool","new_registry_evidence",
                "program_revision_unchanged","different_run_than_second"):
        assert third.get(key) is True,(key,third)
    terminal_third=command(args.session,"agentic-findings","--offset",0,"--limit",1)
    assert terminal_third["agentic"]["state"]=="SUCCESS",terminal_third
    assert terminal_third["agentic"]["run"]!=independent["new_run_id"]
    assert terminal_third["agentic"]["programRevision"]==evidence["programRevision"]

    # Corruption must be rejected by offline reader, not merely flagged.
    tampered=out/"ga15-corrupted-private.json"
    data=json.loads(checkpoint.read_text())
    data["payload"]["state"]="CANCELLED"
    tampered.write_text(json.dumps(data))
    command(offline_session,"agentic-read","--input",tampered,
            "--offset",0,"--limit",10,success=False)
    tampered.unlink()

    # Real Ghidra tool evidence is sourced from its static Listing PC.
    all_rows=json.loads(checkpoint.read_text())["payload"]["rows"]
    assert any("00000020" in (row.get("fact") or "") for row in all_rows)
    receipt={
        "schema":1,"synthetic_only":True,
        "scenario":"normal","scenario_passed":True,
        "actual_ghidra_codebrowser":True,
        "real_react_execution":True,"llm_provider":"scripted-no-network",
        "native_readonly_tool":"ga_get_current_address",
        "real_http_bearer_401":True,"real_cli_in_progress":True,
        "real_cli_completed":True,"source_program":"synthetic-mmio.bin",
        "source_revision_unchanged":result["revision_unchanged"],
        "program_revision":evidence["programRevision"],
        "stale_run_and_revision_denied":True,
        "checkpoint_no_overwrite":True,
        "offline_no_session_verify_and_read":True,
        "tampered_offline_denied":True,
        "real_cli_resume_preflight_exact_source":True,
        "real_cli_resume_preflight_forged_row_denied":True,
        "real_cli_resume_preflight_stale_run_denied":True,
        "real_cli_resume_preflight_wrong_bearer_denied":True,
        "no_resume_without_new_review":True,
        "real_cli_new_review_draft_unapproved":True,
        "real_cli_review_draft_no_overwrite":True,
        "real_cli_forged_draft_source_denied":True,
        "real_ghidra_java_review_import_validated":True,
        "real_ghidra_java_forged_draft_denied":True,
        "real_gui_new_chat_id":True,
        "real_gui_old_grants_not_inherited":True,
        "real_gui_readonly_tool_limit_8":True,
        "real_gui_staged_no_model_run":True,
        "real_gui_source_program_unchanged":True,
        "second_independent_react_after_test_review":True,
        "second_react_real_readonly_tool":True,
        "second_react_new_registry_generation":True,
        "second_react_stale_checkpoint_denied":True,
        "second_react_new_policy_readonly":True,
        "second_react_no_firmware_mutation":True,
        "third_react_via_actual_swing_approve_button":True,
        "third_react_real_tool_and_terminal_success":True,
        "third_react_different_run_and_no_program_change":True,
        "retained":len(all_rows),"tool_calls":result["tool_calls"],
        "checkpoint_sha256":digest,
        "runtime_execution_verified":False,"model_or_oauth_used":False,
        "genuine_llm_resumption_verified":False,
    }
    (out/"ga15-react-e2e.json").write_text(
        json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print("GA15/18 REAL REACT + CODEBROWSER + BEARER JSON-RPC + CLI E2E PASS")


if __name__=="__main__":
    main()
