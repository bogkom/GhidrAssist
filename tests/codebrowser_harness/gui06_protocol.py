"""GUI-06 strict structural handshake checks; not a native GUI acceptance gate."""
import hashlib
import json
import os
import re
import stat

RUN_ID=re.compile(r"[a-f0-9]{32}\Z")
XID=re.compile(r"0x[0-9a-f]{1,16}\Z")
CASE="synthetic-codebrowser-001"
PROGRAM="synthetic-mmio.bin"
ADDRESS="0x00000020"
FUNCTION="FUN_00000020"
CLASS="CodeBrowserMmioMain.CodeBrowserMmioMain"
TITLE="GhidrAssist isolated CodeBrowser MMIO: CodeBrowserFixture:/synthetic-mmio.bin"


def require(ok,what):
    if not ok:
        raise ValueError("BLOCKED_GUI06_"+what)


def reserve_run(root,run_id):
    require(isinstance(run_id,str) and RUN_ID.fullmatch(run_id),"INVALID_RUN_ID")
    evidence=root/"evidence"
    target=evidence/("pilot-ghidra-"+run_id)
    other=evidence/("pilot-x11-"+run_id)
    require(not target.exists() and not other.exists(),
            "REUSED_RUN_ID")
    target.mkdir(mode=0o700,exist_ok=False)
    return target



def read_private_capture(evidence, run_id):
    """Read original bridge bytes once using Linux dir-fd/no-follow checks.

    A validated receipt and the SHA pins must refer to the same bytes.
    This is local file integrity, NOT independent GUI/source provenance.
    """
    require(isinstance(run_id, str) and RUN_ID.fullmatch(run_id),
            "INVALID_RUN_ID")
    flags=os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    directory_flags=flags | os.O_DIRECTORY
    try:
        root_fd=os.open(evidence, directory_flags)
    except OSError as exc:
        raise ValueError("BLOCKED_GUI06_UNSAFE_EVIDENCE_ROOT") from exc
    try:
        parent=os.fstat(root_fd)
        require(stat.S_ISDIR(parent.st_mode) and
                parent.st_uid==os.getuid() and
                stat.S_IMODE(parent.st_mode)==0o700,
                "UNSAFE_EVIDENCE_ROOT")
        try:
            bridge_fd=os.open("pilot-x11-"+run_id, directory_flags,
                              dir_fd=root_fd)
        except OSError as exc:
            raise ValueError("BLOCKED_GUI06_UNSAFE_BRIDGE_DIR") from exc
        try:
            metadata=os.fstat(bridge_fd)
            require(stat.S_ISDIR(metadata.st_mode) and
                    metadata.st_uid==os.getuid() and
                    stat.S_IMODE(metadata.st_mode)==0o700,
                    "UNSAFE_BRIDGE_DIR")

            def read_one(filename, limit):
                try:
                    fd=os.open(filename, flags | os.O_NONBLOCK,
                               dir_fd=bridge_fd)
                except OSError as exc:
                    raise ValueError("BLOCKED_GUI06_UNSAFE_BRIDGE_FILE") from exc
                try:
                    item=os.fstat(fd)
                    require(stat.S_ISREG(item.st_mode) and item.st_nlink==1 and
                            item.st_uid==os.getuid() and
                            stat.S_IMODE(item.st_mode)==0o600 and
                            0<item.st_size<=limit,
                            "UNSAFE_BRIDGE_FILE")
                    with os.fdopen(fd, "rb", closefd=False) as stream:
                        raw=stream.read(limit+1)
                    require(len(raw)==item.st_size, "CHANGED_BRIDGE_FILE")
                    return raw
                finally:
                    os.close(fd)

            report_raw=read_one("bridge-capture.json",128*1024)
            image_raw=read_one("ghidra-window.png",64*1024*1024)
        finally:
            os.close(bridge_fd)
    finally:
        os.close(root_fd)

    def unique_object(pairs):
        data={}
        for key,value in pairs:
            require(key not in data, "DUPLICATE_BRIDGE_JSON_KEY")
            data[key]=value
        return data

    try:
        report=json.loads(report_raw.decode("utf-8"),
                          object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("BLOCKED_GUI06_INVALID_BRIDGE_JSON") from exc
    require(isinstance(report,dict), "INVALID_BRIDGE_JSON")
    return report, report_raw, image_raw


def verify(ready,receipt,bridge,host_png,run_id):
    require(isinstance(run_id,str) and RUN_ID.fullmatch(run_id),
            "INVALID_RUN_ID")
    require(all(isinstance(o,dict) for o in (ready,receipt,bridge)),
            "MISSING_REPORT")
    expect={
        "run_id":run_id,"case_id":CASE,
        "window_id":ready.get("window_id"),
        "window_title":TITLE,"program":PROGRAM,
        "address":ADDRESS,"function":FUNCTION,
    }
    require(XID.fullmatch(str(expect["window_id"])) is not None,
            "INVALID_XID")
    for name in ("run_id","case_id","window_id","window_title",
                 "program","address","function"):
        require(ready.get(name)==expect[name] and
                receipt.get(name)==expect[name],
                "GHIDRA_"+name.upper()+"_MISMATCH")
    require(ready.get("window_class")==CLASS and
            receipt.get("window_class")==CLASS,
            "WINDOW_CLASS_MISMATCH")
    require(ready.get("decompiler_function")==FUNCTION and
            receipt.get("decompiler_function")==FUNCTION,
            "DECOMPILER_MISMATCH")
    require(receipt.get("listing_verified") is True and
            receipt.get("decompiler_verified") is True and
            receipt.get("inprocess_consistency_verified") is True,
            "UNVERIFIED_GHIDRA_STATE")
    for key,value in {
        "run_id":run_id,"case_id":CASE,"window_id":expect["window_id"],
        "window_title":TITLE,"wm_class":CLASS,
        "result":"HOST_SYNTHETIC_X11_CAPTURED_PROVENANCE_PENDING",
        "applied":True,"identity_before_after_capture":True,
        "source":"host-owned-readonly-x11"
    }.items():
        require(type(bridge.get(key)) is type(value) and
                bridge[key]==value,"BRIDGE_"+key.upper()+"_MISMATCH")
    for field in ("visual_readback_verified","native_nonce_ack",
                  "supervisor_ack","formal_gui_pass",
                  "trusted_ghidra_provenance_verified",
                  "same_run_semantics_verified"):
        require(bridge.get(field) is False and receipt.get(field) is False,
                "UNAUTHORIZED_"+field.upper())
    require(receipt.get("pre_capture",{}).get("program")==PROGRAM and
            receipt.get("post_capture",{}).get("program")==PROGRAM and
            receipt.get("pre_capture",{}).get("address")==ADDRESS and
            receipt.get("post_capture",{}).get("address")==ADDRESS and
            receipt.get("pre_capture",{}).get("function")==FUNCTION and
            receipt.get("post_capture",{}).get("function")==FUNCTION and
            receipt.get("pre_capture",{}).get("decompiler_function")==FUNCTION and
            receipt.get("post_capture",{}).get("decompiler_function")==FUNCTION,
            "STALE_GHIDRA_STATE")
    times=[receipt.get("pre_capture_epoch_ms"),
           bridge.get("capture_start_epoch_ms"),
           bridge.get("capture_end_epoch_ms"),
           receipt.get("post_capture_epoch_ms")]
    require(all(type(x) is int and x>0 for x in times) and
            times==sorted(times) and times[2]-times[1]<=60000,
            "BRIDGE_TIME_WINDOW")
    robot_start=receipt.get("capture_start_epoch_ms")
    robot_end=receipt.get("capture_end_epoch_ms")
    require(type(ready.get("pre_capture_epoch_ms")) is int and
            ready["pre_capture_epoch_ms"]==times[0] and
            receipt.get("pre_capture",{}).get("observed_epoch_ms")==times[0] and
            receipt.get("post_capture",{}).get("observed_epoch_ms")==times[3] and
            type(robot_start) is int and type(robot_end) is int and
            times[2]<=robot_start<=robot_end<=times[3],
            "GHIDRA_CAPTURE_SEQUENCE")
    require(isinstance(host_png,bytes) and
            4096<len(host_png)<=64*1024*1024 and
            hashlib.sha256(host_png).hexdigest()==
            bridge.get("captured_screenshot_sha256"),
            "BRIDGE_PNG_HASH")
    # Exact original screenshot parsing and CRC validation remain the
    # Supervisor PR90 responsibility, and are also checked in local CI.
    from assertion_audit import png_info
    w,h=png_info(host_png)
    require(w==bridge.get("screenshot_width") and
            h==bridge.get("screenshot_height"),"BRIDGE_PNG_DIMENSIONS")
    return {"structurally_correlated":True,
            "trusted_ghidra_provenance_verified":False,
            "same_run_semantics_verified":False,
            "visual_readback_verified":False,
            "supervisor_ack":False,"formal_gui_pass":False}
