"""Strict self-reported Ghidra CodeBrowser + X11 PNG receipt verifier.

This checks source/temporal *consistency*, never trusted in-process provenance,
independent image semantics, native nonce/ACK, or formal GUI acceptance.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib

KIND="ga18-codebrowser-listing-assertions"
SOURCE="ghidra-inprocess-codebrowser"
HEX=re.compile(r"[0-9a-f]{64}\Z")
ID=re.compile(r"0x[0-9a-fA-F]{1,16}\Z")
TOKEN=re.compile(r"[a-zA-Z0-9_-]{6,64}\Z")
NEEDED=(
    "schema","kind","case_id","run_id","source_kind","window_id",
    "window_class","window_title","program","address","function",
    "decompiler_function","listing_verified","decompiler_verified",
    "image_sha256","image_width","image_height","pre_capture",
    "post_capture","pre_capture_epoch_ms","capture_start_epoch_ms",
    "capture_end_epoch_ms","post_capture_epoch_ms",
    "inprocess_consistency_verified",
    "trusted_ghidra_provenance_verified","same_run_semantics_verified",
    "independent_visual_readback","visual_readback_verified",
    "supervisor_ack","native_nonce_ack","formal_gui_pass",
)


class EvidenceError(ValueError):
    pass


def need(ok, message):
    if not ok:
        raise EvidenceError(message)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def png_info(raw):
    need(len(raw)>4096 and raw.startswith(b"\x89PNG\r\n\x1a\n"),
         "original screenshot missing/invalid PNG")
    i=8
    width=height=None
    has_idat=False
    seen_end=False
    while i<len(raw):
        need(i+12<=len(raw),"truncated PNG chunk")
        n=struct.unpack_from(">I",raw,i)[0]
        tag=raw[i+4:i+8]
        need(n<=32*1024*1024 and i+12+n<=len(raw),"oversized/truncated PNG")
        value=raw[i+8:i+8+n]
        crc=struct.unpack_from(">I",raw,i+8+n)[0]
        need(zlib.crc32(tag+value)&0xffffffff==crc,"PNG CRC mismatch")
        if width is None:
            need(tag==b"IHDR" and n==13,"invalid IHDR")
            width,height=struct.unpack_from(">II",value)
            need(640<=width<=8192 and 400<=height<=8192,
                 "PNG dimensions outside isolated CodeBrowser limits")
        if tag==b"IDAT":
            has_idat=True
        if tag==b"IEND":
            need(n==0 and i+12==len(raw),"invalid PNG trailing data")
            seen_end=True
        i+=12+n
    need(seen_end and has_idat,"missing PNG IDAT/IEND")
    return width,height


def validate(receipt, image, *, case_id, run_id,
             program="synthetic-mmio.bin", address="0x00000020",
             function="FUN_00000020"):
    need(isinstance(receipt,dict),"missing receipt object")
    need(all(key in receipt for key in NEEDED),"incomplete assertion report")
    need(receipt["schema"]==1 and receipt["kind"]==KIND and
         receipt["source_kind"]==SOURCE,"wrong source/schema")
    need(receipt["case_id"]==case_id and TOKEN.fullmatch(case_id) and
         receipt["run_id"]==run_id and TOKEN.fullmatch(run_id),
         "wrong test case/run identity")
    need(receipt["program"]==program and receipt["address"]==address and
         receipt["function"]==function and
         receipt["decompiler_function"]==function,
         "wrong expected program/address/function")
    need(receipt["listing_verified"] is True and
         receipt["decompiler_verified"] is True and
         receipt["inprocess_consistency_verified"] is True,
         "missing genuine in-process assertion result")
    need(ID.fullmatch(receipt["window_id"]) is not None and
         receipt["window_class"] and
         "Ghidra" in receipt["window_class"] and
         "CodeBrowser" in receipt["window_title"],
         "invalid X11 window identity/class/full title")
    for moment in ("pre_capture","post_capture"):
        snap=receipt[moment]
        need(isinstance(snap,dict) and
             snap.get("program")==program and
             snap.get("address")==address and
             snap.get("function")==function and
             snap.get("decompiler_function")==function and
             type(snap.get("observed_epoch_ms")) is int,
             "stale or incomplete Ghidra "+moment)
    timestamps=[receipt["pre_capture_epoch_ms"],
                receipt["capture_start_epoch_ms"],
                receipt["capture_end_epoch_ms"],
                receipt["post_capture_epoch_ms"]]
    need(all(type(x) is int and x>0 for x in timestamps) and
         timestamps==sorted(timestamps) and
         timestamps[0]==receipt["pre_capture"]["observed_epoch_ms"] and
         timestamps[-1]==receipt["post_capture"]["observed_epoch_ms"],
         "mismatched pre/capture/post time ordering")
    need(all(receipt[x] is False for x in (
        "trusted_ghidra_provenance_verified","same_run_semantics_verified",
        "independent_visual_readback","visual_readback_verified",
        "supervisor_ack","native_nonce_ack","formal_gui_pass")),
        "unearned GUI provenance/readback/ACK/PASS assertion")
    need(isinstance(image,bytes),"original PNG must be raw bytes")
    width,height=png_info(image)
    need(receipt["image_width"]==width and
         receipt["image_height"]==height,"screenshot dimensions mismatch")
    need(isinstance(receipt["image_sha256"],str) and
         HEX.fullmatch(receipt["image_sha256"]) and
         sha256(image)==receipt["image_sha256"],
         "screenshot SHA-256 mismatch")
    return {
        "structural_evidence_consistent":True,
        "trusted_ghidra_provenance_verified":False,
        "same_run_semantics_verified":False,
        "visual_readback_verified":False,
        "supervisor_ack":False,
        "formal_gui_pass":False,
    }


def validate_files(report_path,image_path,**expected):
    report=Path(report_path)
    png=Path(image_path)
    need(report.is_file() and png.is_file() and
         not report.is_symlink() and not png.is_symlink(),
         "report/PNG must be regular non-symlink files")
    need(report.stat().st_size<128*1024 and png.stat().st_size<64*1024*1024,
         "oversized private evidence input")
    return validate(json.loads(report.read_text(encoding="utf-8")),
                    png.read_bytes(),**expected)
