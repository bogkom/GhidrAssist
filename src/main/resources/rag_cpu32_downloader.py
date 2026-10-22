#!/usr/bin/env python3
"""Download officially linked CPU32 PDFs for GhidrAssist RAG, optionally import NXP ZIP.

Only direct HTTPS PDF links already present in docs/rag-cpu32-manual-catalog.md
are fetched. NXP product pages/account-gated files are reported, never guessed.
No package installation, auto-indexing, overwrites or arbitrary ZIP extraction.
Python 3.9+, standard library only.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import json
import re
import sys
import urllib.parse
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

CATALOG = "https://raw.githubusercontent.com/bogkom/GhidrAssist/master/docs/rag-cpu32-manual-catalog.md"
MAX_PDF = 50 * 1024 * 1024
ALLOWED_PDF_HOSTS = frozenset(("www.nxp.com", "nxp.com"))
ALIASES = {
    "M68000PRM": ("CPU32-common", "M68000PRM.pdf"),
    "SIMRM": ("CPU32-common", "SIMRM.pdf"),
    "TPURM": ("CPU32-common", "TPURM.pdf"),
    "MC68332UM": ("MC68332", "MC68332UM.pdf"),
    "MC68332TS": ("MC68332", "MC68332TS.pdf"),
    "MC68331UM": ("MC68331", "MC68331UM.pdf"),
    "MC68331TS": ("MC68331", "MC68331TS.pdf"),
    "MC68336376UM": ("MC68336-376", "MC68336376UM.pdf"),
}
CHAPTERS = {
    "05": "SIM",
    "08": "QADC",
    "09": "QSM",
    "10": "CTM4",
    "11": "TPU",
    "12": "TPURAM",
    "13": "TOUCAN",
}
for chapter, module in CHAPTERS.items():
    ALIASES["MC68336376UM" + chapter] = (
        "MC68376-only" if chapter == "13" else "MC68336-376",
        f"MC68336_68376_{chapter}_{module}.pdf",
    )
ALIASES["MC68336376UMD"] = (
    "MC68336-376", "MC68336_68376_D_REGISTERS.pdf"
)

# Short, non-unique filenames are accepted ONLY from the specific user-selected
# MC683336_376UM_ZIP archive; never infer CPU from a short basename in isolation.
ZIP_NAMES = {
    "apdreg.pdf": "MC68336376UMD",
    "c5sim.pdf": "MC68336376UM05",
    "c8qadc.pdf": "MC68336376UM08",
    "c9qsm.pdf": "MC68336376UM09",
    "c10ctm4.pdf": "MC68336376UM10",
    "c11tpu.pdf": "MC68336376UM11",
    "c12tpu.pdf": "MC68336376UM12",
    "c13can.pdf": "MC68336376UM13",
    "c13toucan.pdf": "MC68336376UM13",
}
CATALOG_LINK = re.compile(r"\[[^\]]+\]\((https://www\.nxp\.com/[^)\s]+\.pdf)\)", re.I)


class NxpOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_PDF_HOSTS:
            raise ValueError("Blocked redirect outside NXP: " + newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def pdf_ok(data: bytes) -> bool:
    return (
        20 <= len(data) <= MAX_PDF
        and data[:5] == b"%PDF-"
        and b"%%EOF" in data[-4096:]
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def direct_catalog_urls(markdown: str) -> list[tuple[str, str]]:
    """Extract only catalog links to real PDFs, not product HTML or guessed URLs."""
    found = []
    seen = set()
    for url in CATALOG_LINK.findall(markdown):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_PDF_HOSTS:
            continue
        name = Path(urllib.parse.unquote(parsed.path)).name
        if not name.lower().endswith(".pdf"):
            continue
        doc_id = name[:-4].upper()
        if doc_id in ALIASES and doc_id not in seen:
            found.append((doc_id, url))
            seen.add(doc_id)
    return found


def read_catalog(location: str) -> str:
    if location.startswith("https://"):
        parsed = urllib.parse.urlparse(location)
        if parsed.hostname != "raw.githubusercontent.com" or parsed.path != (
            "/bogkom/GhidrAssist/master/docs/rag-cpu32-manual-catalog.md"
        ):
            raise ValueError("Catalog URL must be the official GhidrAssist master catalog")
        with urllib.request.urlopen(location, timeout=30) as response:
            return response.read(1_000_001).decode("utf-8")
    return Path(location).expanduser().read_text(encoding="utf-8")


def fetch_pdf(url: str) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_PDF_HOSTS:
        raise ValueError("Only official HTTPS NXP PDF links are allowed")
    request = urllib.request.Request(
        url, headers={"User-Agent": "GhidrAssist-RAG-Documentation/1.0"}
    )
    with urllib.request.build_opener(NxpOnlyRedirect()).open(
        request, timeout=40
    ) as response:
        data = response.read(MAX_PDF + 1)
    if not pdf_ok(data):
        raise ValueError("Response is not a complete PDF (login page/403 or damaged file)")
    return data


def save_named(output: Path, library: str, filename: str, doc_id: str,
               data: bytes, source: str, records: list[dict], verify: str) -> None:
    if (library in (".", "..") or not re.fullmatch(r"[A-Za-z0-9_-]{2,50}", library)
            or not re.fullmatch(r"[A-Za-z0-9_-]{2,96}\.pdf", filename, re.I)):
        raise ValueError("Unsafe PDF destination name")
    destination = output / library / filename
    if destination.parent.is_symlink() or destination.is_symlink():
        raise ValueError("Unsafe symlink in PDF output destination")
    record = {
        "document": doc_id, "library": library, "filename": filename,
        "source": source, "provenance": verify, "sha256": sha256(data),
        "bytes": len(data), "status": "",
    }
    if not pdf_ok(data):
        record["status"] = "INVALID_PDF"
    elif destination.exists():
        record["status"] = ("ALREADY_PRESENT" if sha256(destination.read_bytes()) ==
                            record["sha256"] else "CONFLICT_NOT_OVERWRITTEN")
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temp = destination.with_name(destination.name + ".partial")
        try:
            with temp.open("xb") as stream:
                stream.write(data)
            temp.replace(destination)
            record["status"] = "SAVED"
        finally:
            temp.unlink(missing_ok=True)
    records.append(record)
    print(f"[{record['status']}] {library}/{filename}")


def store_pdf(output: Path, doc_id: str, data: bytes, source: str,
              records: list[dict], verify: str) -> None:
    library, filename = ALIASES[doc_id]
    save_named(output, library, filename, doc_id, data, source, records, verify)


def classify_local_pdf(filename: str) -> tuple[str, str, str]:
    """Only explicit MCU prefixes/official filenames convey candidate scope."""
    basename = Path(filename).name
    ident = basename[:-4].upper() if basename.lower().endswith(".pdf") else ""
    if ident in ALIASES:
        library, name = ALIASES[ident]
        return library, name, "CANONICAL_FILENAME_CANDIDATE"
    short = re.fullmatch(r"MC(?:68331|331)_([A-Za-z0-9_-]{2,50})\.pdf", basename, re.I)
    if short:
        return "MC68331", "MC68331_" + short.group(1).upper() + ".pdf", "LOCAL_MCU_PREFIX_UNVERIFIED"
    m332 = re.fullmatch(r"MC68332_([A-Za-z0-9_-]{2,50})\.pdf", basename, re.I)
    if m332:
        return "MC68332", "MC68332_" + m332.group(1).upper() + ".pdf", "LOCAL_MCU_PREFIX_UNVERIFIED"
    m336 = re.fullmatch(r"MC68336_68376_([A-Za-z0-9_-]{2,50})\.pdf", basename, re.I)
    if m336:
        suffix = m336.group(1).upper()
        lib = "MC68376-only" if suffix.startswith("13_") else "MC68336-376"
        return lib, "MC68336_68376_" + suffix + ".pdf", "LOCAL_MCU_PREFIX_UNVERIFIED"
    # For unknown PDF names do not invent CPU scope. Keep a stable quarantine
    # filename with source hash prefix; user can inspect document and move it.
    clean = re.sub(r"[^A-Za-z0-9_-]+", "_", Path(basename).stem)[:45] or "DOCUMENT"
    return "TO_REVIEW", "UNVERIFIED_" + clean + ".pdf", "DOCUMENT_SCOPE_UNKNOWN"


def import_pdf_directory(source: Path, output: Path, records: list[dict]) -> None:
    if not source.is_dir():
        raise ValueError("Selected PDF source folder does not exist")
    if source.resolve() == output.resolve():
        raise ValueError("PDF input folder and destination must differ")
    processed = 0
    for root, dirs, files in os.walk(source, followlinks=False):
        dirs[:] = sorted(d for d in dirs if not (Path(root) / d).is_symlink()
                         and (Path(root) / d).resolve() != output.resolve())
        for name in sorted(files):
            file_path = Path(root) / name
            if file_path.suffix.lower() != ".pdf" or file_path.is_symlink():
                continue
            processed += 1
            if processed > 2000:
                raise ValueError("Too many PDFs: limit 2000")
            if file_path.stat().st_size > MAX_PDF:
                records.append({"source": str(file_path), "status": "PDF_TOO_LARGE"})
                continue
            try:
                library, target, provenance = classify_local_pdf(name)
                save_named(output, library, target, target[:-4].upper(),
                           file_path.read_bytes(), str(file_path), records,
                           provenance + "; CHECK_COVER_AND_MODEL")
            except Exception as exc:
                records.append({"source": str(file_path), "status": "FAILED", "error": str(exc)})


def extract_zip(archive: Path, output: Path, records: list[dict]) -> None:
    # Do not classify another device archive using these same short basenames.
    if not archive.name.upper().startswith("MC683336_376UM"):
        raise ValueError("ZIP must be named MC683336_376UM*.zip (original NXP archive)")
    with zipfile.ZipFile(archive) as zip_file:
        used = set()
        for item in zip_file.infolist():
            if item.is_dir():
                continue
            components = item.filename.replace("\\", "/").split("/")
            if any(component in (".", "..") for component in components):
                records.append({"source": archive.name + ":" + item.filename,
                                "status": "SKIPPED_UNSAFE_ZIP_PATH"})
                continue
            original = components[-1].lower()
            doc_id = ZIP_NAMES.get(original)
            if doc_id is None:
                # Older ZIP revisions sometimes change suffix spelling.
                match = re.fullmatch(r"c(\d{1,2})([a-z][a-z0-9_-]*)\.pdf", original)
                if match:
                    chapter = match.group(1).zfill(2)
                    expected = CHAPTERS.get(chapter)
                    if expected is not None and expected.lower() in match.group(2):
                        doc_id = "MC68336376UM" + chapter
            if doc_id is None and not original.endswith(".pdf"):
                continue
            if doc_id is None:
                # Unknown sections are preserved but quarantined, not assigned
                # automatic MC68336/376 hardware register authority.
                safe = re.sub(r"[^a-z0-9_-]+", "_",
                              Path(original).stem.lower())[:42] or "document"
                if item.file_size > MAX_PDF or item.compress_size > MAX_PDF:
                    records.append({"source": archive.name + ":" + item.filename,
                                    "status": "PDF_TOO_LARGE"})
                    continue
                try:
                    with zip_file.open(item) as stream:
                        data = stream.read(MAX_PDF + 1)
                    save_named(output, "TO_REVIEW",
                               "MC68336_68376_UNMAPPED_" + safe + ".pdf",
                               "UNMAPPED_" + safe.upper(), data,
                               archive.name + ":" + item.filename, records,
                               "ZIP_CHAPTER_UNKNOWN; VERIFY_MODEL_AND_CONTENT")
                except Exception as exc:
                    records.append({"source": archive.name + ":" + item.filename,
                                    "status": "FAILED", "error": str(exc)})
                continue
            if doc_id in used:
                records.append({"document": doc_id, "source": archive.name,
                                "status": "DUPLICATE_ARCHIVE_ENTRY_SKIPPED"})
                continue
            used.add(doc_id)
            if item.file_size > MAX_PDF or item.compress_size > MAX_PDF:
                records.append({"document": doc_id, "source": archive.name,
                                "status": "PDF_TOO_LARGE"})
                continue
            try:
                with zip_file.open(item) as stream:
                    data = stream.read(MAX_PDF + 1)
                store_pdf(output, doc_id, data,
                          archive.name + ":" + item.filename, records,
                          "ZIP_ARCHIVE_CONTEXT_UNVERIFIED; CHECK_PDF_HEADER")
            except Exception as exc:
                records.append({"document": doc_id, "source": archive.name,
                                "status": "FAILED", "error": str(exc)})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Download NXP CPU32 manuals for GhidrAssist RAG, with safe names."
    )
    parser.add_argument("--output", type=Path,
                        default=Path.home() / "Dokumentacja" / "GhidrAssist-RAG")
    parser.add_argument("--catalog", default=CATALOG,
                        help="Official GitHub master catalog URL or local Markdown")
    parser.add_argument("--zip", dest="archives", type=Path, action="append",
                        default=[], help="Optional existing MC683336_376UM_ZIP archive")
    parser.add_argument("--pdf-dir", dest="pdf_dirs", type=Path, action="append",
                        default=[], help="Import locally downloaded PDF files recursively")
    parser.add_argument("--offline", action="store_true",
                        help="Do not contact GitHub or NXP; process local sources only")
    parser.add_argument("--dry-run", action="store_true",
                        help="List planned official URLs and ZIP sources without fetching")
    args = parser.parse_args(argv)
    output = args.output.expanduser().resolve()
    records: list[dict] = []
    urls: list[tuple[str, str]] = []
    if not args.offline:
        try:
            urls = direct_catalog_urls(read_catalog(args.catalog))
        except Exception as exc:
            print("ERROR: cannot read source catalog:", exc, file=sys.stderr)
            return 2
    if args.dry_run:
        for doc_id, url in urls:
            print(f"PLAN {ALIASES[doc_id][0]}/{ALIASES[doc_id][1]} <- {url}")
        for archive in args.archives:
            print("PLAN ZIP", archive)
        for directory in args.pdf_dirs:
            print("PLAN local PDF folder", directory)
        return 0
    # Product-only catalog entries are deliberately not converted into
    # guessed URLs, and remain visible in the machine-readable report.
    if not args.offline:
        known_direct = {doc_id for doc_id, url in urls}
        for doc_id in sorted(set(ALIASES).difference(known_direct)):
            records.append({
                "document": doc_id,
                "status": "NO_VERIFIED_DIRECT_URL",
                "source": "catalog only (product page, not direct PDF)",
                "note": "Manual manufacturer download or authenticated NXP session required",
            })
            print(f"[MANUAL DOWNLOAD] {doc_id}: no verified direct PDF URL")
    for archive in args.archives:
        try:
            extract_zip(archive.expanduser(), output, records)
        except Exception as exc:
            print("ZIP FAILED:", archive, exc, file=sys.stderr)
            records.append({"source": str(archive), "status": "ZIP_FAILED",
                            "error": str(exc)})
    for local_dir in args.pdf_dirs:
        try:
            import_pdf_directory(local_dir.expanduser(), output, records)
        except Exception as exc:
            print("LOCAL PDF FOLDER FAILED:", local_dir, exc, file=sys.stderr)
            records.append({"source": str(local_dir), "status": "LOCAL_FOLDER_FAILED",
                            "error": str(exc)})
    consecutive404 = 0
    nxp_offline = False
    for doc_id, url in urls:
        library, name = ALIASES[doc_id]
        if (output / library / name).exists():
            records.append({"document": doc_id, "source": url,
                            "status": "EXISTS_NOT_REDOWLOADED"})
            print(f"[EXISTS] {library}/{name}")
            continue
        if nxp_offline:
            records.append({"document": doc_id, "source": url,
                            "status": "SKIPPED_NXP_DIRECT_ENDPOINT_UNAVAILABLE",
                            "note": "Two independent official NXP PDF links returned HTTP 404"})
            print(f"[SKIPPED] {doc_id}: NXP direct PDF endpoint unavailable")
            continue
        try:
            store_pdf(output, doc_id, fetch_pdf(url), url, records,
                      "NXP_CATALOG_DIRECT_LINK; VERIFY_EDITION")
            consecutive404 = 0
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                consecutive404 += 1
                if consecutive404 >= 2:
                    nxp_offline = True
                    print("[NXP ENDPOINT UNAVAILABLE] Two different direct NXP PDF "+
                          "links returned HTTP 404; skipping remaining attempts. "+
                          "Use --zip or --pdf-dir with files downloaded from NXP.",
                          file=sys.stderr)
            else:
                consecutive404 = 0
            records.append({"document": doc_id, "source": url,
                            "status": "FAILED", "http_status": exc.code,
                            "error": str(exc)})
            print(f"[FAILED] {doc_id}: {exc}", file=sys.stderr)
        except Exception as exc:
            consecutive404 = 0
            records.append({"document": doc_id, "source": url,
                            "status": "FAILED", "error": str(exc)})
            print(f"[FAILED] {doc_id}: {exc}", file=sys.stderr)
    output.mkdir(parents=True, exist_ok=True)
    manifest = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "catalog": None if args.offline else args.catalog,
        "notes": [
            "Model applicability and revision MUST be checked against PDF contents.",
            "NXP product landing pages, account-gated files and MC68375 without official manual are not guessed.",
            "GhidrAssist RAG indexing is a separate, explicit user action.",
        ],
        "documents": records,
    }
    (output / "download_report.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    saved = sum(x.get("status") in ("SAVED", "ALREADY_PRESENT", "EXISTS_NOT_REDOWLOADED")
                for x in records)
    failed = sum(x.get("status") in ("FAILED", "ZIP_FAILED", "INVALID_PDF",
                                   "CONFLICT_NOT_OVERWRITTEN",
                                   "LOCAL_FOLDER_FAILED") for x in records)
    print(f"RESULT saved/present={saved}, issues={failed}; report: {output/'download_report.json'}")
    if saved == 0:
        print("No verified PDFs available. Supply an official local NXP ZIP "+
              "or a folder of previously downloaded PDF manuals.", file=sys.stderr)
        return 2
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
