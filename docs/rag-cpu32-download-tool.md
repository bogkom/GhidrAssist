# CPU32 / MC683xx RAG documentation downloader

The canonical Python 3.9+ script is located at
[src/main/resources/rag_cpu32_downloader.py](../src/main/resources/rag_cpu32_downloader.py).
No Python packages are required. It is also bundled inside the GhidrAssist
extension and can be launched with **RAG > Download CPU32 manuals...**.

The button asks for an output directory and optionally an existing
**MC683336_376UM_ZIP.zip** file. It runs the downloader as an explicit background
task. It never indexes the files automatically. Use **RAG > Add Documents**
after verifying the correct CPU/library assignment.

## Terminal (Linux)

Download public NXP direct-PDF links from the current official GitHub
documentation catalog:

    python3 rag_cpu32_downloader.py --output "$HOME/Dokumentacja/GhidrAssist-RAG"

To additionally unpack the ZIP already downloaded from NXP and rename its
recognized chapter PDFs:

    python3 rag_cpu32_downloader.py --output "$HOME/Dokumentacja/GhidrAssist-RAG" \
       --zip "$HOME/Pobrane/MC683336_376UM_ZIP.zip"

For offline extraction only, add --offline. To preview what the script plans
without downloads, add --dry-run.

## File naming

| Publication or ZIP entry | Output path |
|---|---|
| MC68332UM.pdf | MC68332/MC68332UM.pdf |
| MC68336376UMD.pdf or ZIP apdreg.pdf | MC68336-376/MC68336_68376_D_REGISTERS.pdf |
| MC68336376UM05.pdf or ZIP c5sim.pdf | MC68336-376/MC68336_68376_05_SIM.pdf |
| MC68336376UM08.pdf or ZIP c8qadc.pdf | MC68336-376/MC68336_68376_08_QADC.pdf |
| MC68336376UM13.pdf | MC68376-only/MC68336_68376_13_TOUCAN.pdf |
| M68000PRM.pdf, SIMRM.pdf, TPURM.pdf | CPU32-common/ (original names) |

The script also handles other explicitly cataloged chapter identifiers.
It groups downloaded PDFs into CPU32-common, MC68331, MC68332, MC68336-376
and MC68376-only folders. The ZIP context provides a *candidate* source
identity, not proof of CPU model, manual edition or reset register fields.

A report named **download_report.json** stores source URLs, local names,
SHA-256, size and status for each processed document. The Ghidra launcher
additionally writes **download_process.log**.

## NXP direct PDF HTTP 404 (verified 2026-10-22)

The first GhidrAssist downloader attempted 13 vendor PDF URLs and obtained
**0** PDFs (13 HTTP 404). A separate GitHub Actions probe confirmed HTTP 404
for NXP `/docs/en/user-guide/`, `/reference-manual/` and `/data-sheet/`
with both GhidrAssist and browser User-Agent strings, including on
`www.nxp.com.cn`. Cached/indexed PDF search results are not proof that the
live download endpoint remains available.

When running the new script online, **two independent NXP HTTP 404 results**
stop further redundant direct-PDF attempts. The report marks the remaining
entries `SKIPPED_NXP_DIRECT_ENDPOINT_UNAVAILABLE`. This is not a fix for
NXP's server; no unauthorized mirrors are used.

The RAG UI now explicitly asks for a **source** rather than presenting a
misleading YES/NO dialog: **Import NXP ZIP (recommended)**, **Import downloaded
PDF folder** or **Try NXP online**. The first two are offline and avoid
NXP endpoints entirely. Use the ZIP you downloaded already from the vendor.

Existing local PDF folder import accepts verified canonical names and
**user-supplied candidate prefixes** `MC331_...`, `MC68331_...`,
`MC68332_...`, `MC68336_68376_...`. Unrecognized short names
(`c5sim.pdf` without the defining NXP ZIP context) go to
`TO_REVIEW/UNVERIFIED_...`; never assign those to a concrete MCU.
A source-mapping claim is separate from a verified manual revision.

Terminal alternatives:

    python3 rag_cpu32_downloader.py --offline \
      --zip "/path/to/MC683336_376UM_ZIP.zip" --output "/path/to/destination"

    python3 rag_cpu32_downloader.py --offline \
      --pdf-dir "/path/to/downloaded-manuals" --output "/path/to/destination"

## Correcting partial imports from Oct 22 (PR #39)

The first observed NXP `MC683336_376UM_ZIP` import saved **24 PDFs,
0 errors**, but placed recognized module chapters such as `c10ctm.pdf`,
`c12tram.pdf` and `c13tcan.pdf` in `TO_REVIEW`. The real archive also
contains introductory chapters `c1intro.pdf` through `c4cpu.pdf`,
`c6sram.pdf`, `c7mrm.pdf`, and appendices or index pages.
The corrected ZIP parser explicitly recognizes **chapters 01–13**, including
`07_MRM` and `13_TOUCAN` as **MC68376-only** candidates, while
keeping unknown non-register publications out of canonical profile mappings.

The subsequent **Import PDF folder** on a broad Motorola documentation tree
recorded 365 new PDFs, 13 already-present, 96 same-name collisions and 1
invalid PDF. This occurred because generic short names, such as `c5sim.pdf`,
occur in unrelated manuals. The log does not prove PDF integrity, MCU model or
correct revision in the 365 files.

The corrected local importer:
- Identifies short chapter names only when the parent directory itself has
  an explicit MC68332 or MC68336/376 manual/ZIP context. This is a **folder
  hint** that needs a matching PDF cover before trusted RAG use.
- Leaves standalone ambiguous short names in `TO_REVIEW`; skips unrelated
  manuals such as `MPC555UserManual.pdf` instead of copying every document
  from a large archive into CPU32 RAG staging.
- Preserves a differently-contented PDF with the same resulting name under
  `TO_REVIEW/COLLISION_..._<SHA256>.pdf`, without overwriting either PDF.
  Such collisions are reported as review-required, not successful trusted
  imports.
- Recognizes legacy `MC68336_68376_UNMAPPED_c10ctm.pdf` and similar
  output names from the earlier GhidrAssist ZIP import as chapter candidates.

**No files are deleted or modified in the source directories.** To obtain a
cleaner library, choose a **fresh, empty destination directory** and reimport
the original NXP ZIP first. Avoid indexing the entire old `TO_REVIEW`
directory; it contains unrelated processors, duplicate chapter names and
unverified manuals. The separate `MC68F375` label must not be promoted
to a verified `MC68375` register profile.

For audit, compare the selected documents with the original manufacturer's
manual and revision before adding them to the model-specific RAG library.

## Security and known limitations

- Only direct HTTPS PDF links to official NXP from the current
  [catalog](rag-cpu32-manual-catalog.md) are downloaded; login-gated
  materials and NXP product-page-only links are not guessed.
- An existing ZIP must have its NXP MC683336_376UM prefix and be supplied
  explicitly. ZIP-slip paths are never used as extraction destinations.
- Non-PDF responses, excessive sizes, duplicate chapters and changed
  existing files are rejected or flagged. Existing files are not overwritten.
- Files are not automatically passed to RAG/AI, and no firmware is copied.
- MC68331 documents listed only via product pages require manual download.
  MC68375 remains undocumented by a verified official model-specific manual.
- Download failures (HTTP 403, account requirement, missing PDF, changes in
  NXP URLs) are recorded; successful downloads remain available.

The Python tests run without network access using synthetic PDFs and ZIPs,
and GitHub Actions also builds the Ghidra 12.1.4 extension.
