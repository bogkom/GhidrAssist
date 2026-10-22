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
