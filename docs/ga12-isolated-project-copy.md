# GA-12 offline isolated project snapshot candidate

This tool is an **offline filesystem copy** of a CLOSED disposable Ghidra project, not an Apply transaction or an in-process Ghidra undo operation. It cannot establish a consistent snapshot of a project open in Ghidra. Use only synthetic projects that are closed, on a disposable filesystem. Do not point it at ECU411 or any production project.

```sh
python3 scripts/ga12-isolated-project-copy.py snapshot --source /tmp/synthetic-project --destination /tmp/ga12-snapshot
python3 scripts/ga12-isolated-project-copy.py verify --source /tmp/ga12-snapshot
python3 scripts/ga12-isolated-project-copy.py restore --source /tmp/ga12-snapshot --destination /tmp/new-synthetic-project --authorize-isolated-restore
python3 -m unittest discover -s tests -p test_ga12_isolated_project_copy.py
```

Snapshot creates a new directory with a manifest of relative paths, sizes and SHA-256 digests. Restore verifies the manifest and content, copies to a new directory and checks the copied bytes before publication. It requires exactly one top-level `.gpr` and a matching `.rep` directory, and rejects arbitrary folders, unpaired or multiple projects, existing destinations, nested destinations, symlinks, tampering and missing authorization. A matching pair is a structural check, not proof that Ghidra can reopen the project or that it is closed. It does not replace an existing project, replay Apply, authorize Ghidra writes, or restore undo history. The filesystem may change during copying; a source that changes and returns to identical bytes cannot be detected, so project closure is a mandatory external precondition.

The CLI regression suite additionally exercises snapshot → verify → explicitly authorized restore end-to-end in separate Python processes, including digest comparison of restored files and fail-closed refusal for tampered snapshots, pre-existing destinations and symlinked manifests. These tests use a synthetic filesystem fixture, **not** a Ghidra-created project; they do not count as a Ghidra runtime PASS.

Acceptance remains **PARTIAL**: run the source regressions, Java 21/25 checks and a genuine isolated Ghidra 12.1.4 PUBLIC test that creates and closes a synthetic project, snapshots it, restores to a fresh location, reopens it and verifies Listing/program state plus Review/Apply/Undo behavior. Only that runtime test can support Ghidra restoration claims. No static firmware evidence proves execution, active MM/VBR/ISR or physical chip-select mapping.

## Genuine isolated Ghidra reopen smoke (candidate)

With Java 25 and `GHIDRA_INSTALL_DIR` set to the **12.1.4 PUBLIC** installation, run:

```sh
bash scripts/ga12-genuine-reopen-smoke.sh
```

The harness creates a temporary synthetic CPU32 binary, imports it into a fresh Ghidra project, checks a GhidraScript witness, exits Ghidra, snapshots and restores the closed project using the production CLI, then runs `analyzeHeadless -process` on the restored project **without reimporting**. It requires `GA12_REOPEN_PASS` in both Ghidra logs and emits `GA12_GENUINE_REOPEN_PASS` only after the second witness. All temporary project data is deleted on exit. The harness has not yet been executed against Ghidra; its presence alone is not a runtime PASS. The strengthened witness checks the exact six imported fixture bytes (4e714e714e75), the CPU32 language ID, the program name and the six-byte memory size on both import and reopen. This prevents a false PASS merely because a nonempty, unrelated program opened. It does not yet assert a saved annotation or Undo transaction. This is a headless program-open and content witness, **not** GUI Listing, Review/Apply/Undo, persistence of undo history or formal GA-12 acceptance.

The genuine harness also makes a separate corrupted copy of the snapshot, alters a payload file, and demands that an explicitly authorized restore is rejected **without creating the destination** (`GA12_CORRUPT_RESTORE_REJECTED`). This negative witness is required before the restored valid project is reopened. Source-level regression checks the harness contract; neither check is a runtime PASS until the harness actually runs under Ghidra 12.1.4 PUBLIC.

## Java 25 genuine Actions execution gate

The PR workflow now has two independent jobs: Python 3.11 source/CLI regressions and a Java 25 job that downloads the official Ghidra 12.1.4 PUBLIC release, runs the disposable synthetic project import/snapshot/corrupt-rejection/restore/reopen harness, and archives the output and SHA-256 hashes. The real job must emit both `GA12_CORRUPT_RESTORE_REJECTED` and `GA12_GENUINE_REOPEN_PASS`. The source-contract regression guards that these steps remain wired into Actions. CI workflow configuration is **not** proof of execution; only a successful run on the recorded commit/checkout and its logs can support a genuine headless PASS. Java 25 here does not imply a full GhidrAssist extension build; that is a separate acceptance gate.

The smoke is deliberately limited to offline project bytes and Ghidra program reopening; it does not establish Review/Apply/Undo, restored in-process transactions, GUI behavior or full formal GA-12 completion.
