# GA-12 offline isolated project snapshot candidate

This tool is an **offline filesystem copy** of a CLOSED disposable Ghidra project, not an Apply transaction or an in-process Ghidra undo operation. It cannot establish a consistent snapshot of a project open in Ghidra. Use only synthetic projects that are closed, on a disposable filesystem. Do not point it at ECU411 or any production project.

```sh
python3 scripts/ga12-isolated-project-copy.py snapshot --source /tmp/synthetic-project --destination /tmp/ga12-snapshot
python3 scripts/ga12-isolated-project-copy.py verify --source /tmp/ga12-snapshot
python3 scripts/ga12-isolated-project-copy.py restore --source /tmp/ga12-snapshot --destination /tmp/new-synthetic-project --authorize-isolated-restore
python3 -m unittest discover -s tests -p test_ga12_isolated_project_copy.py
```

Snapshot creates a new directory with a manifest of relative paths, sizes and SHA-256 digests. Restore verifies the manifest and content, copies to a new directory and checks the copied bytes before publication. It requires exactly one top-level `.gpr` and a matching `.rep` directory, and rejects arbitrary folders, unpaired or multiple projects, existing destinations, nested destinations, symlinks, tampering and missing authorization. A matching pair is a structural check, not proof that Ghidra can reopen the project or that it is closed. It does not replace an existing project, replay Apply, authorize Ghidra writes, or restore undo history. The filesystem may change during copying; a source that changes and returns to identical bytes cannot be detected, so project closure is a mandatory external precondition.

Acceptance remains **PARTIAL**: run the source regressions, Java 21/25 checks and a genuine isolated Ghidra 12.1.4 PUBLIC test that creates and closes a synthetic project, snapshots it, restores to a fresh location, reopens it and verifies Listing/program state plus Review/Apply/Undo behavior. Only that runtime test can support Ghidra restoration claims. No static firmware evidence proves execution, active MM/VBR/ISR or physical chip-select mapping.
