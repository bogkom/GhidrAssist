# GA-12 — digest-bound recovery handoff (candidate)

`scripts/handoff-ga12-cpu32-checkpoint.py --root DIR --source-sha SHA` invokes the existing selector, checks the selected files again for existence, symlinks and SHA-256 changes, then invokes the independent semantic JSON/log verifier. `--allow-prior` is opt-in. Exit 0 only for `HANDOFF_READY`; otherwise exit 2 with `BLOCKED`.

The handoff is **read-only**. Its output is a transient manifest, not a capability token, not a Ghidra project snapshot, and not authorization for Apply or replay. A later consumer must independently verify source identity and the files again, obtain explicit authorization, provide Review and Undo, and test restoration in an isolated Ghidra 12.1.4 PUBLIC program. Neither synthetic CFG reachability nor a SIMCR/VBR/CSBAR site proves execution or active hardware state.

Source regression: `python3 -m unittest discover -s tests -p 'test_ga12_handoff.py'`. This checks rejection paths; it does not establish actual Ghidra runtime behavior. Required before merge: exact-head source regression, Java 21/25 and real synthetic Ghidra where the acceptance criterion requires them, review and Actions evidence. GA-12 remains PARTIAL.
