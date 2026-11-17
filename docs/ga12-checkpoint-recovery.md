# GA-12 — read-only recovery of isolated CPU32 checkpoints

This is a **candidate recovery selector**, not formal GA-12 acceptance. It reads immutable checkpoint pairs created by the isolated CPU32 runner and validated by `verify-ga12-cpu32-checkpoint.py`.

Store each completed run in a distinct UTC directory, e.g. `checkpoints/20261117T110000Z/result.json` and `checkpoints/20261117T110000Z/evidence.log`. Both files must come from the **same** completed isolated run. Run:

```sh
python3 scripts/recover-ga12-cpu32-checkpoint.py --root checkpoints --source-sha FULL_40_CHAR_SOURCE_SHA
```

The default selects only the newest timestamp-named directory and **blocks** on a corrupt, incomplete or FAIL checkpoint. It never silently selects older evidence. For explicit operator-authorized fallback, pass `--allow-prior`; output then identifies every rejected newer checkpoint in `skipped`. A recovered checkpoint must have an independently verified PASS and match the supplied source SHA, synthetic fixture, Ghidra release and preserved log hash. The command does not mutate any evidence, project, firmware, or production data. Exit 0 means recoverable, exit 2 means blocked.

This is recovery *selection*, not automatic reapplication of Ghidra changes, not proof of execution on MC68332, and not proof of active MM, VBR/ISR or physical chip-select mapping. Do not use it to bypass Review/Apply/Undo or authorization. The existing checkpoint validator remains the single evidence authority. Source regressions cover newest PASS, corrupt latest, explicit fallback, FAIL verdict, symlink and missing-file refusal. Exact-head CI and independent review are required before integration.
