# GA-18 GUI-06 — bounded live CodeBrowser window for a future native CUA

**Source:** stacked GhidrAssist PR over the exact tested PR101 head, not a new GUI worker.
**Purpose:** create a NEW disposable CodeBrowser session for a separately authorized
native CUA test, rather than attempting to interact with the closed historical
window from run `786766dad08141dda989ae5b2cab6131`.

Invocation, **future host only with separate owner authorization**:

```bash
python3 run.py --ghidra <verified-ghidra_12.1.4_PUBLIC> \
  --java-home <verified-JDK25> --extension-zip <sha-verified-extension> \
  --extension-sha256 <exact-inner-ZIP-sha256> \
  --output <existing-owner-private-0700-ga18-gui-dir> \
  --cua-live --cua-timeout 90 --timeout 480
```

The host creates a unique 32-hex `run_id`, private 0700
`evidence/pilot-ghidra-<run_id>` and isolated throwaway `synthetic-mmio.bin`.
The real Ghidra CodeBrowser from the current JVM shows `synthetic-mmio.bin`,
Listing address `0x00000020` and Listing + Decompiler `FUN_00000020`.
It emits the original structural evidence and then private 0600
`cua-live-ready.json` with actual X11 XID/class/full title, pre-observation,
run ID, bounded timeout, and all native CUA/nonce/GUI PASS booleans FALSE.
Only then is the live window offered to Supervisor.

The **Supervisor-owned**, independently approved native CUA dispatcher may
inspect this READY signal and independently verify the **current** XID and
the real foreground window, session/Goal, approved workflow and per-turn
`turn/start.permissions=ga18-listing-restricted`. After its bounded
observation (or verified inability), an authorized host-only controller
may create 0600 `cua-live-release.json` in the same directory:

```json
{"schema":1,"run_id":"<fresh-run-id>","window_id":"<real-xid>",
 "window_class":"CodeBrowserMmioMain.CodeBrowserMmioMain",
 "window_title":"GhidrAssist isolated CodeBrowser MMIO: CodeBrowserFixture:/synthetic-mmio.bin",
 "status":"WINDOW_OBSERVATION_COMPLETE",
 "native_cua_verified":false,"native_nonce_ack":false,"formal_gui_pass":false}
```

This is **only a window lifecycle release signal**, NOT native tool proof.
If CUA is unavailable, status must be `CUA_UNAVAILABLE`, resulting in
`BLOCKED_NATIVE_CUA_UNAVAILABLE`. The Java process verifies the exact
window identity and Listing/Decompiler before/during/after hold, writes
`cua-live-result.json` (0600) with `LIVE_CUA_WINDOW_RELEASED_STRUCTURAL_ONLY`
or `BLOCKED`, and always disposes the temporary Ghidra project and window.
Missing signal yields `BLOCKED_NATIVE_CUA_TIMEOUT`. Changed XID/title or
Listing/Decompiler yields BLOCKED. Python terminates the Java process group
on timeout regardless of host behavior; `--cua-timeout` is 5..180 seconds.

`--cua-ci-response` is only an explicit GitHub Actions synthetic observer,
never a native Codex/CUA surrogate. Its `release`, `unavailable` and
`window-changed` cases plus the no-signal timeout run in isolated Xvfb,
using actual Ghidra 12.1.4 PUBLIC/JDK25. The previous host X11 screenshot,
four SHA256 pins, independent visual readback and historical frozen native
status are not rewritten or repeated on Wyse.

**Integrator contract:** The unchanged PR110 pending plan still targets
PR101 exact tested source/immutable artifact. The new live-window executable
harness necessarily yields a NEW commit/Actions artifact and NEW run ID and
cannot be silently substituted for PR110's old artifact target. The Supervisor
maintainer must separately review and explicitly authorize a new immutable
runtime pin/plan (or independently pinned harness supplement), then adapt
the GUI-only dispatch under its own PR. Never retarget PR110, activate a
headless queue, infer CUA from host-only JSON, forge nonce/ACK, grant X11
permissions, use `xhost +`, sudo, network, ECU411, user projects/profiles
or start Goal/session/timer. Real native ACK and final PRIVATE reporting
remain Supervisor-owned independent post-workflow gates.
