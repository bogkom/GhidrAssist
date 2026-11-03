# GA-18 — Hardware Automation API bridge v2 (synthetic pilot)

This pilot is an incremental extension of PR #114. It is **not** yet a
production network server or an unrestricted general-purpose GhidrAssist API.

The existing Ghidra 12.1.4 CodeBrowser harness runs under Xvfb with an
isolated synthetic CPU32 project. A **separate Python process** communicates
with the live JVM using five sequential request/response files:

| Sequence | Action | Verified observation |
| --- | --- | --- |
| 0 | `ui.snapshot` | Read real Swing button states before analysis |
| 1 | `hardware.analyze` | Select MC68332, click real Analyze button on EDT; await MMIO button enabled |
| 2 | `ui.snapshot` | Verify post-analysis state |
| 3 | `listing.goto` | Navigate to synthetic address `0x20` through real GoToService |
| 4 | `listing.snapshot` | Verify actual CodeViewerService current location |

Replies are schema 2 JSON with the sequence number, active program, selected
tab, profile, status, button IDs/enabled/visible states, EDT flag and Listing
address. Replies are written to a temporary file and atomically renamed.
No screenshots are necessary for these semantic assertions; the existing
CodeBrowser fixture continues to capture X11 screenshots independently.

The production Hardware Analysis Swing components now expose stable names:
`hardware.profile`, `hardware.analyze`, `hardware.cancel`,
`hardware.review`, `hardware.mmio`, `hardware.search`,
`hardware.status`, `hardware.overview`, `hardware.evidence`.

The file handshake accepts only the fixture's known actions and allows
Listing navigation only to its synthetic `0x20`. It is not enabled in
ordinary GhidrAssist sessions. Test runner prerequisites are unchanged:
hash-pinned Ghidra 12.1.4 PUBLIC, extension ZIP, disposable workspaces,
Xvfb/Openbox and Java 25.

**Evidence tiers:** successful Ghidra 12.1.4 CI proves automated command
execution and live Swing/Ghidra service state for the exact workflow commit.
It does **not** imply human visual review, Supervisor GUI ACK, or any
acceptance of private ECU411 firmware. Keep historical reports intact.

Next stage: move the dispatcher out of the fixture into an opt-in
versioned production Automation API, add explicit program/session identity,
table snapshots, asynchronous task events and local agent transport.
