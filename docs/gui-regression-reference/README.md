# Historical GhidrAssist GUI regression harness — reference (2026-10-29)

This is a **source-recovery / implementation reference**, not an installed or passing test suite. Do not treat this document as evidence of PR #56 acceptance.

## Recovered mechanism

The archived run of 2026-10-28 used a standalone Java test entry point `GuiIntegrationMain.java`, running on Ghidra 12.1.4 / JDK 25. It initializes Ghidra's application libraries with splash screen disabled, instantiates a custom `PluginTool`, registers `ProgramManagerPlugin` and `GhidrAssistPlugin`, and drives real Swing components on the EDT. Thus it can show a light `GhidrAssist isolated GUI regression` window without the standard Ghidra Project Manager or CodeBrowser windows. Screenshots from `Window.printAll()` are Swing renders and must be distinguished from a real X11 screenshot.

A follow-up run on 2026-10-29, performed by an isolated Codex **testing** session on the owner’s Wyse, selected `test_query_policy_ergonomics`: **1 passed, 5 deselected**. Within the fixture there were five ControlledLLM scenarios. Codex separately used `import -window` and viewed the resulting real X11 PNG using `view_image`. The temporary test GUI was closed on completion; no paid LLM was used. The original ECU411 project was not altered. This is not an acceptance test of the MMIO Listing navigation in PR #56.

## Archived source identifiers

Owner-provided historic source files (content intentionally not copied here):

| File | SHA-256 | Bytes |
| --- | --- | ---: |
| `scripts/gui/GuiIntegrationMain.java` | `8d163baf439ca3e175eebf771513276cd6baf3a8cc5398219cf92d33838ebce3` | 16210 |
| `tests/test_gui_integration.py` | `d47db915336845638eb2a6debe461822a94851b15eca98d67e05108b57a780f5` | 4943 |
| `scripts/controlled_llm.py` | `a2110b724642ed6dde47cb4c8ea6f60d62f6c6ebce074930f08d0102f51f8b56` | 13383 |
| `scripts/harness.py` | `14ca945369076a481802c43c7311121e9327c9fd46f11c53059da46137e6048c` | 14459 |

Full archives may contain private paths, settings, local test evidence, firmware metadata and other user data. **Do not upload the full archives to the public repository.** For further development, use only reviewed, relevant source files and rewrite environment-specific defaults.

## Implementation task

Create a reusable GUI test harness in the GhidrAssist repository, with one-shot smoke mode and an isolated full Query/policy mode; explicit Ghidra/JDK/artifact configuration; no network-dependent LLM; disposable test project/profile; deterministic cleanup; separate Swing/X11 evidence and actual visual readback status; and negative tests. Maintain a distinct full-CodeBrowser Listing-navigation acceptance path for PR #56.

**Ownership:** ChatGPT GhidrAssist development conversation implements code, opens PRs and reviews CI; local Codex executes approved tests only. Do not change existing pinned test plans or SHA references, and do not create ACK/PASS for PR #56.
