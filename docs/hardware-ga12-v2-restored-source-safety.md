# GA-12 — fail-closed restoration of unverified JSR/MOVEC/RESET sources

A GA-12 completed *aggregate CFG* checkpoint contains text, typed MMIO/role
rows, bounded RESET metadata and optionally a V2 source inventory of computed
JSR targets / MAY-SIMCR effects and MOVEC-to-VBR candidates. Both V1 and V2
are keyed to the complete current Ghidra Program, translated Listing and
installed extension JAR; a disk envelope SHA-256 detects byte changes.

**A matching key and valid SHA-256 are not source authentication.** A locally
rehashed V2 can retain correct shape, canonical RESET membership and exact
indirect JSR PCs while changing `mayMm` or MOVEC table-state claims. The
earlier restore passed `Snapshot.sourceInventory()` straight to the active
`GhidraHardwareFlowService.Report`. A consumer could paginate source pairs
from disk without independently reconstructing CPU32 instruction provenance
after the JVM restart.

## New boundary

`HardwareDurableCfgReport.restoredForReadOnlyDisplay()` is a pure,
schema-compatible **CFG-only** projection used exclusively for aggregate
report restoration by `HardwareFlowStageCache`:

- An incomplete, truncated or oversized completed snapshot is a cold
  recompute, not a source or CFG publication.
- A valid complete source report remains reusable as aggregate read-only
  CFG text, counts and existing review-safety flags. It gains a prominent
  `SOURCE INVENTORY UNVERIFIED` heading so historic source claims in the
  cached Markdown are not mistaken for freshly inspected Listing sites.
- Typed V2 `SourceInventory` is dropped from the **active** restored report.
  The source provenance remains in V2 disk bytes for compatibility and
  forensic inspection; it is never promoted into a live Automation/API
  `source-pairs` cursor after a restart. The existing GUI/API method returns
  `SOURCE_INVENTORY_NOT_RETAINED` until explicit checkpoint clear and
  **fresh Analyze** reconstructs JSR/MOVEC and bounded RESET candidates.
- V1 and generic CPU32 remain source-free. Unknown/omitted JSR, MOVEC,
  indirect-call and RESET data stay UNKNOWN; a syntactically valid source
  inventory does not alter Review/Apply/Undo authorization.
- New typed V2 structural validation refuses unrecognized RESET roots with
  a nonempty function set and an implausibly complete missing RESET root.
  Matching metadata alone does not certify source execution.

## Evidence

The Java21 disk/codec regression writes an actually rehashed forged V2
MAY-MM claim under a matching full-input key, verifies it is structurally
valid, and then asserts the active restore has **no source inventory**.
The Java25 / Ghidra 12.1.4 PUBLIC regression uses ten separate synthetic
JVMs for cold capture, complete V2 restart, syntactically rehashed false MAY,
legacy V1, invalid V2, changed source byte, renamed Function, mismatched
profile and incomplete source/report cases. In the forged V2 phase the
restored aggregate remains cache-eligible but source pagination is denied;
the test then explicitly clears that checkpoint and performs a **fresh,
independent real-Ghidra scan**. The fresh source must recover the original
positive JSR MAY-SIMCR witness instead of inheriting the forged negative
MAY claim. Exact source fingerprint and Ghidra revision are reported in
synthetic-only CI JSON.

A fresh Analyze still benefits from independently verified GA-12
**per-function** register/MMIO/VBR checkpoints and detects stale active
revision/epoch before publishing new source pages. Neither synthetic
static-CFG reachability nor a source checksum proves runtime execution,
SIMCR MM latch, active VBR/ISR or physical memory mapping.

GA-01/02/03/11/12/18 remain PARTIAL. No original ECU411 firmware,
production Ghidra project, user profile/OAuth or stopped Supervisor worker
is touched.
