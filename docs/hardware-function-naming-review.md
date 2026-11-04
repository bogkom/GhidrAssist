# Direct-write-derived function naming review (no automatic renames)

Hardware Analysis's **Export CSV** now includes both candidate registers and candidate functions, using the existing seven-column schema. Function rows start with `FUNCTION_ROLE:` in the `register` column. No change to Ghidra's database occurs when generating the CSV.

A proposed function role requires:
- a **manually selected** concrete MC68332 profile (still hypothetical for ECU411);
- an existing auto-generated Ghidra function name (`FUN_...` or `SUB_...`), not a manually assigned user name;
- **at least three distinct direct hardware-register WRITE sites**, and three distinct register names;
- a conservative role signature: CSPAR + CSBAR + CSOR, or SIMCR + SYNCR, or TRAMBAR + TPUMCR (subject to the three-register minimum);
- no collision with **any** existing Ghidra symbol name, regardless of address.

Proposed names include the selected MCU as a **hypothesis**, `_CANDIDATE_`, and the function start address. A read or static XREF alone does not count as write evidence. Branches, indirect aliases, duplicate instruction sites and uncertain execution paths are not evidence of execution. No automatic `setName()` / transaction is performed in this batch.

The existing Review / Apply dialog remains reserved for memory/register definitions and the user-supplied VBR structure. A separate undoable, preflighted **function renaming UI** remains outstanding. Never feed preview-only CSV rows directly into Ghidra without human review.

Pure Java regressions cover role requirements, branch-independent direct-site counting, collisions, user-name preservation and CPU32 lockout.

## 2026-11-04 — read-only legacy naming CSV hardening (GA-08/13)

The seven-column legacy **register naming** and **function-role naming**
CSV previews were distinct from the newer, bounded GA-13 provenance export.
They quoted strings correctly, but did not neutralize spreadsheet formulas
embedded in existing symbol names, imported MCU/profile labels, or raw
register evidence. Quoting is insufficient for Excel/Calc formula execution.

Both legacy naming CSV row producers now share the same fail-closed cell
encoder in `HardwareNamingReview`, applied to **every text field**:
- Detect a leading `=`, `+`, `-` or `@` after whitespace and
  Unicode format controls (`Cf`, including supplementary code points).
  Prefix an apostrophe before CSV quoting. Never evaluate such text.
- Normalize CR, LF, NUL, Unicode line and paragraph separators into
  spaces. Escape interior quotes. Preserve otherwise harmless content.
- Bound each raw text field to 512 UTF-16 code units, appending an
  explicit `[SOURCE_TRUNCATED]` marker; never cut a surrogate pair.
  Numeric count columns remain generated typed integers. **This is
  not** a completeness claim or permission to Apply an incomplete row.

New standalone Java 21 CI executes both naming Review selftests,
including formula payloads in the symbol/profile/register fields, Unicode
word-joiners/format tags, malformed/huge input and unchanged ordinary
rows. Existing full Ghidra 12.1.4 PUBLIC / Java 25 build checks remain
required on the exact final commit.

This does **not** add a CSV importer or a renaming action. Review/Apply/Undo
and real provenance/author identities remain unchanged and partially
implemented; no inference about runtime firmware, MC68332 activity,
or manual authorship is justified. Stopped Wyse/Precision and Supervisor
tasks are not restarted.
