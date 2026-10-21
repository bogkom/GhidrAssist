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
