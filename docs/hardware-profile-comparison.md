# GA-06 — read-only comparison of external MCU profile manifests

This feature is a **claim-difference review**, not a hardware-profile import,
MCU recognition system, RAG truth source, or verified documentation merger.
Both source files must pass the existing strict `GHIDRASSIST_PROFILE 1`
tab-delimited preview parser. No network access or external commands are used.

## Workflow in Ghidra 12.1.4

1. Hardware Analysis → `Preview profile...` → select a local `.tsv` file.
2. Read the structural preview; choose `Compare with another...` to select
   a second local `.tsv` manifest. Choosing `Close preview` leaves the
   existing preview and optional local PDF hash-check workflow unchanged.
3. Review the separate text report. No manifest is installed; selecting or
   comparing a file does **not** change the active MCU in Ghidra.

Each manifest is limited to 1 MiB and the existing 1024-record parser bounds.
Device labels must match (case-insensitively), otherwise the comparison
**fails closed** instead of suggesting a cross-model hardware merge.

## Findings and confidence

- Definitions for modules (base offset and aperture size), registers (name,
  module, width and offset) and bitfields (register, field name and mask)
  are compared by stable, case-insensitive identifiers.
- Missing entries are counted separately on each side. Conflicting definitions
  are never silently resolved by lexicographic/source order.
- Different page **labels** are reported separately from physical definition
  differences. Neither PDF page number nor printed folio is verified.
- Overlapping register intervals with **different names** are flagged as
  possible alias/name conflicts, not proven address errors or proof that
  one manifest is correct.
- Claimed SHA-256 values are compared only when both contain 64 hex digits.
  Even equal claims do **not** establish PDF byte identity, edition correctness
  or source authenticity. The separate optional streaming local-PDF checksum
  check is still needed to verify actual byte identity with a claimed digest.
- All discrepancy counters remain exact; only the first 100 detailed findings
  are displayed. The report includes the number omitted, and cannot be
  treated as a complete item-by-item record when the display is capped.

The original Ghidra Program, firmware image, Memory Map, Symbols, RAG index,
OAuth settings and hardware Review/Apply plans are never modified. Nothing is
exported or uploaded to GitHub by the comparison tool. Confidence remains
**UNVERIFIED EXTERNAL CLAIM**, even if both input manifests agree.

## Validation

The pure-Java deterministic self-test covers identical and divergent claims,
definition vs page-label separation, register-name/address collisions,
missing records, mismatched device labels, claimed digest semantics,
large capped output and immutable results. GitHub Actions runs the dedicated
test plus the full extension integration build for **Ghidra 12.1.4 PUBLIC**.
Real GUI acceptance remains a separate Supervisor test with an exact-head
artifact and a disposable project; green Java CI is not GUI acceptance.

This PR is an independent GA-06 branch based on the exact prior GA-06
profile/PDF-checkpoint PR #63, and does not modify or supersede the
GA-02/GA-05/GA-12 integrated analyzer stack.

## 2026-10-29 — case-collision and page-label validation

To prevent lossy reconciliation, the preview parser rejects module
identifiers that differ only by case (e.g., `SIM` and `sim`). A register
may refer to the canonical module in any case, but the stored definition
uses the declared module name. Each comparison key is now unique after
normalization; no source record can be silently overwritten.

A nonempty label containing `PDF page` is no longer sufficient to count
as a numbered PDF reference. Claims must contain `PDF page N` or
`PDF pages N-M` with positive numbers and no UNKNOWN, UNVERIFIED,
AMBIGUOUS, or to-be-verified qualifiers. This affects the *count of
missing/ambiguous page references*, not source authenticity. Even a
numeric label is an unverified statement from the external TSV, not
proof of page identity or source edition. Neither manifest is imported.
