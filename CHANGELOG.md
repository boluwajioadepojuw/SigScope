# Changelog

## 0.4.1

- Fixed screenshot paths so images render in the packaged build.

## 0.4.0, 10/07/2026 (first public release)

- **Packaging:** the compact ATT&CK database now ships inside the
  package (`coverage_gate/data/`), so a plain install works out of the
  box.
- Added `LICENSE` (MIT) and package metadata.

## 0.3.0

- New `report` HTML style: print-ready dossier with vertical ATT&CK
  columns and sub-techniques nested under their parents.
- Legend moved to the top controls row for all styles. Synced top
  scrollbar for the column rack. Multi-tactic techniques marked with a
  tooltip.
- GitHub Actions: CI (pytest matrix + ATT&CK coverage gate) and a
  monthly dataset-freshness check against the MITRE CTI data.

## 0.2.0

- **Fixed:** `--include`/`--ignore` now accept TA tactic IDs (TA0002) as
  documented. Previously they silently matched nothing.
- **Fixed:** the coverage ratio numerator now respects the active scope
  (covered within in-scope). JSON output exposes `covered_in_scope`.
- **Fixed:** a covered technique now counts in every tactic it belongs
  to, matching the official matrix semantics. Previously only its first
  tactic counted.
- **Fixed:** revoked and deprecated techniques are filtered out of the
  database. Totals now match the official Enterprise v19 matrix (15
  tactics, 222 techniques, 475 sub-techniques).
- ATT&CK dataset regenerated from the current MITRE CTI STIX bundle
  (v19 structure: Stealth TA0005 + Defense Impairment TA0112).
- ATT&CK Navigator layer export now includes the version fields
  Navigator requires. Regression test suite added
  (`tests/test_bug_regressions.py`).

## 0.1.0

- Initial version: Sigma parsing, coverage engine, terminal report,
  3 HTML styles, SVG badge, JSON summary, scope filters.
