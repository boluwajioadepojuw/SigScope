# Changelog

## 0.4.1 — Readme update
- Absolute image URLs so screenshots render on PyPI (Paths are the bane of my existence)

## 0.4.0 — 2026-07-10 (first public release)

- **Packaging**: the compact ATT&CK DB now ships *inside* the package
  (`attack_mapper/data/`), so `pip install attack-mapper` works out of the box.
- Added `LICENSE` (MIT), PyPI metadata (classifiers, project URLs).

## 0.3.0

- New `report` HTML style: print-ready dossier with canonical vertical ATT&CK
  columns and sub-techniques nested under their parents.
- Legend moved to the top controls row (all styles); synced top scrollbar for
  the column rack; multi-tactic techniques marked with ⧉ + tooltip.
- GitHub Actions: CI (pytest matrix + ATT&CK coverage gate) and a monthly
  dataset-freshness check against MITRE CTI.

## 0.2.0

- **Fixed**: `--include`/`--ignore` now accept TA tactic IDs (`TA0002`), as
  documented. Previously they silently matched nothing.
- **Fixed**: the coverage ratio numerator now respects the active scope
  (`covered ∩ in-scope`); JSON output exposes `covered_in_scope`.
- **Fixed**: a covered technique now counts in *every* tactic it belongs to,
  matching the official matrix semantics (previously only its first tactic).
- **Fixed**: revoked and deprecated techniques are filtered out of the DB.
  Totals now match the official Enterprise v19 matrix (15 tactics,
  222 techniques, 475 sub-techniques).
- ATT&CK dataset regenerated from the current MITRE CTI STIX bundle
  (v19 structure: Stealth TA0005 + Defense Impairment TA0112).
- ATT&CK Navigator layer export now includes the version fields Navigator
  requires; regression test suite added (`tests/test_bug_regressions.py`).

## 0.1.0

- Initial version: Sigma parsing, coverage engine, terminal report,
  3 HTML styles, SVG badge, JSON summary, scope filters.
