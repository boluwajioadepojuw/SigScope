# Changelog

## 0.5.0 (2026-06)

- rebuilt the parser and coverage engine as standalone modules
  (scanner / attck / gate / out)
- curated ATT&CK snapshot replaces the generated database file
- new HTML theme with matrix, rows, heat and report layouts
- renamed sample rules with lynx- prefixes

## 0.4.x (2026-03 / 2026-04)

- early prototype with the coverage matrix and badge output

## 0.5.1 (2026-09-30)

- Added --min-coverage gate threshold (exit 2 when below), --csv output.
- Coverage gate now runs in CI against rules/ at a 60% minimum.
- Test suite grew from 11 to 15 tests.

## 0.5.2 (2026-09-30)

- Added --gaps: Markdown detection coverage workbook with the uncovered techniques and next actions.
- 17 tests.
