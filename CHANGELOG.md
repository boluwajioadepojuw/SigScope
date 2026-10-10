# Changelog

## 0.7.0 (2026-10)

- ten new rules converted from the SOCAtelier Elastic detections:
  ping sweep, archiver on sensitive folders, process from unusual
  directory, Suricata SCAN/EXPLOIT alerts, RDP file creation, suspicious
  named pipes, Defender exclusion, Office spawning script host, UAC
  bypass registry hijack
- coverage of the 54-technique snapshot raised from 24 to 39 techniques
  (72 percent)
- all rule IDs are now valid UUIDs; owner fields normalized to author

## 0.6.0 (2026-10)

- ATT&CK Navigator layer export
- `--strict` mode: unparseable rule files fail the run instead of being skipped
- per-tactic minimum coverage (`--min-tactic-coverage`)
- CI: ruff lint, pytest with coverage, PyPI publish workflow
- test suite grown from 17 to 24 tests
- coverage gate kept at 40 percent for the curated 54-technique snapshot

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

## 0.6.0 (2026-10-01)

- Added --navigator: ATT&CK Navigator layer export (covered techniques at
  score 100, gaps at score 0).
- Added --strict: exit 1 when any rule file cannot be parsed. scan_rules()
  now reports broken files instead of silently dropping them.
- Added --min-tactic-coverage: fail the gate when a single tactic drops
  below the threshold, not only the overall coverage.
- CI now runs ruff, pytest-cov, and the strict coverage gate; the gate job
  uploads a Navigator layer alongside the HTML/JSON/badge artifacts.
- Packaging: PEP 639 SPDX license, setuptools>=77, version 0.6.0.
