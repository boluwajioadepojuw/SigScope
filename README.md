# CoverageGate

A small Python tool that answers one question for detection engineers:
*"Which MITRE ATT&CK techniques do my Sigma rules actually cover -- and where
are the gaps?"*

It works fully offline, reads your local rule files, and plugs into CI so that
coverage regressions fail the build.

## What it does

- parses Sigma rules from a directory
- matches each rule against the bundled MITRE ATT&CK v19 dataset
- reports coverage per tactic and technique
- renders the result in four HTML styles (matrix, rows, heatmap, report)
- optionally emits JSON, a coverage badge, and a Navigator-friendly export
- exits non-zero in CI mode when coverage drops below the threshold

## Install

```bash
pip install -e .
```

## Use

```bash
coverage-gate rules --html report.html
coverage-gate rules --ci --min-coverage 80
```

The `rules/` directory contains example Sigma rules; point the command at your
own rule set in a real pipeline.

## Why it matters

Detection rules that are never mapped to ATT&CK drift silently. This tool makes
the drift visible and, wired into CI, makes it a build failure instead of a
surprise -- the same "detection-as-code" discipline large SOC teams use.

## Author

Boluwaji Oluwaseyi Adepoju

## License

MIT
