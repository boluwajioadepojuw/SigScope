"""Extra output plugins: portfolio badge (SVG) and machine-readable JSON."""

from __future__ import annotations

from typing import List

from .coverage import CoverageReport


def render_badge(report: CoverageReport) -> str:
    """Return an SVG coverage badge string (e.g. for a README or portfolio)."""
    pct = report.coverage_ratio * 100
    label = "ATT&CK"
    value = f"{pct:.0f}%"
    color = "#e74c3c" if pct < 25 else "#e67e22" if pct < 60 else "#27ae60"

    # Simple two-segment badge, shields.io style.
    label_w, value_w = 56, 46
    total = label_w + value_w
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" '
        f'role="img" aria-label="{label}: {value}">'
        f'<linearGradient id="b" x2="0" y2="100%">'
        f'<stop offset="0" stop-color="#444"/><stop offset="1" stop-color="#333"/>'
        f'</linearGradient>'
        f'<clipPath id="a"><rect width="{total}" height="20" rx="3"/></clipPath>'
        f'<g clip-path="url(#a)">'
        f'<rect width="{label_w}" height="20" fill="#444"/>'
        f'<rect x="{label_w}" width="{value_w}" height="20" fill="{color}"/>'
        f'<g fill="#fff" text-anchor="middle" '
        f'font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{label_w/2}" y="14">{label}</text>'
        f'<text x="{label_w + value_w/2}" y="14">{value}</text>'
        f"</g></g></svg>"
    )


def render_json(report: CoverageReport) -> str:
    """Return a JSON summary suitable for dashboards / CI artifacts."""
    import json as _json

    out = {
        "version": report.db.version,
        "rules_analyzed": report.rule_count,
        "coverage": {
            "covered": len(report.covered),
            "covered_in_scope": len(report.covered_in_scope),
            "in_scope": report.total_techniques,
            "ratio": round(report.coverage_ratio, 4),
        },
        "scope": {
            "include": sorted(report.include),
            "ignore": sorted(report.ignore),
            "ignored_count": len(report.ignored),
            "out_of_scope_count": len(report.out_of_scope),
        },
        "unknown_technique_ids": report.unknown,
        "unmapped_rules": [r.path for r in report.unmapped_rules],
        "covered_techniques": [
            {
                "id": tid,
                "name": report.db.technique_name(tid),
                "rules": report.covered[tid],
            }
            for tid in report.covered_techniques
        ],
        "tactics": [
            {"tactic": t, **info}
            for t, info in report.tactics_coverage().items()
        ],
    }
    return _json.dumps(out, indent=2)
