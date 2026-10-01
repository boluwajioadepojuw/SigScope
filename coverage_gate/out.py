"""Output rendering: terminal, JSON, SVG badge, standalone HTML and
ATT&CK Navigator layer JSON."""

from __future__ import annotations

import html
import json

from .gate import GateReport

STYLES = ["matrix", "rows", "heat", "report"]


def terminal(report: GateReport) -> str:
    lines: list[str] = []
    lines.append("sig-scope")
    lines.append("=" * 40)
    for tid, paths in sorted(report.covered.items()):
        t = report.mapping.lookup(tid)
        name = t.name if t else tid
        lines.append(f"{tid:<10} {name:<45} {len(paths)} rule(s)")
    lines.append("-" * 40)
    lines.append(f"covered {report.covered_count}/{report.total_count} techniques")
    return "\n".join(lines)


def json_summary(report: GateReport) -> str:
    payload = {
        "covered_techniques": sorted(report.covered.keys()),
        "covered_count": report.covered_count,
        "total_techniques": report.total_count,
        "unlinked_ids": sorted(report.unlinked),
    }
    return json.dumps(payload, indent=2)


def badge(report: GateReport) -> str:
    pct = round(100 * report.covered_count / max(report.total_count, 1))
    color = "#4caf50" if pct >= 60 else ("#ff9800" if pct >= 30 else "#f44336")
    label = f"coverage {pct}%"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="180" height="20">'
        f'<rect width="180" height="20" rx="3" fill="#2c3846"/>'
        f'<rect x="100" width="80" height="20" rx="0" fill="{color}"/>'
        f'<text x="50" y="14" font-family="monospace" font-size="11" fill="#e8eef4" text-anchor="middle">'
        f'{label}</text></svg>'
    )


_HTML_HEAD = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>SigScope</title>
<style>
body { font-family: system-ui, sans-serif; background:#0a0f16; color:#e8eef4; margin:24px; }
h1 { font-size:20px; letter-spacing:.06em; }
.meta { color:#94a7b8; font-size:12px; margin-bottom:18px; }
.tactic { margin:14px 0 6px; color:#5ecbcf; font-size:13px; letter-spacing:.08em; text-transform:uppercase; }
.tech { display:inline-block; margin:3px; padding:5px 9px; border-radius:3px; font-size:12px; }
.hit { background:#1e4d3f; border:1px solid #2f7a63; color:#d9f5ec; }
.miss { background:#3a2327; border:1px solid #6e3940; color:#f2d4d9; }
.bar { height:8px; border-radius:2px; background:#22303f; margin:4px 0 10px; }
.bar i { display:block; height:8px; border-radius:2px; background:#5ecbcf; }
table { border-collapse:collapse; font-size:12px; width:100%; }
td,th { padding:4px 8px; border-bottom:1px solid #22303f; text-align:left; }
</style></head><body>"""


def _html_matrix(report: GateReport) -> str:
    chunks = [_HTML_HEAD, "<h1>SigScope — ATT&CK matrix</h1>",
              f'<div class="meta">{report.covered_count} of {report.total_count} techniques covered</div>']
    for tactic in report.mapping.tactics:
        techs = [t for t in report.mapping.techniques.values() if t.tactic == tactic]
        if not techs:
            continue
        chunks.append(f'<div class="tactic">{tactic}</div>')
        for t in techs:
            cls = "hit" if t.id in report.covered else "miss"
            chunks.append(f'<span class="tech {cls}">{t.id}</span>')
    chunks.append("</body></html>")
    return "\n".join(chunks)


def _html_rows(report: GateReport) -> str:
    chunks = [_HTML_HEAD, "<h1>SigScope — per technique</h1>",
              f'<div class="meta">{report.covered_count} of {report.total_count} techniques covered</div>']
    for tactic in report.mapping.tactics:
        techs = [t for t in report.mapping.techniques.values() if t.tactic == tactic]
        if not techs:
            continue
        chunks.append(f'<div class="tactic">{tactic}</div>')
        for t in techs:
            n = len(report.covered.get(t.id, []))
            pct = round(100 * n / max(len(report.covered), 1)) if t.id in report.covered else 0
            chunks.append(f'<div>{t.id} {html.escape(t.name)} — {n} rule(s)</div>')
            chunks.append(f'<div class="bar"><i style="width:{min(pct,100)}%"></i></div>')
    chunks.append("</body></html>")
    return "\n".join(chunks)


def _html_heat(report: GateReport) -> str:
    chunks = [_HTML_HEAD, "<h1>SigScope — heat view</h1>",
              f'<div class="meta">{report.covered_count} of {report.total_count} techniques covered</div>', "<table>"]
    for tactic in report.mapping.tactics:
        techs = [t for t in report.mapping.techniques.values() if t.tactic == tactic]
        if not techs:
            continue
        row = f'<tr><td>{tactic}</td>'
        for t in techs:
            n = len(report.covered.get(t.id, []))
            shade = {0: "#3a2327", 1: "#4a3b1e", 2: "#1e4d3f"}.get(n, "#2f7a63")
            row += f'<td style="background:{shade}" title="{t.id}">{n}</td>'
        row += "</tr>"
        chunks.append(row)
    chunks.append("</table></body></html>")
    return "\n".join(chunks)


def _html_report(report: GateReport) -> str:
    chunks = [_HTML_HEAD, "<h1>SigScope — report</h1>",
              f'<div class="meta">{report.covered_count} of {report.total_count} techniques covered</div>', "<table>"]
    chunks.append("<tr><th>Technique</th><th>Name</th><th>Tactic</th><th>Rules</th></tr>")
    for tid, paths in sorted(report.covered.items()):
        t = report.mapping.lookup(tid)
        names = ", ".join(sorted(p.split("/")[-1] for p in paths))
        chunks.append(f"<tr><td>{tid}</td><td>{html.escape(t.name if t else tid)}</td>"
                      f"<td>{t.tactic if t else ''}</td><td>{html.escape(names)}</td></tr>")
    chunks.append("</table></body></html>")
    return "\n".join(chunks)


def html_report(report: GateReport, style: str) -> str:
    return {
        "matrix": _html_matrix,
        "rows": _html_rows,
        "heat": _html_heat,
        "report": _html_report,
    }[style](report)

def csv_summary(report: GateReport) -> str:
    """CSV of covered techniques for easy diffing in CI."""
    rows = ["technique_id,technique_name,rules"]
    for tid, paths in sorted(report.covered.items()):
        t = report.mapping.lookup(tid)
        name = (t.name if t else tid).replace(",", " ")
        rows.append(f"{tid},{name},{len(paths)}")
    return "\n".join(rows) + "\n"


def gap_workbook(report: GateReport) -> str:
    """Markdown workbook of the techniques still uncovered."""
    lines = [
        "# Detection coverage workbook",
        "",
        f"Covered {report.covered_count} of {report.total_count} techniques.",
        "",
        "## Gaps",
        "",
        "| Technique | Name | Tactic | Note |",
        "| --- | --- | --- | --- |",
    ]
    for tech in report.gaps:
        lines.append(f"| {tech.id} | {tech.name} | {tech.tactic} | no rule yet |")
    if not report.gaps:
        lines.append("| - | - | - | nothing uncovered |")
    lines += [
        "",
        "## Next actions",
        "",
    ]
    for tech in report.gaps:
        lines.append(f"- Write a rule that catches {tech.name.lower()} (tactic: {tech.tactic.lower()}).")
    lines.append("")
    return "\n".join(lines)


def navigator_layer(report: GateReport) -> str:
    """ATT&CK Navigator layer JSON (enterprise-attack domain).

    Covered techniques are marked with score 100 and the rules behind
    them; gaps are marked with score 0. Load the file at
    https://mitre-attack.github.io/attack-navigator/ for visual review.
    """
    techniques = []
    for tid, paths in sorted(report.covered.items()):
        techniques.append({
            "techniqueID": tid,
            "score": 100,
            "comment": "covered by: " + ", ".join(sorted(p.split("/")[-1] for p in paths)),
        })
    for tech in report.gaps:
        techniques.append({
            "techniqueID": tech.id,
            "score": 0,
            "comment": "gap - no rule maps to this technique",
        })
    layer = {
        "name": "SigScope coverage",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": (
            f"Generated by SigScope: {report.covered_count} of "
            f"{report.total_count} techniques covered"
        ),
        "filters": {"platforms": ["Windows", "Linux", "macOS"]},
        "sorting": 0,
        "layout": {"layout": "side", "aggregateFunction": "average", "showID": False, "showName": True},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "covered", "color": "#8ec843"},
            {"label": "gap", "color": "#ff6666"},
        ],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "metadata": [],
    }
    return json.dumps(layer, indent=2)
