"""Render a CoverageReport as terminal text or a standalone HTML page.

The HTML renderer offers three visual *styles* (see ``render_html`` ``style``
argument): ``matrix`` (default card grid), ``rows`` (compact tactic rows), and
``heat`` (dense heatmap). All styles share the same data and legend, show the
active include/ignore scope, and include interactive controls:

* a **search box** (works in every style) that dims non-matching techniques,
* **collapsible tactic areas** (click the header / label),
* an **eye toggle** to hide/show a whole tactic area — the button stays visible
  so you can always bring the area back.

Interactivity is plain JavaScript embedded in the file, so the report is fully
self-contained (no network, no dependencies).
"""

from __future__ import annotations

import json
from typing import Dict, List, Optional

from .coverage import CoverageReport

STYLES = ("matrix", "rows", "heat", "report")


def render_terminal(report: CoverageReport) -> str:
    """Human-friendly terminal output with per-tactic coverage bars."""
    lines: List[str] = []
    db = report.db
    pct = report.coverage_ratio * 100

    lines.append("=" * 60)
    lines.append("  MITRE ATT&CK DETECTION COVERAGE")
    lines.append("=" * 60)
    n_scoped = len(report.covered_in_scope)
    lines.append(
        f"  Covered techniques : {n_scoped} / {report.total_techniques}"
        f"  ({pct:.1f}%)"
    )
    if n_scoped != len(report.covered):
        lines.append(
            f"  Covered (any scope): {len(report.covered)}"
            "  (some detections fall outside the current scope)"
        )
    lines.append(f"  Rules analyzed     : {report.rule_count}")
    lines.append(f"  ATT&CK version     : {db.version}")
    if report.include:
        lines.append(f"  Scope (include)    : {', '.join(sorted(report.include))}")
    if report.ignore:
        lines.append(f"  Ignored            : {', '.join(sorted(report.ignore))}")
    if report.unknown:
        lines.append(f"  Unknown IDs (ignored): {', '.join(report.unknown)}")
    if report.unmapped_rules:
        lines.append(f"  Rules w/o ATT&CK   : {len(report.unmapped_rules)}")
    lines.append("")

    lines.append("  Per-tactic coverage")
    lines.append("  " + "-" * 54)
    for tactic, info in report.tactics_coverage().items():
        bar_len = 20
        filled = int(round(info["ratio"] * bar_len))
        bar = "#" * filled + "-" * (bar_len - filled)
        name = (info["name"] or tactic)[:22].ljust(22)
        lines.append(
            f"  {name} [{bar}] {info['covered']:>3}/{info['total']:<3} {info['ratio']*100:5.1f}%"
        )
    lines.append("")

    if report.covered_techniques:
        lines.append("  Covered techniques")
        lines.append("  " + "-" * 54)
        for tid in report.covered_techniques:
            name = db.technique_name(tid) or tid
            rules = report.covered[tid]
            lines.append(f"  {tid:<9} {name[:40]:<40} x{len(rules)}")
    lines.append("=" * 60)
    return "\n".join(lines)


def _scope_note(report: CoverageReport) -> str:
    bits = []
    if report.include:
        bits.append(
            f"Scope: only {len(report.in_scope_techniques)} in-scope techniques "
            f"(filtered by {', '.join(sorted(report.include))})"
        )
    if report.ignore:
        bits.append(
            f"Ignored: {len(report.ignored)} techniques "
            f"({', '.join(sorted(report.ignore))})"
        )
    if report.out_of_scope:
        bits.append(f"Out of scope: {len(report.out_of_scope)} techniques hidden")
    return " &middot; ".join(bits)


def _legend_html() -> str:
    return (
        '<div class="legend">'
        '<span class="cov">Covered</span>'
        '<span class="gap">Gap</span>'
        '<span class="ign">Ignored</span>'
        "</div>"
    )


def _cell(tid: str, name: str, state: str, url: str) -> str:
    # data-tid / data-name let the search box match without parsing the DOM text.
    # title shows "T1059.001 — PowerShell" as a hover tooltip.
    safe = name.replace(chr(34), "")
    tip = f"{tid} — {safe}"
    return (
        f'<li class="{state}" data-tid="{tid}" data-name="{safe}" title="{tip}">'
        f'<a href="{url}" target="_blank">{tid}</a></li>'
    )


# Shared JavaScript: search (dim non-matches), collapse areas, toggle (hide/show).
INTERACTIVE_JS = """
<script>
function setup(){
  var q = document.getElementById('search');
  var status = document.getElementById('searchstatus');
  if(q){
    q.addEventListener('input', function(){
      var term = q.value.trim().toLowerCase();
      var nodes = document.querySelectorAll('[data-tid], [data-tids]');
      var hits = 0;
      nodes.forEach(function(n){
        var t = (n.getAttribute('data-tid')||'') + ' ' + (n.getAttribute('data-tids')||'') + ' ' + (n.getAttribute('data-name')||'');
        t = t.toLowerCase();
        var match = term === '' || t.indexOf(term) !== -1;
        n.classList.toggle('dim', !match);
        if(match && term !== '') hits++;
      });
      if(status) status.textContent = term === '' ? '' : (hits + ' match(es)');
    });
  }
  // collapse / expand the body of a tactic area
  document.querySelectorAll('.collapse-trigger').forEach(function(h){
    h.style.cursor = 'pointer';
    h.addEventListener('click', function(){
      var body = document.getElementById(h.getAttribute('data-target'));
      if(!body) return;
      var hidden = body.style.display === 'none';
      body.style.display = hidden ? '' : 'none';
      h.classList.toggle('collapsed', !hidden);
    });
  });
  // hide/show a whole tactic area; the eye button lives OUTSIDE the area so it
  // always stays clickable and can restore the area.
  document.querySelectorAll('[data-toggle]').forEach(function(btn){
    btn.addEventListener('click', function(){
      var area = document.getElementById(btn.getAttribute('data-toggle'));
      if(!area) return;
      var hidden = area.style.display === 'none';
      area.style.display = hidden ? '' : 'none';
      btn.textContent = hidden ? '👁' : '🚫';  // eye / no-entry
      btn.classList.toggle('off', !hidden);
    });
  });
  // Export an ATT&CK Navigator layer JSON from the embedded coverage data.
  var layerBtn = document.getElementById('exportlayer');
  if (layerBtn) {
    layerBtn.addEventListener('click', function () {
      var data = JSON.parse(document.getElementById('layerdata').textContent);
      var text = JSON.stringify(data, null, 2);
      var a = document.createElement('a');
      a.download = 'attack-coverage-layer.json';
      document.body.appendChild(a);
      try {
        var blob = new Blob([text], { type: 'application/json' });
        var url = URL.createObjectURL(blob);
        a.href = url;
        a.click();
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
      } catch (e) {
        // Fallback: data-URI works even if Blob/URL is unavailable.
        a.href = 'data:application/json;charset=utf-8,' + encodeURIComponent(text);
        a.click();
      }
      document.body.removeChild(a);
    });
  }
  // Toggle the gaps/covered card between "what's missing" and "what I have".
  // gaps-list starts visible, cov-list starts hidden.
  var gapToggle = document.getElementById('gaptoggle');
  if (gapToggle) {
    gapToggle.addEventListener('click', function () {
      var g = document.getElementById('gaps-list');
      var c = document.getElementById('cov-list');
      var gh = document.getElementById('gaps-hint');
      var ch = document.getElementById('cov-hint');
      var showingCov = c.style.display === '';  // cov currently visible?
      g.style.display = showingCov ? '' : 'none';
      c.style.display = showingCov ? 'none' : '';
      gh.style.display = showingCov ? '' : 'none';
      ch.style.display = showingCov ? 'none' : '';
      gapToggle.innerHTML = showingCov
        ? 'show: what I have &#9656; what&rsquo;s missing'
        : 'show: what&rsquo;s missing &#9656; what I have';
    });
  }
  // Sync the top scrollbar with the horizontally scrolling column rack.
  var ts = document.getElementById('topscroll');
  var rack = document.getElementById('rack');
  if (ts && rack) {
    var spacer = ts.firstElementChild;
    var size = function(){ spacer.style.width = rack.scrollWidth + 'px'; };
    size();
    window.addEventListener('resize', size);
    var lock = false;
    ts.addEventListener('scroll', function(){
      if (lock) return; lock = true; rack.scrollLeft = ts.scrollLeft; lock = false;
    });
    rack.addEventListener('scroll', function(){
      if (lock) return; lock = true; ts.scrollLeft = rack.scrollLeft; lock = false;
    });
  }
}

document.addEventListener('DOMContentLoaded', setup);
</script>
"""


def render_html(
    report: CoverageReport,
    out_path: str,
    style: str = "matrix",
) -> str:
    """Write a self-contained HTML report and return its path.

    ``style`` is one of: ``matrix``, ``rows``, ``heat``.
    """
    if style not in STYLES:
        raise ValueError(f"style must be one of {STYLES}, got {style!r}")

    db = report.db
    tactics = report.tactics_coverage()
    scope = _scope_note(report)

    # Single source of truth: report.covered already includes inherited parents.
    # state: 'cov' if covered, 'ign' if ignored, else 'gap'.
    # A technique appears under EVERY tactic it belongs to — exactly like the
    # official ATT&CK matrix — so each tactic's chips match its covered/total
    # counts from tactics_coverage().
    in_scope = set(report.in_scope_techniques)
    by_tactic: Dict[str, list] = {t: [] for t in tactics}
    for tid, tech in db.techniques.items():
        if tid not in in_scope:
            continue
        if tid in report.covered:
            state = "cov"
        elif tid in report.ignored:
            state = "ign"
        else:
            state = "gap"
        url = tech.get("url", "#")
        for tactic in tech.get("tactics", []):
            by_tactic.setdefault(tactic, []).append((tid, tech["name"], state, url))

    base_css = """
 body{font-family:system-ui,Arial,sans-serif;background:#0f1117;color:#e6e6e6;margin:0;padding:24px}
 h1{font-size:20px;margin:0 0 4px}
 .summary{color:#9aa;margin:0 0 14px}
 .controls{display:flex;align-items:center;gap:12px;margin:0 0 18px;flex-wrap:wrap}
 #search{padding:10px 14px;border-radius:10px;border:1px solid #2a2f3a;
   background:#161a22;color:#e6e6e6;font-size:14px;min-width:280px;outline:none;
   transition:border-color .15s, box-shadow .15s}
 #search::placeholder{color:#6b7280}
 #search:focus{border-color:#27ae60;box-shadow:0 0 0 3px rgba(39,174,96,.25)}
 #searchstatus{color:#9aa;font-size:12px}
 .legend{margin:0;font-size:12px;color:#9aa}
 .legend span{padding:3px 9px;border-radius:4px;margin-right:8px;font-weight:600}
 li.cov, .cov{background:#1f6f3f;color:#dfffe9}
 li.gap, .gap{background:#3a2030;color:#ffb3c8}
 li.ign, .ign{background:#2c2c2c;color:#9aa}
 a{text-decoration:none;color:inherit}
 .dim{opacity:.10}
 .collapsed{opacity:.6}
 .eye{font-size:14px;background:rgba(255,255,255,.10);border:1px solid #2a2f3a;
   border-radius:6px;cursor:pointer;padding:3px 8px;line-height:1}
 .eye.off{background:#3a2030;border-color:#5a2a3f}
 .exportbtn{font-size:13px;font-weight:600;color:#dfffe9;cursor:pointer;
   background:linear-gradient(90deg,#27ae60,#2ecc71);border:none;border-radius:8px;
   padding:9px 14px;line-height:1;box-shadow:0 1px 4px rgba(39,174,96,.35);
   transition:transform .12s, box-shadow .12s}
 .exportbtn:hover{transform:translateY(-1px);box-shadow:0 3px 10px rgba(39,174,96,.45)}
 .exportbtn:active{transform:translateY(0)}
 .gaps-card{background:#1b1f2a;border:1px solid #2a2f3a;border-radius:10px;
   padding:14px 16px;margin:0 0 18px;max-width:560px}
 .gaps-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:10px}
 .gaps-title{font-weight:700;font-size:14px;color:#e6e6e6}
 .gaptoggle{font-size:11px;color:#cdd;cursor:pointer;background:#161a22;
   border:1px solid #2a2f3a;border-radius:6px;padding:5px 9px;line-height:1;
   transition:border-color .15s, color .15s}
 .gaptoggle:hover{border-color:#27ae60;color:#dfffe9}
 .gaps-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:7px}
 .gaps-list li{display:flex;align-items:center;gap:10px;font-size:12px}
 .gname{width:150px;color:#cdd;flex:0 0 auto}
 .gbar{flex:1;height:8px;background:#2a2f3a;border-radius:5px;overflow:hidden}
 .gbar > i{display:block;height:100%}
 .gcnt{flex:0 0 auto;color:#9aa;width:80px;text-align:right}
 .gaps-hint{margin-top:10px;font-size:11px;color:#6b7280}
"""

    if style == "matrix":
        css = base_css + """
 .matrix{display:flex;flex-wrap:wrap;gap:12px}
 .tactic-wrap{display:flex;flex-direction:column;gap:4px}
 .tactic{background:#1b1f2a;border:1px solid #2a2f3a;border-radius:8px;overflow:hidden;width:230px}
 .thead{padding:8px;font-weight:700;color:#fff;font-size:13px;display:flex;justify-content:space-between;align-items:center;gap:6px}
 .thead .tname{flex:1}
 .cnt{font-weight:400;opacity:.9}
 .cells{list-style:none;margin:0;padding:8px;display:flex;flex-wrap:wrap;gap:4px}
 .cells li{font-size:11px;padding:2px 5px;border-radius:4px}
"""
        blocks = []
        for tactic, info in tactics.items():
            ratio = info["ratio"] * 100
            color = (
                "#c0392b" if ratio < 25 else "#e67e22" if ratio < 60
                else "#27ae60" if ratio > 0 else "#7f8c8d"
            )
            rows = "".join(
                _cell(t, n, s, u)
                for (t, n, s, u) in sorted(by_tactic.get(tactic, []), key=lambda x: x[0])
            )
            body_id = f"body-{tactic}"
            area_id = f"area-{tactic}"
            blocks.append(
                f'<div class="tactic-wrap">'
                f'<button class="eye" data-toggle="{area_id}" title="hide/show area">👁</button>'
                f'<div class="tactic" id="{area_id}">'
                f'<div class="thead collapse-trigger" data-target="{body_id}" style="background:{color}">'
                f'<span class="tname">{info["name"]} '
                f'<span class="cnt">{info["covered"]}/{info["total"]}</span></span>'
                f'</div><ul class="cells" id="{body_id}">{rows}</ul></div></div>'
            )
        body_html = f'<div class="matrix">{"" .join(blocks)}</div>'

    elif style == "rows":
        css = base_css + """
 .row{display:flex;align-items:center;gap:12px;margin-bottom:8px;background:#1b1f2a;
      border:1px solid #2a2f3a;border-radius:8px;padding:8px 12px}
 .rname{width:220px;font-weight:600;font-size:13px;flex:0 0 auto;display:flex;justify-content:space-between;align-items:center;gap:6px}
 .rname .et{display:flex;align-items:center;gap:6px}
 .bar{flex:1;height:16px;background:#2a2f3a;border-radius:8px;overflow:hidden}
 .bar > i{display:block;height:100%;background:linear-gradient(90deg,#27ae60,#2ecc71)}
 .rcnt{flex:0 0 auto;font-size:12px;color:#9aa;width:70px;text-align:right}
"""
        rows = []
        for tactic, info in tactics.items():
            pctw = int(info["ratio"] * 100)
            ids = " ".join(t for (t, n, s, u) in by_tactic.get(tactic, []))
            body_id = f"body-{tactic}"
            area_id = f"area-{tactic}"
            rows.append(
                f'<div class="row-wrap">'
                f'<button class="eye" data-toggle="{area_id}" title="hide/show area">👁</button>'
                f'<div class="row" id="{area_id}">'
                f'<div class="rname collapse-trigger" data-target="{body_id}" data-tids="{ids}">'
                f'<span class="et"><span>{info["name"]}</span></span></div>'
                f'<div class="bar"><i style="width:{pctw}%"></i></div>'
                f'<div class="rcnt">{info["covered"]}/{info["total"]}</div></div></div>'
            )
        body_html = "".join(rows)

    elif style == "report":
        # A printable "detection engineering dossier". Design intent:
        #  * Vertical tactic columns in the canonical ATT&CK matrix
        #    orientation, so anyone who knows the framework reads it at a
        #    glance (the other three styles are horizontal dashboards).
        #  * Sub-techniques nested under their parent with a tree rule —
        #    the parent/sub relationship is real information the chip and
        #    heat views flatten away.
        #  * Light "paper & ink" theme + @media print rules: the report can
        #    be printed/PDF'd and attached to an audit or a portfolio.
        css = """
 :root{--paper:#f6f4ee;--ink:#22261f;--cov:#1e5f4e;--gap:#a3313a;
   --muted:#8b877c;--line:#d8d4c8;--covbg:#e3ece7;--gapbg:#f2e4e4}
 *{box-sizing:border-box}
 body{font-family:system-ui,'Segoe UI',sans-serif;background:var(--paper);
   color:var(--ink);margin:0;padding:32px 36px}
 .mono{font-family:ui-monospace,'Cascadia Mono',Menlo,Consolas,monospace}
 .masthead{display:flex;justify-content:space-between;align-items:flex-end;
   gap:24px;border-bottom:3px double var(--ink);padding-bottom:14px;margin-bottom:14px}
 .eyebrow{font-size:11px;letter-spacing:.22em;text-transform:uppercase;color:var(--muted)}
 h1{font-size:26px;margin:2px 0 6px;font-weight:750;letter-spacing:-.01em}
 .summary{color:var(--muted);margin:0;font-size:13px;max-width:640px}
 .stamp{border:2px solid var(--cov);color:var(--cov);border-radius:4px;
   padding:10px 16px;text-align:center;flex:0 0 auto}
 .stamp b{display:block;font-size:30px;line-height:1;font-weight:800}
 .stamp span{font-size:10px;letter-spacing:.18em;text-transform:uppercase}
 .controls{display:flex;align-items:center;gap:12px;margin:16px 0;flex-wrap:wrap}
 #search{padding:9px 13px;border:1px solid var(--line);border-radius:4px;
   background:#fff;color:var(--ink);font-size:14px;min-width:280px;outline:none}
 #search:focus{border-color:var(--cov);box-shadow:0 0 0 3px rgba(30,95,78,.15)}
 #searchstatus{color:var(--muted);font-size:12px}
 .exportbtn{font-size:13px;font-weight:600;color:#fff;cursor:pointer;
   background:var(--cov);border:none;border-radius:4px;padding:9px 14px}
 .exportbtn:hover{background:#17493c}
 .gaps-card{background:#fff;border:1px solid var(--line);border-radius:4px;
   padding:14px 16px;margin:0 0 18px;max-width:560px}
 .gaps-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:10px}
 .gaps-title{font-weight:700;font-size:13px;letter-spacing:.06em;text-transform:uppercase}
 .gaptoggle{font-size:11px;color:var(--ink);cursor:pointer;background:var(--paper);
   border:1px solid var(--line);border-radius:4px;padding:5px 9px}
 .gaptoggle:hover{border-color:var(--cov)}
 .gaps-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:7px}
 .gaps-list li{display:flex;align-items:center;gap:10px;font-size:12px}
 .gname{width:150px;flex:0 0 auto}
 .gbar{flex:1;height:8px;background:var(--line);border-radius:4px;overflow:hidden}
 .gbar > i{display:block;height:100%}
 .gcnt{flex:0 0 auto;color:var(--muted);width:80px;text-align:right}
 .gaps-hint{margin-top:10px;font-size:11px;color:var(--muted)}
 .topscroll{overflow-x:auto;overflow-y:hidden;height:14px;margin-bottom:2px}
 .topscroll > div{height:1px}
 .rack{display:flex;gap:10px;overflow-x:auto;align-items:flex-start;padding-bottom:12px}
 .col{flex:0 0 190px;background:#fff;border:1px solid var(--line);border-radius:4px}
 .colhead{padding:10px 10px 8px;border-bottom:2px solid var(--ink)}
 .colhead .tname{font-weight:750;font-size:13px;line-height:1.2}
 .colhead .tmeta{display:flex;justify-content:space-between;align-items:baseline;
   margin-top:4px;font-size:11px;color:var(--muted)}
 .inkbar{height:4px;background:var(--line);border-radius:2px;margin-top:6px;overflow:hidden}
 .inkbar > i{display:block;height:100%;background:var(--cov)}
 .colbody{list-style:none;margin:0;padding:6px 0}
 .colbody li{font-size:11.5px;line-height:1.35;padding:3px 10px;display:flex;gap:7px;align-items:baseline}
 .xt{margin-left:auto;flex:0 0 auto;font-size:10px;color:var(--muted);cursor:help}
 .colbody li.sub{padding-left:22px;border-left:2px solid var(--line);margin-left:14px}
 .tick{flex:0 0 auto;width:8px;height:8px;border-radius:2px;border:1.5px solid var(--muted);
   position:relative;top:0}
 li.cov{background:var(--covbg)} li.cov .tick{background:var(--cov);border-color:var(--cov)}
 li.gap .tick{border-color:var(--gap)}
 li.ign{color:var(--muted);text-decoration:line-through}
 li a{color:inherit;text-decoration:none}
 li .tid{font-weight:650;letter-spacing:.01em}
 li .nm{color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
 li.cov .nm{color:var(--ink)}
 .legend{margin:0;font-size:11px;color:var(--muted)}
 .legend span{padding:3px 9px;border:1px solid var(--line);border-radius:3px;margin-right:8px;font-weight:600}
 .legend .cov{background:var(--covbg);color:var(--cov);border-color:var(--cov)}
 .legend .gap{background:var(--gapbg);color:var(--gap);border-color:var(--gap)}
 .legend .ign{color:var(--muted)}
 .dim{opacity:.14}
 .collapsed{opacity:.55}
 .eye{display:none}
 @media print{
   body{padding:0}
   .controls,.exportbtn,.gaptoggle,.topscroll{display:none}
   .rack{flex-wrap:wrap;overflow:visible}
   .col{break-inside:avoid}
 }
"""
        n_tactics = {tid: len(t.get("tactics", [])) for tid, t in db.techniques.items()}

        def _report_li(t: str, n: str, s: str, u: str, sub: bool) -> str:
            safe = n.replace(chr(34), "")
            extra = ""
            k = n_tactics.get(t, 1)
            if k > 1:
                extra = (
                    f'<span class="xt" title="This technique spans {k} tactics '
                    f'and appears in each of their columns">&#x29C9;</span>'
                )
            cls = f"{s} sub" if sub else s
            return (
                f'<li class="{cls}" data-tid="{t}" data-name="{safe}" title="{t} — {safe}">'
                f'<span class="tick"></span>'
                f'<a href="{u}" target="_blank" class="mono tid">{t}</a>'
                f'<span class="nm">{safe}</span>{extra}</li>'
            )

        cols = []
        for tactic, info in tactics.items():
            items = by_tactic.get(tactic, [])
            # Group sub-techniques under their parent, preserving ID order.
            parents: Dict[str, list] = {}
            direct: Dict[str, tuple] = {}
            for (t, n, s, u) in sorted(items, key=lambda x: x[0]):
                root = t.split(".", 1)[0]
                if "." in t:
                    parents.setdefault(root, []).append((t, n, s, u))
                else:
                    direct[root] = (t, n, s, u)
                    parents.setdefault(root, [])
            lis = []
            for root in sorted(parents):
                subs = parents[root]
                if root in direct:
                    t, n, s, u = direct[root]
                    lis.append(_report_li(t, n, s, u, sub=False))
                for (t, n, s, u) in subs:
                    lis.append(_report_li(t, n, s, u, sub=True))
            body_id = f"body-{tactic}"
            pctw = int(info["ratio"] * 100)
            cols.append(
                f'<div class="col">'
                f'<div class="colhead collapse-trigger" data-target="{body_id}">'
                f'<div class="tname">{info["name"]}</div>'
                f'<div class="tmeta"><span class="mono">{info["covered"]}/{info["total"]}</span>'
                f'<span>{info["ratio"]*100:.0f}%</span></div>'
                f'<div class="inkbar"><i style="width:{pctw}%"></i></div>'
                f'</div><ul class="colbody" id="{body_id}">{"".join(lis)}</ul></div>'
            )
        body_html = (
            '<div class="topscroll" id="topscroll" aria-hidden="true"><div></div></div>'
            f'<div class="rack" id="rack">{"".join(cols)}</div>'
        )

    else:  # heat
        css = base_css + """
 .heat{display:flex;flex-direction:column;gap:3px}
 .hrow{display:flex;align-items:center;gap:3px}
 .hlabel{width:210px;font-size:12px;color:#cdd;flex:0 0 auto;display:flex;justify-content:space-between;align-items:center;gap:6px}
 .hcells{display:flex;flex-wrap:wrap;gap:3px}
 .hcell{width:16px;height:16px;border-radius:3px}
 .hcell.cov{background:#27ae60}
 .hcell.gap{background:#7f1d2e}
 .hcell.ign{background:#3a3a3a}
"""
        rows = []
        for tactic, info in tactics.items():
            cells = "".join(
                f'<span class="hcell {s}" data-tid="{t}" data-name="{n.replace(chr(34), "")}" title="{t} — {n}"></span>'
                for (t, n, s, u) in sorted(by_tactic.get(tactic, []), key=lambda x: x[0])
            )
            body_id = f"body-{tactic}"
            area_id = f"area-{tactic}"
            rows.append(
                f'<div class="hrow-wrap">'
                f'<button class="eye" data-toggle="{area_id}" title="hide/show area">👁</button>'
                f'<div class="hrow" id="{area_id}">'
                f'<div class="hlabel collapse-trigger" data-target="{body_id}">'
                f'<span>{info["name"]}</span></div>'
                f'<div class="hcells" id="{body_id}">{cells}</div></div></div>'
            )
        body_html = f'<div class="heat">{"" .join(rows)}</div>'

    # ATT&CK Navigator layer JSON (embedded for the Export button).
    # "layer" / "navigator" versions are required for Navigator to accept the
    # file; the ATT&CK content version string is informative.
    layer = {
        "name": "attack-mapper coverage",
        "versions": {"attack": db.version, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "techniques": [
            {
                "techniqueID": tid,
                "color": "#27ae60" if tid in report.covered else "#7f1d2e",
                "comment": (report.db.technique_name(tid) or ""),
                "enabled": tid not in report.ignored,
            }
            for tid in report.in_scope_techniques
        ],
    }
    layer_json = json.dumps(layer)

    # Two ranked lists:
    #  - TOP GAPS: tactics with the most uncovered techniques (biggest blind spot).
    #  - TOP COVERED: tactics with the most covered techniques (what you HAVE).
    uncovered = lambda info: info["total"] - info["covered"]
    gaps_ranked = sorted(
        (kv for kv in tactics.items() if uncovered(kv[1]) > 0),
        key=lambda kv: (uncovered(kv[1]), -kv[1]["total"]),
        reverse=True,
    )
    covered_ranked = sorted(
        (kv for kv in tactics.items() if kv[1]["covered"] > 0),
        key=lambda kv: (kv[1]["covered"], kv[1]["ratio"]),
        reverse=True,
    )

    def _items(ranked, mode):
        out = []
        for t, info in ranked[:5]:
            if mode == "gaps":
                pct = int((1 - info["ratio"]) * 100)
                label = f'{uncovered(info)} gaps'
                color = "linear-gradient(90deg,#c0392b,#e67e22)"
            else:
                pct = int(info["ratio"] * 100)
                label = f'{info["covered"]}/{info["total"]}'
                color = "linear-gradient(90deg,#1f6f3f,#2ecc71)"
            out.append(
                f'<li><span class="gname">{info["name"]}</span>'
                f'<span class="gbar"><i style="width:{pct}%;background:{color}"></i></span>'
                f'<span class="gcnt">{label}</span></li>'
            )
        return "".join(out)

    gap_items = _items(gaps_ranked, "gaps")
    cov_items = _items(covered_ranked, "covered")
    gaps_html = (
        '<div class="gaps-card">'
        '<div class="gaps-head">'
        '<span class="gaps-title">Top coverage gaps</span>'
        '<button id="gaptoggle" class="gaptoggle" title="Switch between gaps and covered">'
        "show: what&rsquo;s missing ▸ what I have</button>"
        "</div>"
        f'<ul class="gaps-list" id="gaps-list">{gap_items}</ul>'
        f'<ul class="gaps-list" id="cov-list" style="display:none">{cov_items}</ul>'
        '<div class="gaps-hint" id="gaps-hint">Tactics with the most uncovered techniques '
        "&mdash; best candidates for new detections.</div>"
        '<div class="gaps-hint" id="cov-hint" style="display:none">Tactics with the most '
        "covered techniques &mdash; your current detection strengths.</div>"
        "</div>"
    )

    n_cov = len(report.covered_in_scope)
    meta = (
        f"{n_cov}/{report.total_techniques} techniques covered "
        f"({report.coverage_ratio*100:.1f}%) &middot; {report.rule_count} rules &middot; "
        f'{db.version}{(" &middot; " + scope) if scope else ""}'
    )
    if style == "report":
        header_html = (
            '<div class="masthead"><div>'
            '<div class="eyebrow">Detection engineering &middot; coverage dossier</div>'
            "<h1>MITRE ATT&amp;CK Detection Coverage</h1>"
            f'<p class="summary">{meta}</p>'
            "</div>"
            f'<div class="stamp mono"><b>{report.coverage_ratio*100:.1f}%</b>'
            f"<span>{n_cov} of {report.total_techniques} in scope</span></div>"
            "</div>"
        )
    else:
        header_html = (
            "<h1>MITRE ATT&CK Detection Coverage</h1>"
            f'<p class="summary">{meta}</p>'
        )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>ATT&CK Coverage Report</title><style>{css}</style></head><body>
{header_html}
<div class="controls">
  <input id="search" type="text" placeholder="Search technique (e.g. T1059 or PowerShell)" />
  <span id="searchstatus"></span>
  <button id="exportlayer" class="exportbtn" title="Export ATT&CK Navigator layer (.json)">&#8595; Export layer</button>
  {_legend_html()}
</div>
{gaps_html}
<script type="application/json" id="layerdata">{layer_json}</script>
{body_html}
{INTERACTIVE_JS}
</body></html>"""
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return out_path
