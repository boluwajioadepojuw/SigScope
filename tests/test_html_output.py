"""Tests that the generated HTML actually works in a browser-like sense.

These catch the class of bug where a stray brace in the inline <script>
silently kills ALL interactivity (search, export, toggles) at once.

NOTE: we shell out to the real CLI (``python -m attack_mapper.cli``) to
generate the HTML because importing the package directly is flaky in this
sandbox. The CLI path is the one users actually run, so it's a fine test.
"""
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES = os.path.join(REPO, "rules")


def _render(tmp_path, style):
    out = str(tmp_path / f"cov_{style}.html")
    cli = [
        sys.executable, "-m", "attack_mapper.cli",
        RULES, "--html", out, "--style", style,
    ]
    r = subprocess.run(cli, capture_output=True, text=True, cwd=REPO, timeout=60)
    assert r.returncode == 0, f"{style}: CLI failed: {r.stderr.strip()}"
    assert os.path.exists(out)
    return out


def _extract_js(html):
    m = re.search(r"<script>(.*?)</script>", html, re.S)
    assert m, "no <script> block found in generated HTML"
    return m.group(1)


def test_js_syntax_valid(tmp_path):
    """The inline JS must be syntactically valid (node --check)."""
    if not shutil.which("node"):
        pytest.skip("node not installed; cannot validate JS syntax")
    for style in ("matrix", "rows", "heat"):
        out = _render(tmp_path, style)
        html = open(out, encoding="utf-8").read()
        js = _extract_js(html)
        probe = tmp_path / f"_{style}.js"
        probe.write_text(js, encoding="utf-8")
        r = subprocess.run(
            ["node", "--check", str(probe)],
            capture_output=True, text=True,
        )
        assert r.returncode == 0, (
            f"{style}: JS syntax error: {r.stderr.strip()}"
        )


def test_layerdata_is_valid_json(tmp_path):
    """The embedded ATT&CK Navigator layer must parse as JSON."""
    out = _render(tmp_path, "matrix")
    html = open(out, encoding="utf-8").read()
    m = re.search(
        r'<script type="application/json" id="layerdata">(.*?)</script>',
        html, re.S,
    )
    assert m, "no layerdata script block"
    data = json.loads(m.group(1))  # raises if invalid
    assert data["techniques"], "layer has no techniques"


def test_search_and_toggle_nodes_present(tmp_path):
    """Search box, toggle button and both gap/covered lists exist."""
    out = _render(tmp_path, "matrix")
    html = open(out, encoding="utf-8").read()
    assert 'id="search"' in html
    assert 'id="gaptoggle"' in html
    assert 'id="gaps-list"' in html
    assert 'id="cov-list"' in html
    assert 'id="exportlayer"' in html
