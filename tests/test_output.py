from coverage_gate.attck import AttackMap
from coverage_gate.gate import evaluate
from coverage_gate.out import badge, html_report, json_summary, navigator_layer, terminal
from coverage_gate.scanner import ScannedRule


def build_report():
    m = AttackMap.build()
    rule = ScannedRule(path="r.yml", title="t", category="c", techniques=["T1059.001"], summary="s")
    return evaluate([rule], m)


def test_terminal_mentions_covered():
    text = terminal(build_report())
    assert "T1059.001" in text
    assert "covered" in text


def test_json_summary_shape():
    import json
    data = json.loads(json_summary(build_report()))
    assert data["covered_count"] == 1
    assert "T1059.001" in data["covered_techniques"]


def test_badge_svg():
    svg = badge(build_report())
    assert svg.startswith("<svg")
    assert "coverage" in svg


def test_html_styles_render():
    rep = build_report()
    for style in ("matrix", "rows", "heat", "report"):
        doc = html_report(rep, style)
        assert "<html" in doc
        assert "SigScope" in doc


def test_navigator_layer_shape():
    import json
    layer = json.loads(navigator_layer(build_report()))
    assert layer["domain"] == "enterprise-attack"
    covered = {t["techniqueID"] for t in layer["techniques"]}
    assert "T1059.001" in covered
    assert any(t["score"] == 0 for t in layer["techniques"])
