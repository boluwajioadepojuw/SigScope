from coverage_gate.attck import AttackMap
from coverage_gate.gate import evaluate
from coverage_gate.scanner import ScannedRule


def make_rule(tid):
    return ScannedRule(path="r.yml", title="t", category="c", techniques=[tid], summary="s")


def test_covered_count():
    m = AttackMap.build()
    rep = evaluate([make_rule("T1059.001"), make_rule("T1053.005")], m)
    assert rep.covered_count == 2
    assert "T1059.001" in rep.covered


def test_ignore_scope():
    m = AttackMap.build()
    rep = evaluate([make_rule("T1059.001")], m, ignore={"T1059"})
    assert rep.covered_count == 0


def test_include_scope():
    m = AttackMap.build()
    rep = evaluate([make_rule("T1059.001"), make_rule("T1033")], m, include={"T1059"})
    assert rep.covered_count == 1
    assert "T1033" in rep.skipped


def test_unlinked_id():
    m = AttackMap.build()
    rep = evaluate([make_rule("T9999.999")], m)
    assert rep.unlinked == ["T9999.999"]
