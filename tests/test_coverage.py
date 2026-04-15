"""Unit tests for attack-mapper."""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from attack_mapper import (  # noqa: E402
    AttackDB,
    build_report,
    parse_rule_text,
)
from tests.fixtures import ATTACK_FIXTURE  # noqa: E402


@pytest.fixture
def db() -> AttackDB:
    return AttackDB(
        version=ATTACK_FIXTURE["version"],
        tactics=ATTACK_FIXTURE["tactics"],
        techniques=ATTACK_FIXTURE["techniques"],
    )


def test_parse_attack_tag():
    rule = parse_rule_text(
        "title: x\ntags:\n  - attack.execution\n  - attack.t1059.001\n",
        path="r1.yml",
    )
    assert "T1059.001" in rule.technique_ids
    assert "T1059" not in rule.technique_ids  # sub-technique only, not parent


def test_parse_raw_tag():
    rule = parse_rule_text("title: x\ntags:\n  - T1053.005\n", path="r2.yml")
    assert rule.technique_ids == {"T1053.005"}


def test_parse_url_reference():
    rule = parse_rule_text(
        "title: x\nreferences:\n  - url: https://attack.mitre.org/techniques/T1505/003\n",
        path="r3.yml",
    )
    assert rule.technique_ids == {"T1505.003"}


def test_parse_unknown_ignored():
    rule = parse_rule_text(
        "title: x\ntags:\n  - attack.t9999.999\n", path="r4.yml"
    )
    assert rule.technique_ids == {"T9999.999"}


def test_parse_no_techniques():
    rule = parse_rule_text("title: x\ndetection:\n  selection: {}\n", path="r5.yml")
    assert rule.technique_ids == set()


def test_build_report_coverage(db):
    rules = [
        parse_rule_text("title: a\ntags:\n  - attack.t1059.001\n", path="a.yml"),
        parse_rule_text("title: b\nreferences:\n  - url: https://attack.mitre.org/techniques/T1505/003\n", path="b.yml"),
        parse_rule_text("title: c\ndetection:\n  selection: {}\n", path="c.yml"),
    ]
    report = build_report(rules, db)
    # T1059.001 and T1505.003 covered; parent T1059 exists in fixture so inherited.
    assert set(report.covered_techniques) == {"T1059", "T1059.001", "T1505.003"}
    assert len(report.unmapped_rules) == 1
    assert report.rule_count == 3
    # Sub-techniques AND inherited parents count toward tactic coverage
    tac = report.tactics_coverage()
    assert tac["execution"]["covered"] == 2   # T1059 + T1059.001 (both first-tactic=execution)
    assert tac["persistence"]["covered"] == 1  # T1505.003 (first-tactic=persistence)


def test_coverage_ratio(db):
    rules = [parse_rule_text("title: a\ntags:\n  - attack.t1059.001\n", path="a.yml")]
    report = build_report(rules, db)
    # 5 total techniques; T1059.001 + inherited parent T1059 = 2 covered -> 0.4
    assert abs(report.coverage_ratio - 0.4) < 1e-9


def test_unknown_reported(db):
    rules = [parse_rule_text("title: a\ntags:\n  - attack.t9999\n", path="a.yml")]
    report = build_report(rules, db)
    assert report.unknown == ["T9999"]
    assert report.covered == {}
