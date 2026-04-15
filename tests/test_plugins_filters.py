"""Tests for filters, inherited coverage, and the extra plugins."""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from attack_mapper import (  # noqa: E402
    AttackDB,
    build_report,
    parse_rule_text,
    render_badge,
    render_json,
)
from tests.fixtures import ATTACK_FIXTURE  # noqa: E402


@pytest.fixture
def db() -> AttackDB:
    return AttackDB(
        version=ATTACK_FIXTURE["version"],
        tactics=ATTACK_FIXTURE["tactics"],
        techniques=ATTACK_FIXTURE["techniques"],
    )


def _rules():
    return [
        parse_rule_text("title: a\ntags:\n  - attack.t1059.001\n", path="a.yml"),
        parse_rule_text("title: b\nreferences:\n  - url: https://attack.mitre.org/techniques/T1505/003\n", path="b.yml"),
    ]


def test_include_narrows_scope(db):
    report = build_report(_rules(), db, include=["T1059"])
    # Only T1059 (and sub T1059.001) in scope -> T1505.003 is out of scope
    assert "T1059.001" in report.in_scope_techniques
    assert "T1059" in report.in_scope_techniques
    # T1505.003 is detected (raw) but is OUT of the T1059 scope
    assert "T1505.003" not in report.in_scope_techniques
    assert "T1505.003" in report.covered_techniques  # raw detection still recorded
    # covered techniques are not listed as out_of_scope; only the truly
    # uncovered, non-included ones (T1003, T1053.005) are.
    assert "T1003" in report.out_of_scope
    assert report.total_techniques == 2  # T1059 + T1059.001


def test_ignore_excludes(db):
    # T1505.003 is covered -> it counts as covered, not "ignored" (coverage wins).
    # Use a NON-covered technique to verify the ignore path.
    rules = [parse_rule_text("title: a\ntags:\n  - attack.t1059.001\n", path="a.yml")]
    report = build_report(rules, db, ignore=["T1505"])
    assert "T1505.003" in report.ignored
    assert "T1505.003" not in report.in_scope_techniques
    # total = all techniques (5) minus the 1 ignored
    assert report.total_techniques == 4


def test_parent_inherits_coverage(db):
    # T1059.001 covered -> parent T1059 is counted as covered too (number matches cells)
    report = build_report(_rules(), db)
    assert "T1059" in report.covered_techniques
    # sub-technique + its parent both counted, so count > raw sub-techniques
    assert report.covered_techniques.count("T1059.001") == 1
    assert report.covered_techniques.count("T1059") == 1


def test_badge_svg(db):
    report = build_report(_rules(), db)
    svg = render_badge(report)
    assert svg.startswith("<svg")
    assert "ATT" in svg


def test_json_summary(db):
    report = build_report(_rules(), db, ignore=["T1505"])
    data = render_json(report)
    assert '"covered"' in data
    assert '"ignored_count"' in data
