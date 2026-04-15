"""Regression tests for bugs found in code review.

Each test documents a bug that shipped in 0.1.0:

1. ``--include TA0002`` silently matched nothing — TA tactic IDs were never
   mapped to tactic shortnames, even though the README promised they work.
2. ``coverage_ratio`` used the *unscoped* covered count as numerator, so a
   restrictive ``--include`` could report nonsense (covered > in-scope, or
   0% with covered techniques present).
3. Per-tactic coverage counted a covered technique only in its FIRST tactic,
   while the denominator counted it in EVERY tactic. A rule covering
   T1053.005 (execution + persistence + privilege-escalation) showed 0
   coverage for privilege-escalation — misleading for a SOC.
4. The STIX loader kept revoked/deprecated techniques, inflating the
   coverage denominator with techniques that no longer exist in ATT&CK.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from attack_mapper import AttackDB, build_report, parse_rule_text  # noqa: E402
from attack_mapper.attack_loader import _load_stix  # noqa: E402
from tests.fixtures import ATTACK_FIXTURE  # noqa: E402


@pytest.fixture
def db() -> AttackDB:
    return AttackDB(
        version=ATTACK_FIXTURE["version"],
        tactics=ATTACK_FIXTURE["tactics"],
        techniques=ATTACK_FIXTURE["techniques"],
    )


# --------------------------------------------------------------------------
# Bug 1: TA tactic IDs in --include / --ignore
# --------------------------------------------------------------------------

def test_include_accepts_ta_id(db):
    """--include TA0002 must behave exactly like --include execution."""
    rules = [parse_rule_text("title: a\ntags:\n  - attack.t1059.001\n", path="a.yml")]
    by_id = build_report(rules, db, include=["TA0002"])
    by_shortname = build_report(rules, db, include=["execution"])
    assert by_id.in_scope_techniques == by_shortname.in_scope_techniques
    assert by_id.total_techniques == 2  # T1059 + T1059.001
    assert by_id.coverage_ratio == by_shortname.coverage_ratio > 0


def test_ignore_accepts_ta_id(db):
    """--ignore TA0006 must exclude credential-access (id via URL fallback)."""
    rules = [parse_rule_text("title: a\ntags:\n  - attack.t1059.001\n", path="a.yml")]
    report = build_report(rules, db, ignore=["TA0006"])
    assert "T1003" in report.ignored
    assert "T1003" not in report.in_scope_techniques


# --------------------------------------------------------------------------
# Bug 2: coverage_ratio numerator must respect the scope
# --------------------------------------------------------------------------

def test_ratio_numerator_is_scoped(db):
    """A covered technique OUTSIDE the include scope must not inflate the ratio."""
    rules = [
        parse_rule_text("title: a\ntags:\n  - attack.t1059.001\n", path="a.yml"),
        # T1505.003 is covered but out of the persistence-only scope below? no —
        # it IS persistence. Use T1059.001 (execution) against a persistence scope.
    ]
    report = build_report(rules, db, include=["persistence"])
    # T1059/T1059.001 are covered but execution-only -> out of scope.
    assert report.covered  # raw detection recorded
    assert report.covered_in_scope == []
    assert report.coverage_ratio == 0.0


def test_ratio_counts_in_scope_covered(db):
    rules = [
        parse_rule_text("title: a\ntags:\n  - attack.t1059.001\n", path="a.yml"),
        parse_rule_text(
            "title: b\nreferences:\n  - url: https://attack.mitre.org/techniques/T1505/003\n",
            path="b.yml",
        ),
    ]
    report = build_report(rules, db, include=["persistence"])
    # In persistence scope: T1053.005 and T1505.003 -> 1 of 2 covered.
    assert report.covered_in_scope == ["T1505.003"]
    assert report.total_techniques == 2
    assert abs(report.coverage_ratio - 0.5) < 1e-9


# --------------------------------------------------------------------------
# Bug 3: covered techniques must count in EVERY tactic they belong to
# --------------------------------------------------------------------------

def test_multi_tactic_technique_counts_everywhere(db):
    """T1053.005 spans persistence + privilege-escalation; covering it must
    light up BOTH tactics, since both denominators include it."""
    rules = [parse_rule_text("title: a\ntags:\n  - attack.t1053.005\n", path="a.yml")]
    report = build_report(rules, db)
    tac = report.tactics_coverage()
    assert tac["persistence"]["covered"] == 1
    assert tac["privilege-escalation"]["covered"] == 1


# --------------------------------------------------------------------------
# Bug 4: revoked / deprecated techniques must not enter the DB
# --------------------------------------------------------------------------

STIX_MINI = {
    "type": "bundle",
    "objects": [
        {
            "type": "x-mitre-matrix",
            "name": "Enterprise ATT&CK test",
            "modified": "2026-04-28T00:00:00.000Z",
        },
        {
            "type": "x-mitre-tactic",
            "name": "Execution",
            "x_mitre_shortname": "execution",
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "TA0002",
                 "url": "https://attack.mitre.org/tactics/TA0002"}
            ],
        },
        {
            "type": "attack-pattern",
            "name": "Alive Technique",
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "execution"}],
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1059",
                 "url": "https://attack.mitre.org/techniques/T1059"}
            ],
        },
        {
            "type": "attack-pattern",
            "name": "Revoked Technique",
            "revoked": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1089",
                 "url": "https://attack.mitre.org/techniques/T1089"}
            ],
        },
        {
            "type": "attack-pattern",
            "name": "Deprecated Technique",
            "x_mitre_deprecated": True,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": "T1064",
                 "url": "https://attack.mitre.org/techniques/T1064"}
            ],
        },
    ],
}


def test_stix_loader_skips_revoked_and_deprecated(tmp_path):
    import json

    p = tmp_path / "mini-stix.json"
    p.write_text(json.dumps(STIX_MINI), encoding="utf-8")
    db = _load_stix(str(p))
    assert "T1059" in db.techniques
    assert "T1089" not in db.techniques
    assert "T1064" not in db.techniques
    # Tactic id captured for TA-token filters, version from the matrix object.
    assert db.tactics["execution"]["id"] == "TA0002"
    assert "Enterprise ATT&CK test" in db.version
