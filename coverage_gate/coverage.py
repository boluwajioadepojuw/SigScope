"""Compute detection coverage and gaps against the ATT&CK matrix.

Supports *scope filters*:

* ``include`` — restrict the analysis to a set of techniques / tactics. Only
  those are counted toward totals and shown as in-scope.
* ``ignore``  — explicitly exclude techniques / tactics (e.g. deprecated or
  out-of-scope for your environment). Ignored items are reported separately.

A token in either set matches if it equals a technique ID, is a prefix of a
technique ID (so ``T1059`` covers ``T1059.001``), or equals a tactic
shortname. An empty ``include`` means "everything is in scope".
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set

from .attack_loader import AttackDB
from .sigma_parser import ParsedRule


def _matches(token: str, include: Set[str]) -> bool:
    """True if ``token`` (technique id or tactic) is covered by ``include``."""
    token = token.upper()
    for inc in include:
        inc = inc.upper()
        if token == inc or token.startswith(inc + "."):
            return True
    return False


def _normalize_scope(tokens: Optional[Iterable[str]], db: AttackDB) -> Set[str]:
    """Uppercase scope tokens, mapping TA tactic IDs to tactic shortnames.

    ``TA0002`` → ``EXECUTION`` so it matches technique tactic lists the same
    way the shortname form does. Unknown tokens pass through unchanged.
    """
    return {db.resolve_tactic_token(s).upper() for s in (tokens or [])}


@dataclass
class CoverageReport:
    """Result of mapping a set of rules onto ATT&CK, optionally scoped."""

    db: AttackDB
    covered: Dict[str, List[str]] = field(default_factory=dict)   # technique_id -> [rule paths]
    unknown: List[str] = field(default_factory=list)             # technique ids not in ATT&CK
    unmapped_rules: List[ParsedRule] = field(default_factory=list)
    rule_count: int = 0
    include: Set[str] = field(default_factory=set)
    ignore: Set[str] = field(default_factory=set)
    ignored: List[str] = field(default_factory=list)            # in-scope tokens explicitly ignored
    out_of_scope: List[str] = field(default_factory=list)       # not matched by include

    @property
    def covered_techniques(self) -> List[str]:
        return sorted(self.covered.keys(), key=lambda t: (len(t), t))

    @property
    def in_scope_techniques(self) -> List[str]:
        """All ATT&CK techniques that are in scope (after include/ignore)."""
        result = []
        for tid, tech in self.db.techniques.items():
            if self._in_scope(tid, tech):
                result.append(tid)
        return sorted(result, key=lambda t: (len(t), t))

    def _in_scope(self, tid: str, tech: dict) -> bool:
        if self.include and not (
            _matches(tid, self.include)
            or any(_matches(t, self.include) for t in tech.get("tactics", []))
        ):
            return False
        if self.ignore and (
            _matches(tid, self.ignore)
            or any(_matches(t, self.ignore) for t in tech.get("tactics", []))
        ):
            return False
        return True

    @property
    def covered_in_scope(self) -> List[str]:
        """Covered techniques that are also in scope (the ratio numerator).

        A technique detected by a rule but excluded via ``--include`` /
        ``--ignore`` is still *recorded* in ``covered`` (you did detect it),
        but it must not count toward the scoped coverage ratio.
        """
        in_scope = set(self.in_scope_techniques)
        return [t for t in self.covered_techniques if t in in_scope]

    @property
    def total_techniques(self) -> int:
        """In-scope techniques (the denominator for the coverage ratio)."""
        return len(self.in_scope_techniques)

    @property
    def coverage_ratio(self) -> float:
        total = self.total_techniques
        return (len(self.covered_in_scope) / total) if total else 0.0

    def tactics_coverage(self) -> Dict[str, dict]:
        """Per-tactic coverage: how many in-scope techniques covered vs total."""
        total_by_tactic: Dict[str, int] = defaultdict(int)
        covered_by_tactic: Dict[str, int] = defaultdict(int)

        for tid, tech in self.db.techniques.items():
            if not self._in_scope(tid, tech):
                continue
            for tactic in tech.get("tactics", []):
                total_by_tactic[tactic] += 1
                # Count a covered technique in EVERY tactic it belongs to.
                # Each tactic row has its own denominator, so this is not
                # double counting — it's how the ATT&CK matrix itself works:
                # covering T1053.005 protects Execution AND Persistence AND
                # Privilege Escalation, and all three bars should say so.
                if tid in self.covered:
                    covered_by_tactic[tactic] += 1

        result: Dict[str, dict] = {}
        for tactic, total in sorted(total_by_tactic.items(), key=lambda x: -x[1]):
            c = covered_by_tactic.get(tactic, 0)
            result[tactic] = {
                "name": self.db.tactic_name(tactic),
                "covered": c,
                "total": total,
                "ratio": (c / total) if total else 0.0,
            }
        return result


def build_report(
    rules: List[ParsedRule],
    db: AttackDB,
    include: Optional[Iterable[str]] = None,
    ignore: Optional[Iterable[str]] = None,
) -> CoverageReport:
    """Map parsed Sigma rules onto ATT&CK and produce a coverage report."""
    report = CoverageReport(
        db=db,
        rule_count=len(rules),
        include=_normalize_scope(include, db),
        ignore=_normalize_scope(ignore, db),
    )
    covered: Dict[str, List[str]] = defaultdict(list)
    seen_unknown: set = set()

    for rule in rules:
        if not rule.technique_ids:
            report.unmapped_rules.append(rule)
            continue
        for tid in rule.technique_ids:
            if db.valid_technique(tid):
                covered[tid].append(rule.path)
            else:
                seen_unknown.add(tid)

    # Inherit coverage to parent techniques so the number shown ("N covered")
    # matches the green cells in the HTML: a covered sub-technique also lights
    # up its parent technique.
    for tid in list(covered.keys()):
        if "." in tid:
            parent = tid.split(".", 1)[0]
            if parent in db.techniques and parent not in covered:
                covered[parent] = list(covered[tid])

    report.covered = dict(covered)
    report.unknown = sorted(seen_unknown, key=lambda t: (len(t), t))

    # Classify each ATT&CK technique as ignored or out-of-scope (for reporting).
    for tid, tech in db.techniques.items():
        if tid in report.covered or tid in seen_unknown:
            continue
        is_ignored = bool(report.ignore) and (
            _matches(tid, report.ignore)
            or any(_matches(t, report.ignore) for t in tech.get("tactics", []))
        )
        if is_ignored:
            report.ignored.append(tid)
        elif report.include and not (
            _matches(tid, report.include)
            or any(_matches(t, report.include) for t in tech.get("tactics", []))
        ):
            report.out_of_scope.append(tid)
    report.ignored.sort(key=lambda t: (len(t), t))
    report.out_of_scope.sort(key=lambda t: (len(t), t))
    return report
