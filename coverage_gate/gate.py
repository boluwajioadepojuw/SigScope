"""Coverage computation: which techniques are covered, where the gaps are."""

from __future__ import annotations

from dataclasses import dataclass, field

from .attck import AttackMap
from .scanner import ScannedRule


def _in_scope(token: str, include: set[str] | None, ignore: set[str] | None) -> bool:
    upper = token.upper()
    if ignore:
        for bad in ignore:
            b = bad.upper()
            if upper == b or upper.startswith(b + "."):
                return False
    if not include:
        return True
    for good in include:
        g = good.upper()
        if upper == g or upper.startswith(g + "."):
            return True
    return False


@dataclass
class GateReport:
    mapping: AttackMap
    covered: dict[str, list[str]] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    unlinked: list[str] = field(default_factory=list)
    gaps: list = field(default_factory=list)
    tactic_coverage: dict[str, int] = field(default_factory=dict)

    @property
    def covered_count(self) -> int:
        return len(self.covered)

    @property
    def total_count(self) -> int:
        return len(self.mapping.techniques)


def _expand_tokens(tokens: set[str] | None, mapping: AttackMap) -> set[str] | None:
    """Expand tactic-name tokens into their technique IDs.

    --include execution and --include T1059 both work: a token that
    matches a tactic name becomes the set of technique IDs in that
    tactic; any other token is kept as a technique-prefix token.
    """
    if not tokens:
        return None
    out: set[str] = set()
    for token in tokens:
        up = token.upper()
        matched = False
        for tid in mapping.techniques:
            tech = mapping.lookup(tid)
            if tech is not None and tech.tactic.upper() == up:
                out.add(tid)
                matched = True
        if not matched:
            out.add(up)
    return out


def evaluate(rules: list[ScannedRule], mapping: AttackMap,
             include: set[str] | None = None,
             ignore: set[str] | None = None) -> GateReport:
    include = _expand_tokens(include, mapping)
    ignore = _expand_tokens(ignore, mapping)
    rep = GateReport(mapping=mapping)
    for rule in rules:
        for tid in rule.techniques:
            if not _in_scope(tid, include, ignore):
                rep.skipped.append(tid)
                continue
            if mapping.lookup(tid) is None:
                rep.unlinked.append(tid)
                continue
            rep.covered.setdefault(tid, []).append(rule.path)
    for tid in mapping.techniques:
        if _in_scope(tid, include, ignore) and tid not in rep.covered:
            tech = mapping.lookup(tid)
            if tech is not None:
                rep.gaps.append(tech)
    per_tactic: dict[str, list[str]] = {}
    for tid in mapping.techniques:
        if not _in_scope(tid, include, ignore):
            continue
        tech = mapping.lookup(tid)
        if tech is None:
            continue
        per_tactic.setdefault(tech.tactic, []).append(tid)
    for tactic, tids in per_tactic.items():
        covered = sum(1 for t in tids if t in rep.covered)
        rep.tactic_coverage[tactic] = round(covered / len(tids) * 100) if tids else 0
    return rep
