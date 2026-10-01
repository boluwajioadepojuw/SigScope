"""Coverage computation: which techniques are covered, where the gaps are."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .attck import AttackMap
from .scanner import ScannedRule


def _in_scope(token: str, include: Optional[Set[str]], ignore: Optional[Set[str]]) -> bool:
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
    covered: Dict[str, List[str]] = field(default_factory=dict)
    skipped: List[str] = field(default_factory=list)
    unlinked: List[str] = field(default_factory=list)
    gaps: List = field(default_factory=list)

    @property
    def covered_count(self) -> int:
        return len(self.covered)

    @property
    def total_count(self) -> int:
        return len(self.mapping.techniques)


def evaluate(rules: List[ScannedRule], mapping: AttackMap,
             include: Optional[Set[str]] = None,
             ignore: Optional[Set[str]] = None) -> GateReport:
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
    return rep
