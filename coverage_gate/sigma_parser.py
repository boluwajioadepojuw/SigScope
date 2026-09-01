"""Parse Sigma rules and extract referenced MITRE ATT&CK techniques.

Sigma rules are YAML files. ATT&CK technique IDs (e.g. ``T1059``) are commonly
referenced in a few places:

* ``tags:`` list, as ``attack.<id>`` (the Sigma convention) or raw ``T1059``.
* ``references:`` list of URLs containing ``attack.mitre.org/techniques/Txxxx``.
* Free text in the ``description:`` / ``logsource:`` (rare, optional).

This module supports both the canonical ``attack.*`` tag form and URL
extraction so it works with rules written by different teams.
"""

from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass, field
from typing import Iterable

try:
    import yaml
except ImportError as exc:  # pragma: no cover - surfaced to the user clearly
    raise SystemExit(
        "PyYAML is required. Install it with: pip install pyyaml"
    ) from exc


# Matches T<4 digits> optionally followed by .<2-3 digits> (sub-technique)
TECH_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{1,3})?\b", re.IGNORECASE)
# MITRE URLs use slashes (attack.mitre.org/techniques/T1059/001), so accept
# both '.' and '/' as the sub-technique separator and normalize to '.'.
URL_RE = re.compile(r"attack\.mitre\.org/techniques/(T\d{4}(?:[./]\d{1,3})?)", re.IGNORECASE)


@dataclass
class ParsedRule:
    """A Sigma rule reduced to the data we care about for coverage mapping."""

    path: str
    title: str | None = None
    technique_ids: set[str] = field(default_factory=set)

    @property
    def techniques(self) -> list[str]:
        return sorted(self.technique_ids, key=lambda t: (len(t), t))


def _extract_from_tags(tags: Iterable[str]) -> set[str]:
    found = set()
    for tag in tags or []:
        if not isinstance(tag, str):
            continue
        # Canonical Sigma form: attack.t1059 / attack.t1059.001 (case-insensitive)
        if tag.lower().startswith("attack."):
            cand = tag.split(".", 1)[1]
            m = TECH_ID_RE.search(cand)
            if m:
                found.add(m.group(0).upper())
        else:
            m = TECH_ID_RE.search(tag)
            if m:
                found.add(m.group(0).upper())
    return found


def _extract_from_references(references: Iterable) -> set[str]:
    found = set()
    for ref in references or []:
        url = ref.get("url") if isinstance(ref, dict) else str(ref)
        if not url:
            continue
        for m in URL_RE.finditer(url):
            # Normalize a slash separator (T1059/001) to a dot (T1059.001)
            found.add(m.group(1).upper().replace("/", "."))
    return found


def parse_rule_text(text: str, path: str = "<string>") -> ParsedRule:
    """Parse a single Sigma rule from a YAML string."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return ParsedRule(path=path, title=None, technique_ids=set())

    if not isinstance(doc, dict):
        return ParsedRule(path=path, title=None, technique_ids=set())

    rule = ParsedRule(path=path, title=doc.get("title"))

    found = set()
    found |= _extract_from_tags(doc.get("tags", []))
    found |= _extract_from_references(doc.get("references", []))
    # Fallback: scan description for raw technique IDs
    desc = doc.get("description") or ""
    if isinstance(desc, str):
        found |= {m.group(0).upper() for m in TECH_ID_RE.finditer(desc)}

    rule.technique_ids = found
    return rule


def parse_rule_file(path: str) -> ParsedRule:
    """Parse a Sigma rule from a file on disk."""
    with open(path, "r", encoding="utf-8") as fh:
        return parse_rule_text(fh.read(), path=path)


def parse_rules(paths: Iterable[str]) -> list[ParsedRule]:
    """Parse many rule files. ``paths`` may include glob patterns."""
    resolved: list[str] = []
    for p in paths:
        if any(ch in p for ch in "*?[]"):
            resolved.extend(sorted(glob.glob(p, recursive=True)))
        elif os.path.isdir(p):
            resolved.extend(sorted(glob.glob(os.path.join(p, "**", "*.yml"), recursive=True)))
            resolved.extend(sorted(glob.glob(os.path.join(p, "**", "*.yaml"), recursive=True)))
        elif os.path.isfile(p):
            resolved.append(p)
    # De-duplicate while preserving order
    seen, rules = set(), []
    for fp in resolved:
        if fp in seen:
            continue
        seen.add(fp)
        rules.append(parse_rule_file(fp))
    return rules
