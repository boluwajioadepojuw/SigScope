"""Sigma rule scanner.

Walks Sigma YAML files and pulls out the detection-relevant bits the rest of
the tool needs: rule title, logsource category, MITRE technique references
(from tags and from the references list) and a human-readable detection
summary.

scan_rules() never hides a broken file: unparseable rules are reported in
the returned error list so callers (the CLI) can warn or fail on them.
"""


from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass, field

import yaml

_TECH_RE = re.compile(r"(?:attack\.|techniques/)?(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)
_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


@dataclass
class ScannedRule:
    path: str
    title: str
    category: str
    techniques: list[str] = field(default_factory=list)
    summary: str = ""


def _walk_files(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        if os.path.isdir(p):
            out += sorted(glob.glob(os.path.join(p, "*.yml")) + glob.glob(os.path.join(p, "*.yaml")))
        else:
            out += sorted(glob.glob(p))
    return list(dict.fromkeys(out))


def _pull_techniques(doc: dict) -> list[str]:
    found: list[str] = []
    seen = set()
    for tag in doc.get("tags") or []:
        m = _TAG_RE.match(str(tag))
        if m:
            tid = m.group(1).upper()
            if tid not in seen:
                seen.add(tid)
                found.append(tid)
    for ref in doc.get("references") or []:
        for m in _TECH_RE.finditer(str(ref)):
            tid = m.group(1).upper()
            if tid not in seen:
                seen.add(tid)
                found.append(tid)
    return found


def scan_rule_file(path: str) -> ScannedRule:
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    logsource = doc.get("logsource") or {}
    category = str(logsource.get("category") or logsource.get("product") or "unknown")
    det = doc.get("detection") or {}
    cond = str(det.get("condition") or "unknown")
    return ScannedRule(
        path=path,
        title=str(doc.get("title") or os.path.basename(path)),
        category=category,
        techniques=_pull_techniques(doc),
        summary=cond,
    )


def scan_rules(paths: list[str]) -> tuple[list[ScannedRule], list[tuple[str, str]]]:
    """Scan every file under paths.

    Returns (rules, errors): errors is a list of (path, message) for
    files that could not be parsed. Broken rules are never silently
    dropped from the coverage picture.
    """
    rules: list[ScannedRule] = []
    errors: list[tuple[str, str]] = []
    for f in _walk_files(paths):
        try:
            rules.append(scan_rule_file(f))
        except (OSError, ValueError, TypeError, yaml.YAMLError) as exc:
            errors.append((f, str(exc)))
    return rules, errors
