"""attack-mapper: map your Sigma detection rules onto the MITRE ATT&CK matrix."""

from .attack_loader import AttackDB, load_attack
from .coverage import CoverageReport, build_report
from .sigma_parser import (
    ParsedRule,
    parse_rule_file,
    parse_rule_text,
    parse_rules,
)
from .renderers import render_terminal, render_html, STYLES
from .plugins import render_badge, render_json

__version__ = "0.4.1"

__all__ = [
    "AttackDB",
    "load_attack",
    "CoverageReport",
    "build_report",
    "ParsedRule",
    "parse_rule_file",
    "parse_rule_text",
    "parse_rules",
    "render_terminal",
    "render_html",
    "STYLES",
    "render_badge",
    "render_json",
]