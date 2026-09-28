"""CLI entry point for coverage-gate."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .attck import AttackMap
from .gate import evaluate
from .out import STYLES, badge, html_report, json_summary, terminal
from .scanner import scan_rules


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="coverage-gate",
        description="Map your Sigma detection rules onto the MITRE ATT&CK matrix "
        "and find coverage gaps.",
    )
    p.add_argument("rules", nargs="+", help="Sigma rule file(s), directory(ies), or glob pattern(s).")
    p.add_argument("--db", default=None, help="Path to an optional ATT&CK JSON override.")
    p.add_argument("--html", metavar="PATH", default=None, help="Write a standalone HTML report to PATH.")
    p.add_argument("--style", choices=STYLES, default="matrix", help="HTML layout: matrix, rows, heat or report.")
    p.add_argument("--include", nargs="*", default=None, metavar="TOKEN", help="Only count techniques/tactics matching these tokens.")
    p.add_argument("--ignore", nargs="*", default=None, metavar="TOKEN", help="Exclude these techniques/tactics from scope.")
    p.add_argument("--json", metavar="PATH", default=None, help="Also write a JSON summary to PATH.")
    p.add_argument("--badge", metavar="PATH", default=None, help="Also write an SVG coverage badge to PATH.")
    p.add_argument("--quiet", action="store_true", help="Suppress the terminal table.")
    p.add_argument("--version", action="version", version="%(prog)s 0.5.0")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    overrides = None
    if args.db:
        with open(args.db, encoding="utf-8") as fh:
            overrides = json.load(fh)
    mapping = AttackMap.build(overrides)
    rules = scan_rules(args.rules)
    if not rules:
        print("No Sigma rules found at the given path(s).", file=sys.stderr)
        return 1
    report = evaluate(rules, mapping,
                      include=set(args.include or []),
                      ignore=set(args.ignore or []))
    if not args.quiet:
        print(terminal(report))
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html_report(report, args.style))
        print(f"\nHTML report written to: {os.path.abspath(args.html)}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(json_summary(report))
        print(f"JSON summary written to: {os.path.abspath(args.json)}")
    if args.badge:
        with open(args.badge, "w", encoding="utf-8") as fh:
            fh.write(badge(report))
        print(f"Badge written to: {os.path.abspath(args.badge)}")
    return 0 if report.covered_count else 1


if __name__ == "__main__":
    raise SystemExit(main())
