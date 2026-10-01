"""CLI entry point for sig-scope."""

from __future__ import annotations

import argparse
import json
import os
import sys

from .attck import AttackMap
from .gate import evaluate
from .out import STYLES, badge, csv_summary, gap_workbook, html_report, json_summary, terminal
from .scanner import scan_rules


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sig-scope",
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
    p.add_argument("--csv", metavar="PATH", default=None, help="Also write a CSV of covered techniques to PATH.")
    p.add_argument("--min-coverage", type=int, default=0, metavar="PCT", help="Fail (exit 2) when coverage is below this percentage.")
    p.add_argument("--gaps", metavar="PATH", default=None, help="Write a Markdown workbook of uncovered techniques to PATH.")
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
    if args.gaps:
        with open(args.gaps, "w", encoding="utf-8") as fh:
            fh.write(gap_workbook(report))
        print(f"Gap workbook written to: {os.path.abspath(args.gaps)}")
    if args.csv:
        with open(args.csv, "w", encoding="utf-8") as fh:
            fh.write(csv_summary(report))
        print(f"CSV written to: {os.path.abspath(args.csv)}")
    if args.badge:
        with open(args.badge, "w", encoding="utf-8") as fh:
            fh.write(badge(report))
        print(f"Badge written to: {os.path.abspath(args.badge)}")
    if not report.covered_count:
        return 1
    if args.min_coverage:
        pct = round(report.covered_count / report.total_count * 100) if report.total_count else 0
        if pct < args.min_coverage:
            print(f"Gate failed: {pct}% covered, threshold is {args.min_coverage}%", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
