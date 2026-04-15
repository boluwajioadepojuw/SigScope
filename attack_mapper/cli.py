"""CLI entry point for attack-mapper."""

from __future__ import annotations

import argparse
import os
import sys

from .attack_loader import load_attack
from .coverage import build_report
from .renderers import render_terminal, render_html, STYLES
from .sigma_parser import parse_rules
from .plugins import render_badge, render_json


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="attack-mapper",
        description="Map your Sigma detection rules onto the MITRE ATT&CK matrix "
        "and find coverage gaps.",
    )
    p.add_argument(
        "rules",
        nargs="+",
        help="Sigma rule file(s), directory(ies), or glob pattern(s).",
    )
    p.add_argument("--db", default=None, help="Path to a compact ATT&CK DB JSON.")
    p.add_argument(
        "--html", metavar="PATH", default=None,
        help="Write a standalone HTML coverage report to PATH.",
    )
    p.add_argument(
        "--style", choices=STYLES, default="matrix",
        help="HTML layout: matrix (cards), rows (bars), or heat (dense).",
    )
    p.add_argument(
        "--include", nargs="*", default=None, metavar="TOKEN",
        help="Only count/show techniques or tactics matching these tokens "
             "(e.g. T1059 TA0002). Others are treated as out-of-scope.",
    )
    p.add_argument(
        "--ignore", nargs="*", default=None, metavar="TOKEN",
        help="Exclude these techniques/tactics from scope (e.g. T1003 Reconnaissance).",
    )
    p.add_argument(
        "--json", metavar="PATH", default=None,
        help="Also write a machine-readable JSON summary to PATH.",
    )
    p.add_argument(
        "--badge", metavar="PATH", default=None,
        help="Also write an SVG coverage badge to PATH (great for a README).",
    )
    p.add_argument("--quiet", action="store_true", help="Suppress the terminal table.")
    p.add_argument("--version", action="version", version="%(prog)s 0.4.1")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        db = load_attack(args.db)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    rules = parse_rules(args.rules)
    if not rules:
        print("No Sigma rules found at the given path(s).", file=sys.stderr)
        return 1

    report = build_report(rules, db, include=args.include, ignore=args.ignore)

    if not args.quiet:
        print(render_terminal(report))

    if args.html:
        out = render_html(report, args.html, style=args.style)
        print(f"\nHTML report written to: {os.path.abspath(out)}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(render_json(report))
        print(f"JSON summary written to: {os.path.abspath(args.json)}")

    if args.badge:
        with open(args.badge, "w", encoding="utf-8") as fh:
            fh.write(render_badge(report))
        print(f"Badge written to: {os.path.abspath(args.badge)}")

    return 0 if report.covered else 1


if __name__ == "__main__":
    raise SystemExit(main())
