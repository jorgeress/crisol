"""CLI de crisol: scan, features, rules."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from . import __version__
from .features import extract
from .report import build_report, to_html, to_json
from .scanner import RuleSet

console = Console()
DEFAULT_RULES = Path(__file__).resolve().parents[2] / "rules"


def _cmd_scan(args) -> int:
    rs = RuleSet(args.rules).compile()
    feats = extract(args.sample)
    data = Path(args.sample).read_bytes()
    nested: list = []
    if args.recursive:
        matches, nested = rs.scan_recursive(data, timeout=args.timeout)
    else:
        matches = rs.scan_bytes(data, timeout=args.timeout)
    # El veredicto se calcula solo con lo que dispara sobre el fichero: que un
    # contenedor lleve algo dentro es una pista para el analista, no una
    # condena automática. Los payloads se listan aparte.
    report = build_report(feats, matches)

    if args.json:
        print(to_json(report))
        return _exit_code(report)

    if args.html:
        Path(args.html).write_text(to_html(report), encoding="utf-8")
        console.print(f"[green]HTML report written to[/] {args.html}")

    t = report["triage"]
    color = {"malicious-likely": "red", "suspicious": "yellow",
             "clean-likely": "green"}[t["verdict"]]
    console.print(f"\n[bold]{feats.path}[/]")
    console.print(f"  sha256   {feats.sha256}")
    console.print(f"  type     {feats.filetype}  ·  {feats.size} bytes  ·  "
                  f"entropy {feats.entropy}")
    console.print(f"  verdict  [{color}]{t['verdict']}[/]  (score {t['score']}/100)")

    if feats.pe:
        console.print(f"  PE: {feats.pe['n_sections']} sections, "
                      f"{feats.pe['n_imports']} imports, "
                      f"imphash {feats.pe['imphash']}")
        if feats.pe["suspicious_imports"]:
            console.print(f"      suspicious imports: "
                          f"[yellow]{', '.join(feats.pe['suspicious_imports'])}[/]")
    if feats.ole:
        console.print(f"  OLE/VBA: macros={feats.ole['has_macros']} "
                      f"autoexec={feats.ole['autoexec_triggers']}")

    if matches:
        tbl = Table(title="YARA matches", show_lines=False)
        tbl.add_column("rule", style="cyan")
        tbl.add_column("sev")
        tbl.add_column("tags")
        tbl.add_column("description")
        for m in matches:
            tbl.add_row(m.rule, str(m.meta.get("severity", "?")),
                        ", ".join(m.tags), str(m.meta.get("description", "")))
        console.print(tbl)
    else:
        console.print("  [dim]no YARA matches[/]")

    if nested:
        tbl = Table(title="Embedded payloads that do match", show_lines=False)
        tbl.add_column("origin", style="magenta")
        tbl.add_column("rules")
        for origin, hits in nested:
            tbl.add_row(origin, ", ".join(sorted({m.rule for m in hits})))
        console.print(tbl)
        console.print("  [dim]these don't count towards the verdict: a container is not "
                      "its contents[/]")
    elif args.recursive:
        console.print("  [dim]no matches in embedded payloads[/]")

    for ioc_type, vals in feats.iocs.items():
        if vals:
            console.print(f"  IOC {ioc_type}: {', '.join(vals[:5])}"
                          + (" …" if len(vals) > 5 else ""))
    return _exit_code(report)


def _exit_code(report) -> int:
    # útil en pipelines: 0 limpio, 1 sospechoso, 2 malicioso
    return {"clean-likely": 0, "suspicious": 1, "malicious-likely": 2}[
        report["triage"]["verdict"]]


def _cmd_features(args) -> int:
    print(to_json(extract(args.sample).to_dict()))
    return 0


def _cmd_rules(args) -> int:
    rs = RuleSet(args.rules).compile()
    console.print(f"[green]{rs.rule_count} rules compiled OK[/] "
                  f"from {args.rules}")
    for src in rs.sources:
        console.print(f"  · {src}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="crisol",
        description="Static malware triage engine + YARA rule test bench")
    p.add_argument("--version", action="version", version=f"crisol {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="full triage of a sample")
    ps.add_argument("sample")
    ps.add_argument("--rules", default=str(DEFAULT_RULES))
    ps.add_argument("--json", action="store_true", help="JSON output")
    ps.add_argument("--html", metavar="OUT.html", help="write an HTML report")
    ps.add_argument("--timeout", type=int, default=30)
    ps.add_argument("--recursive", action="store_true",
                    help="also scan embedded PEs and ZIP members inside the sample "
                         "(they don't change the verdict)")
    ps.set_defaults(func=_cmd_scan)

    pf = sub.add_parser("features", help="feature extraction only (JSON)")
    pf.add_argument("sample")
    pf.set_defaults(func=_cmd_features)

    pr = sub.add_parser("rules", help="compile and validate the ruleset")
    pr.add_argument("--rules", default=str(DEFAULT_RULES))
    pr.set_defaults(func=_cmd_rules)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        console.print(f"[red]error:[/] {e}")
        return 3


if __name__ == "__main__":
    sys.exit(main())
