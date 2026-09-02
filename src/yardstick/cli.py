"""CLI de yardstick: scan, features, rules."""
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
    matches = rs.scan_bytes(Path(args.sample).read_bytes(), timeout=args.timeout)
    report = build_report(feats, matches)

    if args.json:
        print(to_json(report))
        return _exit_code(report)

    if args.html:
        Path(args.html).write_text(to_html(report), encoding="utf-8")
        console.print(f"[green]informe HTML escrito en[/] {args.html}")

    t = report["triage"]
    color = {"malicious-likely": "red", "suspicious": "yellow",
             "clean-likely": "green"}[t["verdict"]]
    console.print(f"\n[bold]{feats.path}[/]")
    console.print(f"  sha256   {feats.sha256}")
    console.print(f"  tipo     {feats.filetype}  ·  {feats.size} bytes  ·  "
                  f"entropía {feats.entropy}")
    console.print(f"  veredicto [{color}]{t['verdict']}[/]  (score {t['score']}/100)")

    if feats.pe:
        console.print(f"  PE: {feats.pe['n_sections']} secciones, "
                      f"{feats.pe['n_imports']} imports, "
                      f"imphash {feats.pe['imphash']}")
        if feats.pe["suspicious_imports"]:
            console.print(f"      imports sospechosos: "
                          f"[yellow]{', '.join(feats.pe['suspicious_imports'])}[/]")
    if feats.ole:
        console.print(f"  OLE/VBA: macros={feats.ole['has_macros']} "
                      f"autoexec={feats.ole['autoexec_triggers']}")

    if matches:
        tbl = Table(title="Coincidencias YARA", show_lines=False)
        tbl.add_column("regla", style="cyan")
        tbl.add_column("sev")
        tbl.add_column("tags")
        tbl.add_column("descripción")
        for m in matches:
            tbl.add_row(m.rule, str(m.meta.get("severity", "?")),
                        ", ".join(m.tags), str(m.meta.get("description", "")))
        console.print(tbl)
    else:
        console.print("  [dim]sin coincidencias YARA[/]")

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
    console.print(f"[green]{rs.rule_count} reglas compiladas OK[/] "
                  f"desde {args.rules}")
    for src in rs.sources:
        console.print(f"  · {src}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="yardstick",
        description="Motor de triaje estático de malware + banco de reglas YARA")
    p.add_argument("--version", action="version", version=f"yardstick {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    ps = sub.add_parser("scan", help="triaje completo de una muestra")
    ps.add_argument("sample")
    ps.add_argument("--rules", default=str(DEFAULT_RULES))
    ps.add_argument("--json", action="store_true", help="salida JSON")
    ps.add_argument("--html", metavar="OUT.html", help="escribe informe HTML")
    ps.add_argument("--timeout", type=int, default=30)
    ps.set_defaults(func=_cmd_scan)

    pf = sub.add_parser("features", help="solo extracción de features (JSON)")
    pf.add_argument("sample")
    pf.set_defaults(func=_cmd_features)

    pr = sub.add_parser("rules", help="compila y valida el ruleset")
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
