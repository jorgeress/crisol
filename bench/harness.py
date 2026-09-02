"""Banco de pruebas de reglas YARA — el corazón del "detection engineering".

Mide, sobre dos corpus etiquetados:
  - corpus/goodware/  → cualquier match = FALSO POSITIVO
  - corpus/malware/   → ausencia de match = FALSO NEGATIVO

Produce por-regla: TP, FP, y tasa de FP. Con esto justificas en tu CV que
tus reglas están *evaluadas*, no escritas a ojo.

Uso:
    python bench/harness.py --rules rules --goodware corpus/goodware \
        --malware corpus/malware [--json report.json]
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from yardstick.scanner import RuleSet  # noqa: E402


def _iter_samples(root: Path):
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.stat().st_size > 0 and not p.name.startswith("."):
            yield p


def run(rules_dir: str, goodware: str, malware: str) -> dict:
    rs = RuleSet(rules_dir).compile()

    per_rule = defaultdict(lambda: {"tp": 0, "fp": 0})
    good_files = list(_iter_samples(Path(goodware))) if goodware else []
    mal_files = list(_iter_samples(Path(malware))) if malware else []

    good_flagged = 0
    for f in good_files:
        try:
            matches = rs.scan_file(f)
        except Exception as e:  # noqa: BLE001
            print(f"[warn] {f}: {e}", file=sys.stderr)
            continue
        if matches:
            good_flagged += 1
        for m in matches:
            per_rule[m.rule]["fp"] += 1

    mal_detected = 0
    for f in mal_files:
        try:
            matches = rs.scan_file(f)
        except Exception as e:  # noqa: BLE001
            print(f"[warn] {f}: {e}", file=sys.stderr)
            continue
        if matches:
            mal_detected += 1
        for m in matches:
            per_rule[m.rule]["tp"] += 1

    n_good, n_mal = len(good_files), len(mal_files)
    summary = {
        "rules_compiled": rs.rule_count,
        "goodware_total": n_good,
        "goodware_flagged": good_flagged,
        "false_positive_rate": round(good_flagged / n_good, 4) if n_good else None,
        "malware_total": n_mal,
        "malware_detected": mal_detected,
        "detection_rate": round(mal_detected / n_mal, 4) if n_mal else None,
        "per_rule": {},
    }
    for rule, c in sorted(per_rule.items()):
        fp_rate = round(c["fp"] / n_good, 4) if n_good else None
        summary["per_rule"][rule] = {
            "true_positives": c["tp"], "false_positives": c["fp"],
            "fp_rate_vs_goodware": fp_rate,
        }
    return summary


def print_report(s: dict) -> None:
    print("=" * 60)
    print(f"  Reglas compiladas : {s['rules_compiled']}")
    print(f"  Goodware          : {s['goodware_flagged']}/{s['goodware_total']} "
          f"marcados  (FP rate: {s['false_positive_rate']})")
    print(f"  Malware           : {s['malware_detected']}/{s['malware_total']} "
          f"detectados  (detección: {s['detection_rate']})")
    print("-" * 60)
    print(f"  {'regla':<34}{'TP':>5}{'FP':>5}{'FP-rate':>10}")
    for rule, c in s["per_rule"].items():
        flag = "  <-- REVISAR" if (c["fp_rate_vs_goodware"] or 0) > 0.01 else ""
        print(f"  {rule:<34}{c['true_positives']:>5}{c['false_positives']:>5}"
              f"{str(c['fp_rate_vs_goodware']):>10}{flag}")
    print("=" * 60)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Banco de pruebas de reglas YARA")
    p.add_argument("--rules", default="rules")
    p.add_argument("--goodware", default="corpus/goodware")
    p.add_argument("--malware", default="corpus/malware")
    p.add_argument("--json", metavar="OUT", help="volcar summary a JSON")
    p.add_argument("--max-fp-rate", type=float, default=None,
                   help="falla (exit 1) si la FP rate global supera este umbral (para CI)")
    args = p.parse_args(argv)

    s = run(args.rules, args.goodware, args.malware)
    print_report(s)
    if args.json:
        Path(args.json).write_text(json.dumps(s, indent=2), encoding="utf-8")
        print(f"[ok] JSON escrito en {args.json}")

    if args.max_fp_rate is not None and s["false_positive_rate"] is not None:
        if s["false_positive_rate"] > args.max_fp_rate:
            print(f"[FAIL] FP rate {s['false_positive_rate']} > "
                  f"umbral {args.max_fp_rate}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
