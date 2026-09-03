"""Banco de pruebas de reglas YARA — el corazón del "detection engineering".

Mide, sobre dos corpus etiquetados:
  - corpus/goodware/  → cualquier match = FALSO POSITIVO
  - corpus/malware/   → ausencia de match = FALSO NEGATIVO

Produce por-regla: TP, FP, y tasa de FP. Con esto justificas en tu CV que
tus reglas están *evaluadas*, no escritas a ojo.

Si existe bench/corpus_manifest.json (lo escribe fetch_malwarebazaar.py),
además desglosa la detección por familia y lista los falsos negativos: eso es
lo que dice *qué* regla hay que escribir a continuación.

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

DEFAULT_MANIFEST = Path(__file__).resolve().parent / "corpus_manifest.json"


def _iter_samples(root: Path):
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.stat().st_size > 0 and not p.name.startswith("."):
            yield p


def _load_manifest(path: Path | None) -> dict:
    """Metadatos por sha256 (familia, tipo...). Ausente = corpus sin etiquetar."""
    if path is None or not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print(f"[warn] manifiesto ilegible: {path}", file=sys.stderr)
        return {}


def run(rules_dir: str, goodware: str, malware: str, manifest_path: Path | None = None) -> dict:
    rs = RuleSet(rules_dir).compile()
    manifest = _load_manifest(manifest_path)

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
    # el nombre del fichero es el sha256 (así lo guarda fetch_malwarebazaar.py)
    per_family = defaultdict(lambda: {"total": 0, "detected": 0})
    misses = []
    for f in mal_files:
        try:
            matches = rs.scan_file(f)
        except Exception as e:  # noqa: BLE001
            print(f"[warn] {f}: {e}", file=sys.stderr)
            continue
        family = manifest.get(f.name, {}).get("family", "unknown")
        per_family[family]["total"] += 1
        if matches:
            mal_detected += 1
            per_family[family]["detected"] += 1
        else:
            misses.append({"sha256": f.name, "family": family})
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
        "per_family": {},
        "false_negatives": misses,
    }
    for rule, c in sorted(per_rule.items()):
        fp_rate = round(c["fp"] / n_good, 4) if n_good else None
        summary["per_rule"][rule] = {
            "true_positives": c["tp"], "false_positives": c["fp"],
            "fp_rate_vs_goodware": fp_rate,
        }
    for family, c in sorted(per_family.items(),
                            key=lambda kv: (-kv[1]["total"], kv[0])):
        summary["per_family"][family] = {
            **c,
            "detection_rate": round(c["detected"] / c["total"], 4) if c["total"] else None,
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

    if s["per_family"]:
        print("-" * 60)
        print(f"  {'familia':<34}{'det':>5}{'tot':>5}{'ratio':>10}")
        for family, c in s["per_family"].items():
            flag = "  <-- CIEGOS" if c["detected"] == 0 else ""
            print(f"  {family:<34}{c['detected']:>5}{c['total']:>5}"
                  f"{str(c['detection_rate']):>10}{flag}")

    misses = s.get("false_negatives") or []
    if misses:
        print("-" * 60)
        print(f"  Falsos negativos ({len(misses)}): ninguna regla dispara")
        for m in misses[:15]:
            print(f"    {m['sha256'][:16]}  {m['family']}")
        if len(misses) > 15:
            print(f"    ... y {len(misses) - 15} más")
    print("=" * 60)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Banco de pruebas de reglas YARA")
    p.add_argument("--rules", default="rules")
    p.add_argument("--goodware", default="corpus/goodware")
    p.add_argument("--malware", default="corpus/malware")
    p.add_argument("--manifest", default=str(DEFAULT_MANIFEST),
                   help="JSON con familia por sha256 (opcional, para el desglose)")
    p.add_argument("--json", metavar="OUT", help="volcar summary a JSON")
    p.add_argument("--max-fp-rate", type=float, default=None,
                   help="falla (exit 1) si la FP rate global supera este umbral (para CI)")
    p.add_argument("--min-detection-rate", type=float, default=None,
                   help="falla (exit 1) si la detección baja de este umbral")
    args = p.parse_args(argv)

    s = run(args.rules, args.goodware, args.malware,
            Path(args.manifest) if args.manifest else None)
    print_report(s)
    if args.json:
        Path(args.json).write_text(json.dumps(s, indent=2), encoding="utf-8")
        print(f"[ok] JSON escrito en {args.json}")

    rc = 0
    if args.max_fp_rate is not None and s["false_positive_rate"] is not None:
        if s["false_positive_rate"] > args.max_fp_rate:
            print(f"[FAIL] FP rate {s['false_positive_rate']} > "
                  f"umbral {args.max_fp_rate}", file=sys.stderr)
            rc = 1
    if args.min_detection_rate is not None and s["detection_rate"] is not None:
        if s["detection_rate"] < args.min_detection_rate:
            print(f"[FAIL] detección {s['detection_rate']} < "
                  f"umbral {args.min_detection_rate}", file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
