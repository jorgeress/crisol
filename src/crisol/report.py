"""Scoring de triaje y salida (JSON + HTML)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .features import Features
from .scanner import Match

# Pesos heurísticos: NO son un veredicto, son una priorización para el analista.
# Cada señal se justifica en el README (detection engineering != caja negra).
SCORE_WEIGHTS = {
    "high_overall_entropy": (15, lambda f: f.entropy >= 7.2),
    "high_section_entropy": (15, lambda f: bool(f.pe) and f.pe["max_section_entropy"] >= 7.5),
    "rwx_section": (20, lambda f: bool(f.pe) and f.pe["has_rwx_section"]),
    "suspicious_imports": (
        20, lambda f: bool(f.pe) and len(f.pe["suspicious_imports"]) >= 3),
    "large_overlay": (10, lambda f: bool(f.pe) and f.pe["overlay_size"] > 50_000),
    "network_iocs": (10, lambda f: bool(f.iocs.get("urls") or f.iocs.get("domains"))),
    "vba_autoexec": (25, lambda f: bool(f.ole) and bool(f.ole.get("autoexec_triggers"))),
    "vba_suspicious": (
        15, lambda f: bool(f.ole) and bool(f.ole.get("suspicious_keywords"))),
}


def compute_score(feats: Features, matches: list[Match]) -> dict[str, Any]:
    reasons = []
    score = 0
    for name, (weight, test) in SCORE_WEIGHTS.items():
        try:
            if test(feats):
                score += weight
                reasons.append({"signal": name, "weight": weight})
        except Exception:  # noqa: BLE001
            continue
    # Los matches YARA pesan según su severidad declarada en meta.severity (1-10)
    for m in matches:
        sev = int(m.meta.get("severity", 5))
        w = sev * 5
        score += w
        reasons.append({"signal": f"yara:{m.rule}", "weight": w})

    score = min(score, 100)
    if score >= 70:
        verdict = "malicious-likely"
    elif score >= 35:
        verdict = "suspicious"
    else:
        verdict = "clean-likely"
    return {"score": score, "verdict": verdict, "reasons": reasons}


def build_report(feats: Features, matches: list[Match]) -> dict[str, Any]:
    return {
        "generated": datetime.now(timezone.utc).isoformat(),
        "tool": "crisol",
        "triage": compute_score(feats, matches),
        "yara_matches": [
            {"rule": m.rule, "namespace": m.namespace, "tags": m.tags,
             "meta": m.meta, "strings": m.strings}
            for m in matches
        ],
        "features": feats.to_dict(),
    }


def to_json(report: dict[str, Any], indent: int = 2) -> str:
    return json.dumps(report, indent=indent, ensure_ascii=False, default=str)


_HTML = """<!doctype html><meta charset=utf-8>
<title>crisol · {sha}</title>
<style>
body{{font:14px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:900px;color:#1a1a1a}}
h1{{font-size:1.4rem}} code{{background:#f0f0f0;padding:1px 4px;border-radius:3px}}
.badge{{display:inline-block;padding:4px 12px;border-radius:14px;color:#fff;font-weight:600}}
.malicious-likely{{background:#c0392b}} .suspicious{{background:#e67e22}} .clean-likely{{background:#27ae60}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}
th,td{{border:1px solid #ddd;padding:6px 10px;text-align:left;font-size:13px}}
th{{background:#fafafa}} .meter{{height:22px;background:#eee;border-radius:11px;overflow:hidden}}
.meter>div{{height:100%;background:linear-gradient(90deg,#27ae60,#e67e22,#c0392b)}}
</style>
<h1>crisol · triaje estático</h1>
<p><code>{path}</code><br>sha256 <code>{sha}</code> · {size} bytes · tipo <b>{ftype}</b></p>
<p>Veredicto: <span class="badge {verdict}">{verdict}</span> · score <b>{score}/100</b></p>
<div class="meter"><div style="width:{score}%"></div></div>
<h2>Señales</h2><table><tr><th>señal</th><th>peso</th></tr>{reasons}</table>
<h2>Coincidencias YARA ({n_yara})</h2><table><tr><th>regla</th><th>severidad</th><th>tags</th></tr>{yara}</table>
<h2>IOCs</h2><pre>{iocs}</pre>
<hr><p style=color:#888>generado {gen}</p>
"""


def to_html(report: dict[str, Any]) -> str:
    f = report["features"]
    t = report["triage"]
    reasons = "".join(
        f"<tr><td>{r['signal']}</td><td>{r['weight']}</td></tr>" for r in t["reasons"]
    ) or "<tr><td colspan=2>ninguna</td></tr>"
    yara = "".join(
        f"<tr><td>{m['rule']}</td><td>{m['meta'].get('severity','?')}</td>"
        f"<td>{', '.join(m['tags'])}</td></tr>" for m in report["yara_matches"]
    ) or "<tr><td colspan=3>ninguna</td></tr>"
    return _HTML.format(
        path=f["path"], sha=f["sha256"], size=f["size"], ftype=f["filetype"],
        verdict=t["verdict"], score=t["score"], reasons=reasons,
        n_yara=len(report["yara_matches"]), yara=yara,
        iocs=json.dumps(f["iocs"], indent=2, ensure_ascii=False),
        gen=report["generated"],
    )
