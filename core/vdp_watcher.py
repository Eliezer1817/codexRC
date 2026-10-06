"""VDP-FRESH WATCHER (v0.62.6).

Detecta plugins PAGABLES (VDP con bounty) que sacaron version nueva
desde nuestra ultima auditoria y los manda a DIFF-HUNT solos: el
parche fresco es el mejor momento para cazar parches incompletos.

Lo despierta un workflow cada 6 horas; el script es determinista
(Python puro, sin LLM) y el agente solo triaga al final.

Uso:
  python3 core/vdp_watcher.py             # detecta y caza los que movieron
  python3 core/vdp_watcher.py --check     # solo listar, sin cazar
  python3 core/vdp_watcher.py --limit 20  # prueba rapida (primeros N pagables)
"""
import argparse
import ast
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

HERE = os.path.abspath(os.path.dirname(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, ROOT)

from core import state
from core.diff_hunt import get_versions

VDP = os.path.join(ROOT, "data", "vdp_mapa.json")


def _auditadas() -> dict:
    """slug -> version auditada, de TODOS los resultados historicos."""
    aud = {}
    d = state.hechos()
    for fn in os.listdir(d):
        if not (fn.startswith("wide_hunt_results") or fn.startswith("watcher_diff")):
            continue
        p = os.path.join(d, fn)
        if fn.endswith(".jsonl"):
            for line in open(p, encoding="utf-8", errors="replace"):
                try:
                    j = json.loads(line)
                    r = j.get("res")
                    r = ast.literal_eval(r) if isinstance(r, str) else r
                    if isinstance(r, dict) and r.get("slug") and r.get("version"):
                        aud[r["slug"]] = r["version"]
                except Exception:
                    continue
        elif fn.endswith(".json"):
            try:
                data = json.load(open(p, encoding="utf-8", errors="replace"))
            except Exception:
                continue
            rows = data if isinstance(data, list) else data.get("resultados", [])
            for r in rows:
                if isinstance(r, dict) and r.get("slug") and r.get("version"):
                    aud[r["slug"]] = r["version"]
    return aud


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="solo listar movidos, sin cazar")
    ap.add_argument("--limit", type=int, default=0,
                    help="probar solo los primeros N pagables")
    ap.add_argument("--sleep", type=float, default=0.25,
                    help="pausa entre consultas a la API de wp.org (s)")
    args = ap.parse_args()

    if not os.path.isfile(VDP):
        print(json.dumps({"error": "falta vdp_mapa.json"}))
        return
    mapa = json.load(open(VDP))
    pagables = sorted(s for s, v in mapa.items()
                      if isinstance(v, dict) and v.get("bounty"))
    if args.limit:
        pagables = pagables[:args.limit]

    aud = _auditadas()
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = state.hechos(f"watcher_diff_{ts}.json")

    movidos = []
    for i, slug in enumerate(pagables):
        if slug not in aud:      # nunca auditado: lo lleva PLUGIN-BATCH aparte
            continue
        try:
            r = get_versions(slug)
        except Exception:
            r = None
        if r and r[0] != aud[slug]:
            movidos.append((slug, aud[slug], r[0], mapa[slug].get("bounty")))
            print(f"MOVIDO {slug}: {aud[slug]} -> {r[0]} bounty={mapa[slug].get('bounty')}",
                  flush=True)
        if args.sleep:
            time.sleep(args.sleep)

    if args.check:
        print(json.dumps({"movidos": len(movidos),
                          "slugs": [m[0] for m in movidos]}, ensure_ascii=False))
        return

    if not movidos:
        print(json.dumps({"movidos": 0, "cazados": 0, "vivos": []}))
        return

    slugs = [m[0] for m in movidos]
    cmd = [sys.executable, os.path.join(HERE, "diff_hunt.py"), *slugs,
           "--vdp", VDP, "--out", out_path]
    subprocess.run(cmd, check=False)
    # el veredicto de vivos queda en el JSON de salida de diff_hunt
    vivos = []
    try:
        data = json.load(open(out_path, encoding="utf-8", errors="replace"))
        rows = data if isinstance(data, list) else data.get("resultados", [])
        for r in rows:
            if not isinstance(r, dict):
                continue
            if r.get("vivos") or (r.get("hallazgos") and len(r["hallazgos"]) > 0):
                vivos.append(r["slug"])
    except Exception:
        pass
    print(json.dumps({"movidos": len(movidos),
                      "slugs": slugs,
                      "cazados": len(slugs),
                      "vivos": vivos,
                      "salida": out_path}, ensure_ascii=False))


if __name__ == "__main__":
    main()
