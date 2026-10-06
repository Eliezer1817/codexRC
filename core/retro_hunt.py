#!/usr/bin/env python3
"""
RETRO-HUNT (v0.51.0) — CodexRC

Caza el codigo PRE-COOLDOWN: plugins >=5k installs cuya ultima
actualizacion es ANTERIOR al gate de revision IA de WordPress.org
(junio 2026). Ese codigo distribuido nunca paso por el escaneo
automatico de WP.org ni por Jetpack Scan de cola, asi que es el
terreno con menos filtros encima.

La auditoria es FULL-CODE (no diff): todo el plugin se taintea,
no solo lo nuevo.

Uso:
  python3 core/retro_hunt.py                    # cola completa pre-cooldown
  python3 core/retro_hunt.py --limit 20        # prueba chica
  python3 core/retro_hunt.py --workers 6
  python3 core/retro_hunt.py --desde 2026-06-01 # umbral cooldown

Salida:
  hechos/retro_results.json.jsonl   (hallazgos por plugin)
  hechos/retro_done.txt             (auditados, incremental crash-safe)
"""
import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from core import plugin_batch  # noqa: E402

ROOT = os.path.abspath(os.path.join(HERE, ".."))
CORPUS = os.path.join(ROOT, "data", "wide_corpus.json")
VDP = os.path.join(ROOT, "data", "vdp_mapa.json")
DONE = os.path.join(ROOT, "hechos", "retro_done.txt")
OUT = os.path.join(ROOT, "hechos", "retro_results.json")

COOLDOWN_DEFAULT = "2026-06-01"   # inicio del gate IA de WP.org


def _load_done() -> set:
    os.makedirs(os.path.dirname(DONE), exist_ok=True)
    if not os.path.isfile(DONE):
        return set()
    return {x.strip() for x in open(DONE) if x.strip()}


def _bounty(v: dict) -> int:
    """'$2,600' -> 2600 (0 si no hay)."""
    b = v.get("bounty") if isinstance(v, dict) else v
    if isinstance(b, str):
        b = b.replace("$", "").replace(",", "").strip()
        try:
            return int(b)
        except ValueError:
            return 0
    return int(b) if isinstance(b, (int, float)) else 0


def _auditar(rec: dict) -> dict:
    slug = rec["slug"]
    os.makedirs("/tmp/retro_hunt", exist_ok=True)
    try:
        vdp = {slug: rec["vdp"]}
        res = plugin_batch.scan_slug(slug, "/tmp/retro_hunt", vdp, top=60)
        # v0.47.0: cadena de evidencia + abogados sobre lo hallado
        root = plugin_batch.download(slug, "/tmp/retro_hunt")
        vivos = res.get("hallazgos") or []
        if root and vivos:
            try:
                from core.evidence import annotate as evidence_annotate
                from core.gates_audit import audit as gates_audit
                gates = gates_audit(root)
                evidence_annotate(root, vivos, gates,
                                  analyzers=["TAINT-TRACE", "GATES-AUDIT",
                                             "FP-AUTO-CLOSE", "RETRO-HUNT"])
            except Exception:
                pass
        res["hallazgos"] = [h for h in vivos
                            if not h.get("_fp") and
                            h.get("_verdict") != "DESCARTADO"]
        return {"slug": slug, "res": res}
    except Exception as e:
        return {"slug": slug, "res": {"error": str(e)}}


def main() -> None:
    ap = argparse.ArgumentParser(description="RETRO-HUNT v0.51.0")
    ap.add_argument("--desde", default=COOLDOWN_DEFAULT,
                    help="fecha ISO del gate cooldown (default 2026-06-01)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--solo-pagables", action="store_true")
    args = ap.parse_args()

    corpus = json.load(open(CORPUS))
    vdp_all = json.load(open(VDP)) if os.path.isfile(VDP) else {}
    done = _load_done()

    # cola: pre-cooldown, no auditados nunca (ni wide ni retro)
    wide_done = set()
    wd = os.path.join(ROOT, "hechos", "hunt_wide_done.txt")
    if os.path.isfile(wd):
        wide_done = {x.strip() for x in open(wd)}
    cola = []
    for p in corpus.get("plugins", []):
        upd = (p.get("last_updated") or "")[:10]
        if upd >= args.desde or not upd:
            continue                      # ya paso el gate, DIFF-HUNT lo cubre
        if p["slug"] in done or p["slug"] in wide_done:
            continue
        v = vdp_all.get(p["slug"])
        p["vdp"] = v or {}
        p["monto"] = _bounty(v) if v else 0
        p["paga"] = p["monto"] > 0
        cola.append(p)
    if args.solo_pagables:
        cola = [p for p in cola if p["paga"]]
    cola.sort(key=lambda x: (not x["paga"], -x["monto"], -x["installs"]))
    if args.limit:
        cola = cola[:args.limit]

    pagables = sum(1 for p in cola if p["paga"])
    print(f"RETRO-HUNT: {len(cola)} en cola ({pagables} pagables), "
          f"{len(done)} ya auditados, umbral pre-{args.desde}")

    t0 = time.time()
    ok, fallos, vivos_total = 0, 0, 0
    with open(DONE, "a") as done_f, open(OUT + ".jsonl", "a") as res_f:
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(_auditar, p): p for p in cola}
            for i, fut in enumerate(as_completed(futs), 1):
                p = futs[fut]
                try:
                    r = fut.result()
                    res = r.get("res") or {}
                    if res.get("error") or res.get("status") not in (None, "ok"):
                        fallos += 1
                        estado = "fallo: " + str(res.get("error") or
                                                res.get("status"))[:60]
                    else:
                        ok += 1
                        done_f.write(p["slug"] + "\n")
                        done_f.flush()
                        res_f.write(json.dumps({"slug": p["slug"],
                                                "res": res}) + "\n")
                        res_f.flush()
                        vivos = res.get("hallazgos") or []
                        for h in vivos:
                            h["slug"] = p["slug"]
                            h["paga"] = p["paga"]
                            h["monto"] = p["monto"]
                        vivos_total += len(vivos)
                        estado = f"{len(vivos)} vivos" if vivos else "limpio"
                        if vivos:
                            estado += " 💥"
                    total = len(cola)
                    msg = (f"[{i}/{total}] {p['slug']}: {estado}")
                    print(msg, flush=True)
                except Exception as e:
                    fallos += 1
                    print(f"[{i}/{len(cola)}] {p['slug']}: EXC {e}", flush=True)
    mins = (time.time() - t0) / 60
    print(f"\nRETRO-HUNT fin: {ok} ok, {fallos} fallos, "
          f"{vivos_total} hallazgos vivos, {mins:.0f} min")


if __name__ == "__main__":
    main()
