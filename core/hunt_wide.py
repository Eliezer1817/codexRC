#!/usr/bin/env python3
"""v0.48.0 WIDE-HUNT: caza sobre el corpus COMPLETO wordpress.org (>=5k installs).

La mejora EVIDENCE-CHAIN (v0.47.0) hace que los falsos positivos se cierren
solo, asi que el ruido ya no justifica limitar la caza a los VDP de
Patchstack. Nueva regla:
  - CAZAMOS a todos (corpus ancho, refrescable con wide_corpus.py).
  - REPORTAMOS donde pagan (VDP activo con bounty, mapa vdp_mapa.json);
    sin VDP = solo CVE credit, el hallazgo se guarda igual.
  - Los ya auditados (hechos/hunt_wide_done.txt) se saltan para no repetir.

CLI:
  python3 core/hunt_wide.py --dias 90 --workers 6
  python3 core/hunt_wide.py --solo-pagables   # solo VDP con bounty
"""
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
from core import diff_hunt  # noqa: E402

ROOT = os.path.abspath(os.path.join(HERE, ".."))
CORPUS = os.path.join(ROOT, "wide_corpus.json")
VDP = os.path.join(ROOT, "vdp_mapa.json")
DONE = os.path.join(ROOT, "hechos", "hunt_wide_done.txt")


def _load_done() -> set:
    os.makedirs(os.path.dirname(DONE), exist_ok=True)
    if not os.path.isfile(DONE):
        return set()
    return {x.strip() for x in open(DONE) if x.strip()}


def _save_done(slugs) -> None:
    with open(DONE, "a") as f:
        for s in slugs:
            f.write(s + "\n")


def _frescos(corpus: dict, dias: int) -> list:
    lim = time.time() - dias * 86400
    out = []
    for p in corpus["plugins"]:
        upd = p.get("last_updated") or ""
        try:
            import datetime
            try:  # ISO 8601
                ts = datetime.datetime.fromisoformat(
                    upd.replace("Z", "+00:00")).timestamp()
            except ValueError:  # formato wordpress: "2026-09-30 9:57am GMT"
                ts = datetime.datetime.strptime(
                    upd.replace(" GMT", ""), "%Y-%m-%d %I:%M%p").timestamp()
        except Exception:
            ts = 0
        p["_fresco"] = ts >= lim
        if p["_fresco"]:
            out.append(p)
    return out


def _auditar(rec: dict) -> dict:
    slug = rec["slug"]
    try:
        res = diff_hunt.scan(slug, diff_hunt.WORK)
        return {"slug": slug, "res": res}
    except Exception as e:
        return {"slug": slug, "res": {"error": str(e)}}


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="WIDE-HUNT")
    ap.add_argument("--dias", type=int, default=90)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--solo-pagables", action="store_true")
    ap.add_argument("--out", default=os.path.join(ROOT, "hechos",
                                                  "wide_hunt_results.json"))
    args = ap.parse_args()

    corpus = json.load(open(CORPUS))
    vdp = json.load(open(VDP)) if os.path.isfile(VDP) else {}
    done = _load_done()
    frescos = _frescos(corpus, args.dias)
    cola = [p for p in frescos if p["slug"] not in done]
    for p in cola:
        p["paga"] = bool(vdp.get(p["slug"], {}).get("bounty"))
        p["vdp"] = p["slug"] in vdp
    if args.solo_pagables:
        cola = [p for p in cola if p["paga"]]
    if args.limit:
        cola = cola[:args.limit]
    cola.sort(key=lambda x: (not x["paga"], -x["installs"]))
    pagables = sum(1 for p in cola if p["paga"])
    print(f"WIDE-HUNT: {len(cola)} en cola ({pagables} pagables), "
          f"{len(done)} ya auditados, workers={args.workers}")

    ok, fallos, hallazgos = [], [], []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(_auditar, p): p for p in cola}
        for i, fut in enumerate(as_completed(futs), 1):
            p = futs[fut]
            try:
                r = fut.result()
                res = r.get("res") or {}
                vivos = res.get("hallazgos", []) if isinstance(res, dict) else []
                if isinstance(res, dict) and res.get("error"):
                    fallos.append(p["slug"])
                else:
                    ok.append(p["slug"])
                    for h in vivos:
                        h["slug"] = p["slug"]
                        h["paga"] = p["paga"]
                        h["vdp"] = p["vdp"]
                        hallazgos.append(h)
                estado = f"{len(vivos)} vivos" if vivos else "limpio"
                if res.get("error"):
                    estado = "fallo: " + str(res["error"])[:60]
                print(f"[{i}/{len(cola)}] {p['slug']}: {estado}"
                      + (" 💥 PAGABLE" if vivos and p["paga"] else
                         (" 💥" if vivos else "")))
            except Exception as e:
                fallos.append(p["slug"])
                print(f"[{i}/{len(cola)}] {p['slug']}: fallo {e}")
    _save_done(ok)
    resumen = {"total": len(cola), "ok": len(ok), "fallos": len(fallos),
               "segundos": round(time.time() - t0, 1),
               "hallazgos": hallazgos,
               "pagables_con_hallazgo": sorted({h["slug"] for h in hallazgos
                                                if h.get("paga")})}
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    json.dump(resumen, open(args.out, "w"), indent=1)
    print(f"\nhecho: {len(ok)} ok, {len(fallos)} fallos, "
          f"{len(hallazgos)} hallazgos en {resumen['segundos']}s")
    if hallazgos:
        print("💥 con hallazgo:", resumen["pagables_con_hallazgo"][:20])


if __name__ == "__main__":
    main()
