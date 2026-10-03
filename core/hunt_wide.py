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
    ap.add_argument("--vdp-nuevos", default=os.path.join(
        ROOT, "vdp_nuevos.json"),
        help="VDP-FRESH: altas+ bounty nuevos, prioridad maxima "
             "(sin filtro de 90 dias ni corpus)")
    ap.add_argument("--dry-run", action="store_true",
                    help="imprime la cola ordenada y sale sin cazar")
    ap.add_argument("--band", default="5000-50000",
        help="rango de installs priorizado (medianos: menos "
             "competencia que los top)")
    ap.add_argument("--out", default=os.path.join(ROOT, "hechos",
                                                  "wide_hunt_results.json"))
    args = ap.parse_args()

    corpus = json.load(open(CORPUS))
    vdp = json.load(open(VDP)) if os.path.isfile(VDP) else {}
    done = _load_done()
    frescos = _frescos(corpus, args.dias)
    cola = [p for p in frescos if p["slug"] not in done]

    # VDP-FRESH (v0.61.0): altas de la semana + bounty nuevos entran
    # SIN filtro de frescura (un VDP recien agregado se caza ya,
    # actualizado o no) y aunque no esten en el corpus >=5k
    por_slug = {p["slug"]: p for p in cola}
    if os.path.isfile(args.vdp_nuevos):
        try:
            nf = json.load(open(args.vdp_nuevos))
            frescos_slugs = {p["slug"] for p in frescos}
            nuevos = [s for s in list(nf.get("altas", {}))
                      + list(nf.get("bounty_nuevos", {}))
                      if s not in done]
            extra = []
            for s in nuevos:
                if s in por_slug:
                    p = por_slug[s]
                    p["_vdp_fresh"] = True
                    continue  # ya en cola, solo se promociona
                d = nf.get("altas", {}).get(s) \
                    or nf.get("bounty_nuevos", {}).get(s) or {}
                extra.append({"slug": s, "name": d.get("name", s),
                              "installs": d.get("installs") or 0,
                              "last_updated": "",
                              "_fresco": True, "_vdp_fresh": True})
            for p in cola:
                if p["slug"] in nuevos:
                    p["_vdp_fresh"] = True
            cola.extend([e for e in extra if e["slug"] not in por_slug])
        except Exception as e:
            print(f"(vdp_nuevos ignorado: {e})")

    for p in cola:
        p["paga"] = bool(vdp.get(p["slug"], {}).get("bounty"))
        p["vdp"] = p["slug"] in vdp
    if args.solo_pagables:
        cola = [p for p in cola if p["paga"]]
    if args.limit:
        cola = cola[:args.limit]
    # PRIORIDAD (v0.61.0): VDP-FRESH arriba; luego el mid-band
    # 5k-50k (medianos: menos blindaje y competencia que los top),
    # luego el resto por installs
    try:
        lo, hi = (int(x) for x in args.band.split("-"))
    except Exception:
        lo, hi = 5000, 50000
    def _key(x):
        mid = lo <= x["installs"] < hi
        return (not x.get("_vdp_fresh"), not x["paga"],
                not mid, -x["installs"])
    cola.sort(key=_key)
    pagables = sum(1 for p in cola if p["paga"])
    if args.dry_run:
        mid = 0
        lo, hi = 5000, 50000
        try:
            lo, hi = (int(x) for x in args.band.split("-"))
        except Exception:
            pass
        for i, p in enumerate(cola[:25]):
            band = "*" if lo <= p["installs"] < hi else " "
            fresh = "NUEVO-VDP " if p.get("_vdp_fresh") else ""
            print(f"{i+1:>3}{band} {fresh}{p['slug']:<45}"
                  f"{p['installs']:>9,} paga={p['paga']}")
            mid += 1 if lo <= p["installs"] < hi else 0
        print(f"DRY-RUN: {len(cola)} en cola, {pagables} pagables, "
              f"{mid} de top-25 en banda {lo}-{hi}")
        return
    print(f"WIDE-HUNT: {len(cola)} en cola ({pagables} pagables), "
          f"{len(done)} ya auditados, workers={args.workers}")

    ok, fallos, hallazgos = [], [], []
    t0 = time.time()
    os.makedirs(os.path.dirname(DONE), exist_ok=True)
    done_f = open(DONE, "a")          # guardado incremental (crash-safe)
    res_f = open(args.out + ".jsonl", "a")
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
                    done_f.write(p["slug"] + "\n"); done_f.flush()
                    res_f.write(json.dumps({"slug": p["slug"], "res": res}) + "\n")
                    res_f.flush()
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
    done_f.close(); res_f.close()
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
