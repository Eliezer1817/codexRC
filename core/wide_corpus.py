#!/usr/bin/env python3
"""v0.48.0 WIDE-CORPUS: corpus de caza = TODOS los plugins wordpress.org
con installs >= umbral (por defecto 5k), sin depender del filtro VDP.

Filosofia EVIDENCE-CHAIN: como los abogados cierran solos los falsos
positivos, el cuello de botella ya no es el ruido sino el ancho de banda.
El VDP de Patchstack ya no filtra a quien CAZAMOS; solo decide a quien
REPORTAMOS (VDP activo = paga; sin VDP = CVE credit directo al vendor).

CLI:
  python3 core/wide_corpus.py                 # >=5k installs -> wide_corpus.json
  python3 core/wide_corpus.py --min 10000     # umbral a gusto
  python3 core/wide_corpus.py --refresh       # refresca desde la API
"""
import json
import os
import sys
import time
import urllib.request

API = ("https://api.wordpress.org/plugins/info/1.2/"
       "?action=query_plugins&request[per_page]=100&request[browse]=popular"
       "&request[page]=%d")
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_OUT = os.path.join(HERE, "..", "data", "wide_corpus.json")


def fetch_page(p: int, retries: int = 3):
    for i in range(retries):
        try:
            with urllib.request.urlopen(API % p, timeout=30) as r:
                return json.load(r)
        except Exception:
            if i == retries - 1:
                raise
            time.sleep(2 * (i + 1))


def build(min_installs: int = 5000, max_pages: int = 60) -> dict:
    """Recorre 'popular' hasta que toda una pagina cae bajo el umbral."""
    corpus, page, seen_slugs = [], 1, set()
    while page <= max_pages:
        d = fetch_page(page)
        pls = d.get("plugins") or []
        if not pls:
            break
        added = 0
        for pl in pls:
            inst = pl.get("active_installs") or 0
            if inst < min_installs:
                continue
            slug = pl.get("slug")
            if not slug or slug in seen_slugs:
                continue
            seen_slugs.add(slug)
            corpus.append({
                "slug": slug,
                "name": pl.get("name"),
                "installs": inst,
                "last_updated": pl.get("last_updated") or "",
                "version": pl.get("version") or "",
            })
            added += 1
        if added == 0 and page > 2:
            # toda la pagina bajo el umbral: territorio agotado
            break
        page += 1
        time.sleep(0.3)  # cortesia con la API
    corpus.sort(key=lambda x: -x["installs"])
    return {"min_installs": min_installs,
            "total": len(corpus),
            "generado": time.strftime("%Y-%m-%d %H:%M"),
            "plugins": corpus}


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="WIDE-CORPUS")
    ap.add_argument("--min", type=int, default=5000)
    ap.add_argument("--max-pages", type=int, default=60)
    ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()
    if os.path.isfile(args.out) and not args.refresh:
        d = json.load(open(args.out))
        print(f"corpus existente: {d['total']} plugins >= {d['min_installs']:,} "
              f"(generado {d['generado']})")
        return
    t0 = time.time()
    d = build(args.min, args.max_pages)
    with open(args.out, "w") as f:
        json.dump(d, f, indent=1)
    por_v = sum(1 for x in d["plugins"] if x["installs"] >= 10000)
    print(f"corpus: {d['total']} plugins >= {args.min:,} installs "
          f"({por_v} de ellos >= 10k) en {time.time()-t0:.0f}s -> {args.out}")


if __name__ == "__main__":
    main()
