"""VENDOR-FARM: descubre familias de plugins de UN MISMO vendor con
instalaciones en rango pagable, para farmear el vendor completo (el
patron que dio el 0-day de AFFI en VillaTheme).

- Consulta la API publica de wordpress.org (HTTPS, python puro, Termux OK)
- Agrupa por vendor (autor) y filtra familias con N+ plugins en el rango
- Excluye slugs ya auditados (pasa el directorio del corpus o una lista)
- Estima la paga por plugin con la tabla Patchstack (BTC/ETH) y marca
  el precio del hallazgo mas valioso de la familia

Uso (CLI):
    python3 core/vendor_farm.py --tag woocommerce --pages 5 \
        --min 10000 --max 200000 --family 2 --exclude-dir cz_hunt
    python3 core/vendor_farm.py --browse popular --pages 8

API del server:
    POST /api/vendor_farm {"tag": "woocommerce", "pages": 5,
                          "min": 10000, "max": 200000,
                          "family_min": 2, "exclude_slugs": [...]}
"""

import argparse
import json
import re
import time
import urllib.request
from typing import Any, Dict, List, Optional

API = "https://api.wordpress.org/plugins/info/1.2/"

# tabla Patchstack (verificada 28/09/2026): (unauth, subscriber) por rango
PAY_TABLE = [
    (15_000_000, 16_500, 33_000),
    (5_000_000, 7_200, 14_400),
    (1_000_000, 3_600, 7_200),
    (500_000, 2_450, 4_900),
    (100_000, 1_300, 2_600),
    (50_000, 700, 1_400),
    (10_000, 300, 600),
    (5_000, 200, 400),
    (1_000, 125, 250),
]


def pay_estimate(installs: int) -> Dict[str, Any]:
    """Paga estimada (USD) por un 0-day en ese plugin, segun installs."""
    for base, subs, unauth in PAY_TABLE:
        if installs >= base:
            return {"subs_usd": subs, "unauth_usd": unauth}
    return {"subs_usd": 0, "unauth_usd": 0}


def _autor_limpio(autor: str) -> str:
    m = re.search(r">([^<]+)<", autor or "?")
    return (m.group(1) if m else autor or "?").strip()


def fetch_plugins(tag: Optional[str] = None,
                  browse: str = "popular",
                  pages: int = 5,
                  per_page: int = 100) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for page in range(1, pages + 1):
        url = (f"{API}?action=query_plugins&request[per_page]={per_page}"
               f"&request[browse]={browse}&request[page]={page}")
        if tag:
            url += f"&request[tag]={tag}"
        try:
            with urllib.request.urlopen(url, timeout=25) as r:
                data = json.load(r)
        except Exception as exc:
            out.append({"_error": f"pagina {page}: {exc}"})
            continue
        out.extend(data.get("plugins") or [])
        time.sleep(0.4)  # cortesia con la API publica
    return out


def slugs_auditados(exclude_dir: Optional[str] = None,
                    exclude_slugs: Optional[List[str]] = None) -> set:
    """Set de slugs ya auditados: carpetas del corpus + lista explicita."""
    audit = set(exclude_slugs or [])
    if exclude_dir:
        import os
        for base, dirs, files in os.walk(exclude_dir):
            # solo el primer nivel de carpetas (los slugs) y los zips
            for d in dirs:
                audit.add(d)
            for f in files:
                if f.endswith(".zip"):
                    audit.add(f[:-4])
            break  # maxdepth 1
    return audit


def farm(plugins: List[Dict[str, Any]],
         min_installs: int = 10_000,
         max_installs: int = 200_000,
         family_min: int = 2,
         auditados: Optional[set] = None) -> Dict[str, Any]:
    auditados = auditados or set()
    vendores: Dict[str, List[Dict[str, Any]]] = {}
    for p in plugins:
        if "_error" in p:
            continue
        slug = p.get("slug")
        inst = p.get("active_installs") or 0
        if not slug:
            continue
        vendores.setdefault(_autor_limpio(p.get("author")), []).append(
            {"slug": slug, "installs": inst, "name": p.get("name", "")})

    familias = []
    for autor, plugs in vendores.items():
        en_rango = [x for x in plugs
                    if min_installs <= x["installs"] <= max_installs]
        nuevos = [x for x in en_rango if x["slug"] not in auditados]
        if len(nuevos) < family_min:
            continue
        for x in nuevos:
            x["pay"] = pay_estimate(x["installs"])
        mejor = max(x["pay"]["unauth_usd"] for x in nuevos)
        familias.append({
            "vendor": autor,
            "familia_installs": sum(x["installs"] for x in nuevos),
            "mejor_pago_unauth_usd": mejor,
            "plugins": sorted(nuevos, key=lambda x: -x["installs"]),
        })
    familias.sort(key=lambda f: -f["mejor_pago_unauth_usd"])
    return {"familias": familias,
            "total_plugins_nuevos": sum(len(f["plugins"]) for f in familias)}


def run(tag: Optional[str] = None, browse: str = "popular",
        pages: int = 5, min_installs: int = 10_000,
        max_installs: int = 200_000, family_min: int = 2,
        exclude_dir: Optional[str] = None,
        exclude_slugs: Optional[List[str]] = None) -> Dict[str, Any]:
    plugins = fetch_plugins(tag=tag, browse=browse, pages=pages)
    auditados = slugs_auditados(exclude_dir, exclude_slugs)
    out = farm(plugins, min_installs, max_installs, family_min, auditados)
    out["params"] = {"tag": tag, "browse": browse, "pages": pages,
                     "min": min_installs, "max": max_installs,
                     "family_min": family_min,
                     "auditados_excluidos": len(auditados)}
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="VENDOR-FARM")
    ap.add_argument("--tag", default=None, help="tag a farmear (woocommerce...)")
    ap.add_argument("--browse", default="popular")
    ap.add_argument("--pages", type=int, default=5)
    ap.add_argument("--min", type=int, default=10_000)
    ap.add_argument("--max", type=int, default=200_000)
    ap.add_argument("--family", type=int, default=2,
                    help="minimo de plugins nuevos por vendor")
    ap.add_argument("--exclude-dir", default=None,
                    help="directorio del corpus (cz_hunt) para excluir auditados")
    ap.add_argument("--exclude", default=None,
                    help="slugs extra separados por coma")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = run(tag=a.tag, browse=a.browse, pages=a.pages,
              min_installs=a.min, max_installs=a.max, family_min=a.family,
              exclude_dir=a.exclude_dir,
              exclude_slugs=(a.exclude.split(",") if a.exclude else None))
    if a.json:
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return
    print(f"VENDOR-FARM · tag={res['params']['tag'] or res['params']['browse']} "
          f"· {res['total_plugins_nuevos']} plugins nuevos "
          f"· {len(res['familias'])} familias\n")
    for f in res["familias"][:20]:
        print(f">> {f['vendor']} · mejor paga unauth "
              f"${f['mejor_pago_unauth_usd']:,}")
        for p in f["plugins"][:6]:
            print(f"   {p['installs']:>9,}  {p['slug']:<40} "
                  f"unauth ${p['pay']['unauth_usd']:,}")
        print()


if __name__ == "__main__":
    main()
