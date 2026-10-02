#!/usr/bin/env python3
# ============================================================
# codexRC - PLUGIN-BATCH (v0.42.0)
# ------------------------------------------------------------
# Modo agente: un solo comando recibe slugs de plugins
# WordPress, descarga la ultima version estable, y corre el
# arsenal ESTATICO del Hunter (TAINT-TRACE + CVE-MATCH),
# con capa VERIFICACION: filtra ruido de librerias y deja
# solo hallazgos en codigo propio del plugin.
#
# Uso:
#   python3 core/plugin_batch.py slug1 slug2 ...
#   echo "slug1\nslug2" | python3 core/plugin_batch.py
#   python3 core/plugin_batch.py --vdp cz_hunt/vdp/vdp_matches.json
#   python3 core/plugin_batch.py slugs.txt --out resultados.json
#
# Salida: resumen en consola (💥 = criticos) + JSON completo.
# Nivel de confianza por hallazgo: HIGH (taint confirmado en
# codigo propio) / MED (patron con outlier del baseline) /
# LOW (ruido ya filtrado, no se reporta).
# ============================================================
import argparse
import json
import os
import re
import sys
import subprocess
import tempfile
import time
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.taint_trace import trace_path  # noqa: E402
from core.pattern_match import scan_path  # noqa: E402
from core import vendor_farm  # noqa: E402
from core.gates_audit import audit as gates_audit  # noqa: E402
from core.fp_autoclose import annotate_all as fp_annotate  # noqa: E402
from core.fp_autoclose import es_ruido_publico  # noqa: E402

DL_URL = "https://downloads.wordpress.org/plugin/{}.latest-stable.zip"

# rutas que NO son codigo propio del plugin (librerias de terceros)
NOISE_RE = re.compile(
    r"/(vendor|node_modules|library|libraries|assets|bower_components|"
    r"includes/lib|sdk|codemirror|elFinder|elfinder|freemius|tcpdf|"
    r"phpoffice|scssphp|simplepie|svg-sanitizer|phar-io)(/|$)", re.I)
# extensiones que no son logica del plugin
SKIP_EXT = (".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".woff2",
            ".ttf", ".eot", ".map", ".html", ".htm", ".txt", ".md", ".pot",
            ".po", ".mo", ".xml", ".json", ".min.")


def is_noise(path: str) -> bool:
    p = "/" + path.replace("\\", "/").lstrip("/")
    if NOISE_RE.search(p):
        return True
    # double check: extension
    low = p.lower()
    if low.endswith(SKIP_EXT):
        return True
    if low.endswith(".php") and "/tests/" in low and "/phpunit" in low:
        return True
    return False


def download(slug: str, workdir: str) -> Optional[str]:
    """Descarga y descomprime; devuelve ruta del codigo o None."""
    dest = os.path.join(workdir, slug)
    if os.path.isdir(dest):
        return dest  # cache de corridas anteriores
    zip_path = os.path.join(workdir, slug + ".zip")
    try:
        with urllib.request.urlopen(DL_URL.format(slug), timeout=90) as r:
            data = r.read()
        with open(zip_path, "wb") as f:
            f.write(data)
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(workdir)
        os.remove(zip_path)
        return dest if os.path.isdir(dest) else None
    except Exception:
        return None


def installs_for(slug: str) -> int:
    """Instalaciones activas via API wp.org (para estimar pago)."""
    try:
        url = ("https://api.wordpress.org/plugins/info/1.2/"
               "?action=plugin_information&request[slug]={}").format(slug)
        with urllib.request.urlopen(url, timeout=15) as r:
            d = json.load(r)
        return d.get("active_installs") or 0
    except Exception:
        return 0


def scan_slug(slug: str, workdir: str, vdp: Dict[str, Any],
              top: int = 25) -> Dict[str, Any]:
    t0 = time.time()
    code = download(slug, workdir)
    rec: Dict[str, Any] = {"slug": slug, "vdp": vdp.get(slug, {}),
                            "status": "ok", "hallazgos": []}
    if not code:
        rec["status"] = "download_error"
        return rec

    # 1) TAINT-TRACE: flujo fuente->sink
    taint = trace_path(code, top=top)
    # 2) CVE-MATCH: patrones de familias CVE reales + outlier baseline
    try:
        pats = scan_path(code, top=top)
    except Exception:
        pats = []

    # 3) VERIFICACION: fusion + filtro de ruido + dedupe
    seen, clean = set(), []
    for h in taint + pats:
        f = h.get("file", "")
        # ruta relativa a la raiz del plugin (salida legible)
        if code and code in f:
            f = f.split(code, 1)[1].lstrip("/")
        h["file"] = f
        line = h.get("line", 0)
        key = (f, line)
        if key in seen:
            continue
        seen.add(key)
        if is_noise(f):
            continue
        h["_origin"] = "taint" if h in taint else "pattern"
        clean.append(h)

    # 4) GATES-AUDIT: veredicto de proteccion por handler
    try:
        gates = gates_audit(code)
    except Exception:
        gates = {"handlers": [], "rest_abiertas": [], "resumen": {}}
    rec["gates_resumen"] = gates.get("resumen", {})
    rec["gates_candidatos"] = [h for h in gates.get("handlers", [])
                               if h.get("veredicto") in ("CANDIDATO-BAC",
                                                         "REVISAR-AUTH")
                               and not es_ruido_publico(h.get("accion", ""))]
    rec["gates_ruido_publico"] = [h.get("accion") for h in
                                 gates.get("handlers", [])
                                 if es_ruido_publico(h.get("accion", ""))]
    for h in clean:
        gv = "SIN-HANDLER"   # archivo propio, fuera de handlers ajax
        for g in gates.get("handlers", []):
            f_cb = g.get("archivo_callback", "")
            ln = h.get("line", 0)
            if f_cb == h.get("file", "") and g.get("linea_callback", 10**9) <= ln:
                gv = g.get("veredicto", "?")
                break
        h["_gate"] = gv
    # 5) FP-AUTO-CLOSE: dictamen de falsos positivos conocidos
    clean = fp_annotate(clean, code)
    clean.sort(key=lambda h: (0 if h.get("_fp") is None else 1,
               0 if h.get("_gate") == "CANDIDATO-BAC" else
               (1 if h.get("_gate") == "REVISAR-AUTH" else 2)))
    rec["hallazgos"] = clean
    rec["resumen"] = {
        "total_crudo": len(taint) + len(pats),
        "propios": len(clean),
        "criticos": sum(1 for h in clean
                        if h.get("_fp") is None and
                        str(h.get("severity", "")).lower() in
                        ("critical", "alta", "high", "error")),
        "fp_autocerrados": sum(1 for h in clean if h.get("_fp")),
        "segundos": round(time.time() - t0, 1),
    }
    return rec


def main() -> None:
    ap = argparse.ArgumentParser(description="PLUGIN-BATCH: caza estatica por slugs")
    ap.add_argument("slugs", nargs="*", help="slugs o archivo .txt con slugs")
    ap.add_argument("--vdp", default="", help="JSON slugs con VDP activo (opcional)")
    ap.add_argument("--out", default="", help="guardar JSON de resultados")
    ap.add_argument("--top", type=int, default=25, help="top por escaneo")
    ap.add_argument("--verbose", action="store_true",
                    help="mostrar tambien hallazgos autocerrados (FP)")
    ap.add_argument("--workdir", default="/tmp/plugin_batch",
                    help="dir de descargas (cache)")
    args = ap.parse_args()

    slugs: List[str] = []
    for s in args.slugs:
        if s.endswith(".txt") and os.path.isfile(s):
            slugs += [x.strip() for x in open(s) if x.strip()]
        else:
            slugs.append(s)
    if not slugs and not sys.stdin.isatty():
        slugs = [x.strip() for x in sys.stdin if x.strip()]
    if not slugs:
        print("uso: plugin_batch.py slug1 slug2 ... | slugs.txt | stdin")
        sys.exit(1)

    vdp: Dict[str, Any] = {}
    if args.vdp and os.path.isfile(args.vdp):
        try:
            vdp = json.load(open(args.vdp))
        except Exception:
            pass

    os.makedirs(args.workdir, exist_ok=True)
    results = []
    for i, slug in enumerate(slugs, 1):
        print(f"[{i}/{len(slugs)}] {slug} ...", flush=True)
        rec = scan_slug(slug, args.workdir, vdp, args.top)
        results.append(rec)
        r = rec.get("resumen", {})
        ncand = len(rec.get("gates_candidatos", []))
        nfp = rec.get("resumen", {}).get("fp_autocerrados", 0)
        mark = "💥💥" if ncand else ("💥" if r.get("propios") else "✅")
        print(f"   {mark} propios={r.get('propios', 0)} "
              f"fp-auto={nfp} "
              f"candidatos-bac={ncand} "
              f"({r.get('segundos', '?')}s)"
              + (" [VDP ACTIVO]" if rec.get("vdp") else ""), flush=True)
        for g in rec.get("gates_candidatos", [])[:8]:
            print(f"      💥 [{g['veredicto']}] {g['accion']} -> "
                  f"{g.get('callback','?')} ({g.get('archivo_callback', g['archivo'])}:"
                  f"{g.get('linea_callback', g['linea_hook'])})", flush=True)
        vivos = [h for h in rec.get("hallazgos", [])
                 if h.get("_fp") is None or args.verbose]
        for h in vivos[:10]:
            fp = f"  [FP:{h.get('_fp')}]" if h.get("_fp") else ""
            print(f"      [{h.get('severity', '?')}] {h.get('type', h.get('family', '?'))}"
                  f" {h.get('file', '')}:{h.get('line', '')}{fp}")

    if args.out:
        with open(args.out, "w") as f:
            json.dump({"resultados": results}, f, indent=1)
        print(f"\nJSON -> {args.out}")


if __name__ == "__main__":
    main()
