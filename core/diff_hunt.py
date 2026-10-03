#!/usr/bin/env python3
# ============================================================
# codexRC - DIFF-HUNT (v0.45.0)
# ------------------------------------------------------------
# Pivote de estrategia: en vez de auditar plugins enteros
# (los top ya estan blindados), caza SOLO el codigo nuevo.
# Descarga la version actual y la anterior de cada plugin con
# VDP activo, calcula el diff (lineas agregadas/modificadas en
# archivos .php propios del plugin) y corre TAINT-TRACE +
# CVE-MATCH + GATES-AUDIT + FP-AUTO-CLOSE restringido a esas
# lineas nuevas.
#
# Logica: lo recien escrito no paso por ningun auditor ni
# por los bots de los demas hunters.
#
# Uso:
#   python3 core/diff_hunt.py slug1 slug2 ... [--vdp vdp.json]
#   python3 core/diff_hunt.py slugs.txt --vdp vdp.json --out r.json
# Salida: solo hallazgos VIVOS sobre lineas nuevas. 💥 = critico.
# ============================================================
import argparse
import concurrent.futures
import difflib
import json
import os
import re
import sys
import time
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.taint_trace import trace_path  # noqa: E402
from core.pattern_match import scan_path  # noqa: E402
from core.gates_audit import audit as gates_audit  # noqa: E402
from core.fp_autoclose import annotate_all as fp_annotate  # noqa: E402
from core.fp_autoclose import es_ruido_publico  # noqa: E402
from core.plugin_batch import is_noise  # noqa: E402

INFO_URL = ("https://api.wordpress.org/plugins/info/1.2/"
            "?action=plugin_information&request[slug]={}")
WORK = "/tmp/plugin_diff"


def _info(slug: str) -> Optional[Dict[str, Any]]:
    try:
        with urllib.request.urlopen(INFO_URL.format(slug), timeout=20) as r:
            return json.load(r)
    except Exception:
        return None


def _fetch(url: str, path: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=120) as r:
            data = r.read()
        open(path, "wb").write(data)
        return True
    except Exception:
        return False


def _unzip(zip_path: str, dest: str) -> bool:
    try:
        with zipfile.ZipFile(zip_path) as z:
            z.extractall(dest)
        return True
    except Exception:
        return False


def _zip_url(slug: str, ver: str) -> str:
    """URL canonica de descarga de una version (usada si la API no
    devuelve el mapa de URLs)."""
    return (f"https://downloads.wordpress.org/plugin/"
            f"{slug}.{ver}.zip")


def get_versions(slug: str) -> Optional[Tuple[str, str, str, str]]:
    """(version_nueva, version_anterior, url_nueva, url_anterior)."""
    info = _info(slug)
    if not info:
        return None
    # la API de wp.org devuelve "versions" como dict {ver: url} o como
    # lista [ver, ...] (forma cambiada en 2026-10); normalizar ambas
    vv = info.get("versions") or {}
    if isinstance(vv, dict):
        urls = vv
        versions = list(vv.keys())
    else:
        versions = [v for v in vv if isinstance(v, str)]
        urls = {v: _zip_url(slug, v) for v in versions}
    # la ultima clave suele ser "trunk"; versiones estables reales antes
    stable = [v for v in versions
              if re.match(r"^\d+(\.\d+)*$", v) and v != "trunk"]
    if len(stable) < 2:
        return None
    stable.sort(key=lambda t: [int(x) for x in t.split(".")])
    new_v, old_v = stable[-1], stable[-2]
    if new_v not in urls or old_v not in urls:
        return None
    return new_v, old_v, urls[new_v], urls[old_v]


def _senales_changelog(slug: str) -> list:
    """Palabras de seguridad del changelog publico (readme trunk).
    wp.org sello el historial de zips (oct 2026): el readme sigue
    diciendo QUE parchearon y DONDE; eso guia la caza del parche
    incompleto."""
    try:
        req = urllib.request.Request(
            f"https://plugins.svn.wordpress.org/{slug}/trunk/readme.txt",
            headers={"User-Agent": "Mozilla/5.0"})
        txt = urllib.request.urlopen(req, timeout=15).read().decode(
            "utf-8", "replace")
    except Exception:
        return []
    i = txt.lower().find("== changelog ==")
    if i < 0:
        return []
    trozo = txt[i:i + 4000]           # ultimas ~4-6 versiones
    out = []
    for lin in trozo.split("\n"):
        lin = lin.strip()
        if not lin:
            continue
        m = re.match(r"^(?:=+\s*)?(?:\d{4}\.\d\d\.\d\d\s*-\s*)?"
                     r"version\s*([\d.]+)\s*=*$", lin, re.I)
        if m:
            out.append({"version": m.group(1), "lineas": []})
            if len(out) >= 3:          # solo lo mas reciente
                break
            continue
        if out and re.search(r"secur|xss|sql|inject|sanitiz|escap|"
                            r"nonce|privileg|capabilit|upload|"
                            r"harden|vulnerab|csrf|auth", lin, re.I):
            out[-1]["lineas"].append(lin[:140])
    return [e for e in out if e["lineas"]]


def prepare(slug: str, workdir: str) -> Optional[Tuple[str, str, str]]:
    """Descarga las 2 versiones; devuelve (dir_new, dir_old, v_new).
    Si wp.org ya no sirve el historial (oct 2026: zips viejos 404,
    SVN tags vacios, API sin mapa): fallback FULL-CODE con la version
    ACTUAL (dir_old=None) -> scan() audita todo el codigo vivo."""
    os.makedirs(workdir, exist_ok=True)
    vers = get_versions(slug)
    if not vers:
        info = _info(slug)
        if not info or not info.get("download_link"):
            return None
        d_new = os.path.join(workdir, f"{slug}_new")
        zp = os.path.join(workdir, f"{slug}.zip")
        if not _fetch(info["download_link"], zp) or not _unzip(zp, d_new):
            return None
        return d_new, None, info.get("version") or "?"
    new_v, old_v, new_u, old_u = vers
    d_new = os.path.join(workdir, f"{slug}_new")
    d_old = os.path.join(workdir, f"{slug}_old")
    if not os.path.isdir(d_new) or not os.path.isdir(d_old):
        z_new = os.path.join(workdir, f"{slug}_{new_v}.zip")
        z_old = os.path.join(workdir, f"{slug}_{old_v}.zip")
        if not os.path.isfile(z_new):
            if not _fetch(new_u, z_new):
                return None
        if not os.path.isfile(z_old):
            if not _fetch(old_u, z_old):
                return None
        if not os.path.isdir(d_new):
            _unzip(z_new, d_new)
        if not os.path.isdir(d_old):
            _unzip(z_old, d_old)
    # raiz interna (carpeta con slug dentro del zip)
    def _root(d: str) -> str:
        if not os.path.isdir(d):
            return d
        subs = [x for x in os.listdir(d)
                if os.path.isdir(os.path.join(d, x))]
        if len(subs) == 1:
            return os.path.join(d, subs[0])
        return d
    rn, ro = _root(d_new), _root(d_old)
    if not os.path.isdir(rn) or not os.path.isdir(ro):
        return None
    return rn, ro, new_v


def changed_lines(new_root: str,
                  old_root: Optional[str] = None) -> Dict[str, Set[int]]:
    """Si old_root es None (sin historial): TODAS las lineas cuentan
    (modo FULL-CODE: cada hallazgo del codigo vivo pasa el filtro)."""
    if old_root is None:
        out: Dict[str, Set[int]] = {}
        for raiz, _dirs, archivos in os.walk(new_root):
            for a in archivos:
                if a.endswith(".php"):
                    p = os.path.join(raiz, a)
                    rel = p.split(new_root, 1)[1].lstrip("/").replace(
                        "\\", "/")
                    try:
                        with open(p, encoding="utf-8",
                                  errors="ignore") as f:
                            out[rel] = set(range(1, f.read().count(
                                "\n") + 2))
                    except Exception:
                        pass
        return out
    """{relpath: lineas nuevas} en .php propios (sin vendor/assets)."""
    out: Dict[str, Set[int]] = {}
    for dirpath, _dirs, files in os.walk(new_root):
        for f in files:
            if not f.lower().endswith(".php"):
                continue
            p_new = os.path.join(dirpath, f)
            rel = os.path.relpath(p_new, new_root).replace("\\", "/")
            if is_noise(rel):
                continue
            p_old = os.path.join(old_root, rel)
            try:
                src_new = open(p_new, encoding="utf-8",
                               errors="ignore").read().split("\n")
            except Exception:
                continue
            if not os.path.isfile(p_old):
                out[rel] = set(range(1, len(src_new) + 1))  # archivo nuevo
                continue
            try:
                src_old = open(p_old, encoding="utf-8",
                               errors="ignore").read().split("\n")
            except Exception:
                continue
            sm = difflib.SequenceMatcher(a=src_old, b=src_new, autojunk=False)
            lines: Set[int] = set()
            for op, i1, i2, j1, j2 in sm.get_opcodes():
                if op in ("insert", "replace"):
                    lines.update(range(j1 + 1, j2 + 1))
            if lines:
                out[rel] = lines
    return out


def scan(slug: str, workdir: str) -> Dict[str, Any]:
    t0 = time.time()
    rec: Dict[str, Any] = {"slug": slug, "hallazgos": []}
    prep = prepare(slug, workdir)
    if not prep:
        rec["status"] = "sin_versiones"
        return rec
    new_root, old_root, new_v = prep
    rec["version"] = new_v
    rec["modo"] = "DIFF" if old_root else "FULL-CODE"
    rec["status"] = "ok"
    if old_root is None:
        rec["senales_changelog"] = _senales_changelog(slug)

    nuevas = changed_lines(new_root, old_root)
    rec["archivos_php_nuevos"] = len(nuevas)
    rec["lineas_nuevas"] = sum(len(v) for v in nuevas.values())
    if not nuevas:
        rec["hallazgos"] = []
        return rec

    taint = trace_path(new_root, top=100)
    # SSA-lite: cadena def-use + refutacion de FPs por nombre
    try:
        from core.ssa import enrich as ssa_enrich
        taint = ssa_enrich(new_root, taint)
        taint = [t for t in taint if not t.get("ssa_refuted")]
    except Exception:
        pass
    try:
        pats = scan_path(new_root, top=100)
    except Exception:
        pats = []
    try:
        gates = gates_audit(new_root)
    except Exception:
        gates = {"handlers": []}

    seen, vivos = set(), []
    for h in taint + pats:
        f = h.get("file", "")
        if new_root in f:
            f = f.split(new_root, 1)[1].lstrip("/")
        rel = f.replace("\\", "/")
        line = int(h.get("line", 0) or 0)
        key = (rel, line)
        if key in seen:
            continue
        seen.add(key)
        if rel not in nuevas:        # solo hallazgos en codigo nuevo
            continue
        if line not in nuevas[rel] and \
           not any(abs(line - L) <= 2 for L in nuevas[rel]):
            continue
        h["file"] = rel
        # gate del handler donde cae
        h["_gate"] = "SIN-HANDLER"
        for g in gates.get("handlers", []):
            if g.get("archivo_callback", "") == rel and \
               g.get("linea_callback", 10**9) <= line:
                h["_gate"] = g.get("veredicto", "?")
                break
        vivos.append(h)
    fp_annotate(vivos, new_root)
    vivos = [h for h in vivos if not h.get("_fp")]
    # v0.47.0: cadena de evidencia + abogados (fiscal/defensa/juez)
    try:
        from core.evidence import annotate as evidence_annotate
        evidence_annotate(new_root, vivos, gates,
                          analyzers=["TAINT-TRACE", "GATES-AUDIT",
                                     "FP-AUTO-CLOSE", "DIFF-HUNT"])
    except Exception:
        pass
    order_v = {"CONFIRMED": 0, "DEMOSTRADO-ESTATICO": 1, "PROBABLE": 2,
               "CONTESTADO": 3, "DESCARTADO": 4}
    n_desc = sum(1 for h in vivos if h.get("_verdict") == "DESCARTADO")
    vivos.sort(key=lambda h: (order_v.get(h.get("_verdict", ""), 5),
                              0 if h.get("_gate") in
                              ("CANDIDATO-BAC", "REST-ABIERTO",
                                   "PRIVILEGIO-DEBIL",
                                   "CANDIDATO-IDOR") else 1))
    vivos = [h for h in vivos if h.get("_verdict") != "DESCARTADO"]
    rec["hallazgos"] = vivos
    rec["descartados_defensa"] = n_desc
    rec["segundos"] = round(time.time() - t0, 1)
    return rec


def main() -> None:
    ap = argparse.ArgumentParser(description="DIFF-HUNT: caza en lineas nuevas")
    ap.add_argument("slugs", nargs="*")
    ap.add_argument("--vdp", default="")
    ap.add_argument("--out", default="")
    ap.add_argument("--workdir", default=WORK)
    ap.add_argument("--workers", type=int, default=4)
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
        print("uso: diff_hunt.py slug1 slug2 ... | slugs.txt | stdin")
        sys.exit(1)

    vdp: Dict[str, Any] = {}
    if args.vdp and os.path.isfile(args.vdp):
        try:
            vdp = json.load(open(args.vdp))
        except Exception:
            pass

    results = []
    done = [0]

    def report(rec):
        done[0] += 1
        if rec.get("slug") in vdp:
            rec["vdp"] = True
        results.append(rec)
        if rec.get("status") != "ok":
            print(f"[{done[0]}/{len(slugs)}] {rec['slug']}: "
                  f"{rec.get('status')}", flush=True)
            return
        vivos = rec["hallazgos"]
        crit = [h for h in vivos if str(h.get("severity", "")).lower()
                in ("critical", "alta", "high")]
        mark = "💥💥" if crit else ("💥" if vivos else "✅")
        vdp_tag = " [VDP ACTIVO]" if rec.get("vdp") else ""
        print(f"[{done[0]}/{len(slugs)}] {mark} {rec['slug']} "
              f"v{rec['version']}: "
              f"+{rec['archivos_php_nuevos']} archivos, "
              f"+{rec['lineas_nuevas']} lineas nuevas, "
              f"{len(vivos)} vivos{vdp_tag} "
              f"({rec.get('segundos', '?')}s)", flush=True)
        for h in vivos[:12]:
            print(f"   [{h.get('severity', '?')}] "
                  f"{h.get('type', h.get('family', '?'))} "
                  f"{h.get('file', '')}:{h.get('line', '')} "
                  f"verdicto={h.get('_verdict', '?')} gate={h.get('_gate', '?')}", flush=True)

    with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.workers) as ex:
        futs = [ex.submit(scan, slug, args.workdir) for slug in slugs]
        for fut in concurrent.futures.as_completed(futs):
            rec = fut.result()
            if rec is None:
                continue
            report(rec)

    if args.out:
        with open(args.out, "w") as f:
            json.dump({"resultados": results}, f, indent=1)
        print(f"\nJSON -> {args.out}")


if __name__ == "__main__":
    main()
