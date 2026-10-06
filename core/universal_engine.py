#!/usr/bin/env python3
"""
UNIVERSAL-ENGINE (v0.52.0) — CodexRC

Orquestador: descubre que es un blanco, modela su superficie y decide
que analizadores activar. Convierte los modulos especializados
(BIN-AUDIT, REVERSE, DECOMPILE, TAINT-TRACE, GATES-AUDIT, COV-BAIT,
EVIDENCE-CHAIN, WP-LAB) en componentes de un motor comun.

Arquitectura (metodologia OWASP: mapear -> auth -> logica -> impacto):

  1. UNIVERSAL-RECON    fingerprint del blanco (que tecnologia/es)
  2. descubrir superficie (que entradas existen)
  3. elegir analizadores segun perfil (no 500 pruebas, las que aplican)
  4. correr componentes (estatico + dinamico + navegador)
  5. UNIVERSAL-EVIDENCE  una sola cadena con FISCAL/DEFENSA/JUEZ
  6. ledger de cobertura: ANALIZADO / DESCUBIERTO / NO ACCESIBLE / VERIFICADO

Uso:
  python3 core/universal_engine.py <path>            # fuente (dir/zip/apk/bin)
  python3 core/universal_engine.py <url>            # app viva (GHOSTGATE si CF)
  python3 core/universal_engine.py <path> --json
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
ROOT = os.path.abspath(os.path.join(HERE, ".."))

# ---- estados de cobertura (4, obligatorios en todo reporte) ----
ANALIZADO = "ANALIZADO"          # superficie efectivamente inspeccionada
DESCUBIERTO = "DESCUBIERTO"      # identificada, todavia no probada
NO_ACCESIBLE = "NO ACCESIBLE"    # no pudo examinarse (y por que)
VERIFICADO = "VERIFICADO"        # comportamiento con evidencia reproducible


# ------------------------------------------------------------------
# 1) UNIVERSAL-RECON: perfil del blanco
# ------------------------------------------------------------------
def _is_url(target: str) -> bool:
    return target.startswith("http://") or target.startswith("https://")


def profile_source(target: str) -> dict:
    """Fingerprint de un blanco de codigo/archivo."""
    prof = {"tipo": "desconocido", "lenguajes": set(), "framework": None,
            "componentes": []}
    if not os.path.exists(target):
        return prof
    exts = {".php": "php", ".js": "js", ".py": "python", ".java": "java",
            ".go": "go", ".rb": "ruby", ".ts": "js", ".kt": "java",
            ".cs": "csharp", ".apk": "apk", ".jar": "jar",
            ".class": "jar", ".so": "elf", ".dex": "apk"}
    lang_files = {}
    if os.path.isfile(target):
        ext = os.path.splitext(target)[1].lower()
        if ext in exts:
            lang_files[exts[ext]] = 1
    else:
        for dirpath, _dirs, files in os.walk(target):
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext in exts:
                    lang_files[exts[ext]] = lang_files.get(exts[ext], 0) + 1
            if sum(lang_files.values()) > 40000:
                break
    prof["lenguajes"] = set(lang_files)
    prof["archivos_por_lenguaje"] = lang_files

    # framework / ecosistema
    marcadores = [
        ("wordpress-plugin", ["wp-content", "wp-plugin", "add_action(",
                               "add_shortcode(", "register_activation_hook"]),
        ("wordpress-tema", ["style.css", "get_header(", "functions.php"]),
        ("drupal", ["Drupal\\", "hook_form_alter"]),
        ("laravel", ["artisan", "Illuminate\\"]),
        ("django", ["manage.py", "settings.py"]),
        ("flask", ["from flask", "Flask("]),
        ("express", ["app.listen(", "express()"]),
        ("react", ["react-scripts", "package.json"]),
        ("android", ["AndroidManifest.xml", "classes.dex"]),
    ]
    if os.path.isdir(target):
        sample = []
        for dirpath, _d, files in os.walk(target):
            for f in files:
                if f.endswith((".php", ".py", ".js", ".json", ".xml")):
                    try:
                        p = os.path.join(dirpath, f)
                        sample.append(open(p, encoding="utf-8",
                                           errors="ignore").read(40000))
                    except Exception:
                        pass
                    if len(sample) > 250:
                        break
            if len(sample) > 250:
                break
        blob = "\n".join(sample)
        for nombre, marcas in marcadores:
            if any(m in blob for m in marcas):
                prof["framework"] = nombre
                break
    return prof


def profile_url(target: str) -> dict:
    """Fingerprint de una app viva (headers, HTML, rutas tipicas)."""
    import urllib.request
    prof = {"tipo": "web", "framework": None, "componentes": [],
            "cloudflare": False}
    try:
        req = urllib.request.Request(target, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            head = {k.lower(): v for k, v in r.headers.items()}
            html = r.read(120000).decode("utf-8", "ignore")
    except Exception as e:
        prof["tipo"] = "web-no-alcanzable"
        prof["error"] = str(e)[:200]
        return prof
    if "cloudflare" in head.get("server", "").lower() or \
       "cf-ray" in head:
        prof["cloudflare"] = True
    for nombre, marcas in [
            ("wordpress", ["wp-content", "wp-json", "wp-includes"]),
            ("drupal", ["/sites/default/files", "drupal"]),
            ("shopify", ["cdn.shopify.com"]),
            ("react", ["__NEXT_DATA__", "react-root", "_app.js"]),
            ("angular", ["ng-version", "angular"]),
            ("vue", ["__NUXT__", "vue-root", "data-v-app"])]:
        if any(m in html for m in marcas):
            prof["framework"] = nombre
            break
    # rutas tipicas = descubiertas (no analizadas todavia)
    prof["rutas_tipicas"] = [r for r in ("/wp-json", "/api", "/graphql",
                                         "/admin", "/login", "/wp-admin")
                             if r in html]
    return prof


# ------------------------------------------------------------------
# 2) seleccion de analizadores segun perfil
# ------------------------------------------------------------------
def choose_analyzers(prof: dict) -> list:
    """El motor elige segun lo descubierto, no corre todo siempre."""
    comps = []
    fw = prof.get("framework")
    langs = prof.get("lenguajes") or set()
    tipo = prof.get("tipo")

    if tipo == "web" or _is_url(str(prof.get("target", ""))):
        comps += ["UNIVERSAL-RECON", "BROWSER-INTEL", "UNIVERSAL-API",
                  "STATE-MACHINE"]
    if fw and "wordpress" in fw:
        comps += ["GATES-AUDIT", "TAINT-TRACE", "CVE-MATCH",
                  "EVIDENCE-CHAIN", "WP-LAB"]
    if "php" in langs:
        comps += ["TAINT-TRACE", "GATES-AUDIT", "CVE-MATCH"]
    if "js" in langs:
        comps += ["POLYGLOT-TRACE(js)"]
    if "python" in langs:
        comps += ["POLYGLOT-TRACE(python)"]
    if "apk" in langs or "jar" in langs:
        comps += ["BIN-AUDIT", "REVERSE", "DECOMPILE"]
    if "elf" in langs:
        comps += ["BIN-AUDIT", "REVERSE"]
    # dedupe, preservando orden
    seen, out = set(), []
    for c in comps:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


# ------------------------------------------------------------------
# 3) ledger de cobertura
# ------------------------------------------------------------------
class Ledger:
    """Registro honesto de superficie: analizado vs descubierto vs
    no accesible vs verificado. Nada se reporta sin estado."""

    def __init__(self):
        self.items = {}

    def add(self, item: str, estado: str, nota: str = ""):
        self.items.setdefault(item, {"estado": estado, "nota": nota})
        # los estados solo escalan hacia evidencia mas fuerte
        orden = {DESCUBIERTO: 0, ANALIZADO: 1, NO_ACCESIBLE: 1,
                 VERIFICADO: 2}
        cur = self.items[item]
        if orden[estado] > orden[cur["estado"]]:
            cur["estado"] = estado
        if nota:
            cur["nota"] = nota

    def resumen(self) -> dict:
        cont = {}
        for it in self.items.values():
            cont[it["estado"]] = cont.get(it["estado"], 0) + 1
        return cont

    def as_dict(self) -> dict:
        return {k: v for k, v in self.items.items()}


# ------------------------------------------------------------------
# 4) pipeline principal
# ------------------------------------------------------------------
def run(target: str) -> dict:
    t0 = time.time()
    led = Ledger()
    prof = (profile_url(target) if _is_url(target)
            else profile_source(target))
    prof["target"] = target
    led.add(f"blanco:{target}", ANALIZADO,
            prof.get("error", ""))

    componentes = choose_analyzers(prof)
    for c in componentes:
        led.add(f"componente:{c}", DESCUBIERTO)

    resultados = {"perfil": {k: (sorted(v) if isinstance(v, set) else v)
                             for k, v in prof.items()},
                  "analizadores_elegidos": componentes}

    # ---- ejecucion de componentes que aplican hoy (kernel v0.52) ----
    src = target if not _is_url(target) and os.path.exists(target) else None
    hallazgos = []

    if src and ("php" in prof.get("lenguajes", set())
                or "wordpress" in str(prof.get("framework"))):
        from core.taint_trace import trace_path
        from core.pattern_match import scan_path
        from core.gates_audit import audit as gates_audit
        from core.fp_autoclose import annotate_all as fp_annotate
        try:
            taint = trace_path(src, top=60)
            led.add("superficie:php-taint", ANALIZADO)
        except Exception as e:
            taint = []
            led.add("superficie:php-taint", NO_ACCESIBLE, str(e)[:120])
        try:
            pats = scan_path(src, top=60)
        except Exception:
            pats = []
        for h in taint + pats:
            hallazgos.append(h)
            led.add(f"entrada:{h.get('type')}@{h.get('file')}",
                    ANALIZADO)
        fp_annotate(hallazgos, src)
        # abilities + gates = superficie ajax/rest descubierta
        try:
            gates = gates_audit(src)
            # v0.99.0: UNIVERSAL ENDPOINT GRAPH como superficie adicional.
            # No reemplaza GATES-AUDIT (hooks clasicos de WP); suma
            # endpoints de routers custom (Slim/Laravel/PSR-7/arrays)
            # que GATES-AUDIT no entiende. Adaptador ya normalizado
            # (to_gates_handlers, v0.98.0): mismo shape, dedup por
            # archivo_callback+linea_callback para no reportar 2 veces
            # el mismo handler si ambos motores lo ven.
            try:
                from core.universal_endpoint import surface_for_target
                usurface = surface_for_target(src)
                existentes = {(h.get("archivo_callback"),
                              h.get("linea_callback"))
                              for h in gates.get("handlers", [])}
                nuevos = [h for h in usurface.get("gates_handlers", [])
                          if (h.get("archivo_callback"),
                              h.get("linea_callback"))
                          not in existentes]
                gates.setdefault("handlers", []).extend(nuevos)
                led.add("superficie:universal-endpoint", ANALIZADO,
                        f"{len(nuevos)} endpoint(s) nuevo(s) via "
                        f"router discovery")
            except Exception as e:
                led.add("superficie:universal-endpoint", NO_ACCESIBLE,
                        str(e)[:120])
            for g in gates.get("handlers", []):
                estado = (ANALIZADO if g.get("veredicto") in
                          ("PROTEGIDO", "CANDIDATO-BAC")
                          else DESCUBIERTO)
                led.add(f"handler:{g.get('accion')}", estado,
                        g.get("veredicto", ""))
            for a in gates.get("abilities_abiertas", []):
                led.add(f"ability:{a.get('ability')}", DESCUBIERTO,
                        a.get("veredicto", ""))
            # cadena de evidencia unica (estatico por ahora)
            try:
                from core.evidence import annotate as evidence_annotate
                vivos = [h for h in hallazgos if not h.get("_fp")]
                evidence_annotate(src, vivos, gates,
                                   analyzers=["UNIVERSAL-ENGINE"])
                for h in vivos:
                    if h.get("_verdict") == "CONFIRMED":
                        led.add(f"entrada:{h.get('type')}@"
                                f"{h.get('file')}:{h.get('line')}",
                                VERIFICADO, "cadena completa")
            except Exception:
                pass
        except Exception:
            pass

    if "apk" in prof.get("lenguajes", set()) or target.endswith((".apk", ".jar")):
        try:
            from core.bin_audit import audit as bin_audit
            from core.re_engine import analyze as re_analyze
            path = target if os.path.isfile(target) else src
            for h in (bin_audit(path) or [])[:40]:
                hallazgos.append(h)
                led.add(f"bin:{h.get('type')}", ANALIZADO)
        except Exception:
            led.add("componente:BIN-AUDIT", NO_ACCESIBLE)

    # WP-LAB (dinamico) y BROWSER-INTEL quedan como fases declaradas:
    # el kernel los ejecuta cuando el operador lo pide (costo alto)
    if "WP-LAB" in componentes:
        led.add("superficie:dinamica-lab", DESCUBIERTO,
                "disponible: AUTH-DIFF en WP-LAB local")
    if "BROWSER-INTEL" in componentes:
        led.add("superficie:navegador", DESCUBIERTO,
                "disponible: GHOSTGATE/CDP cuando aplique")

    vivos = [h for h in hallazgos
             if not h.get("_fp") and h.get("_verdict") != "DESCARTADO"]
    vivos.sort(key=lambda h: (h.get("_verdict") != "CONFIRMED",
                              h.get("_verdict") != "DEMOSTRADO-ESTATICO"))
    resultados["hallazgos"] = vivos
    resultados["cobertura"] = led.as_dict()
    resultados["cobertura_resumen"] = led.resumen()
    resultados["segundos"] = round(time.time() - t0, 1)
    return resultados


def main() -> None:
    ap = argparse.ArgumentParser(description="UNIVERSAL-ENGINE v0.52.0")
    ap.add_argument("target", help="path fuente o URL")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    res = run(args.target)
    if args.json:
        print(json.dumps(res, indent=2, default=str))
        return
    print(f"UNIVERSAL-ENGINE — {args.target}")
    print(f"  perfil: {res['perfil'].get('framework') or res['perfil'].get('tipo')}")
    print(f"  analizadores elegidos: {', '.join(res['analizadores_elegidos'])}")
    print(f"  cobertura: {res['cobertura_resumen']}")
    print(f"  hallazgos vivos: {len(res['hallazgos'])}")
    for h in res["hallazgos"][:15]:
        print(f"    [{h.get('_verdict')}] {h.get('type')} "
              f"{h.get('file')}:{h.get('line')}")


if __name__ == "__main__":
    main()
