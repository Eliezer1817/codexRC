#!/usr/bin/env python3
# ============================================================
# codexRC - DOSSIER-HUNT (v0.96.1) — caza con las clases Q4-2026
# ------------------------------------------------------------
# Driver de caza READ-ONLY sobre fuentes publicas de plugins
# WordPress (downloads.wordpress.org), con las clases nuevas del
# dossier: POI-REACH (Object Injection con alcance+gadget) y
# MAGIC-CONFUSION (extension vs contenido hacia Imagick).
#
# Reusa la infra de plugin_batch (descarga + filtro de ruido de
# librerias). Anti-FP: hallazgos dentro de vendor/lib NO se
# reportan (NOISE_RE de plugin_batch).
#
# Uso:
#   python3 core/dossier_hunt.py slug1 slug2 ...
#   python3 core/dossier_hunt.py --populares 40
#   python3 core/dossier_hunt.py slug --version 1.2.3   # calibracion
#
# Escalera honesta: solo POI-REACH y MAGIC-CONFUSION son
# 💥; POI-AUTH/POI-DETECTED son pistas, CONFUSION-GUARDED
# es defensa correcta.
# ============================================================
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core import plugin_batch as pb          # noqa: E402
from core.poi_reach import poi_audit         # noqa: E402
from core.magic_confusion import confusion_audit  # noqa: E402


def _hunt_slug(slug: str, workdir: str,
               version: str = "",
               budget: int = 150) -> dict:
    """Descarga (o reusa) y audita un slug con las clases nuevas.

    budget: segundos maximos de CPU-por-plugin (senal SIGALRM);
    gigantes como booking-manager se cortan honestos con TIMEOUT.
    """
    import signal
    import zipfile
    import urllib.request

    def _alrm(signum, frame):
        raise TimeoutError(f"budget {budget}s excedido")
    signal.signal(signal.SIGALRM, _alrm)
    signal.alarm(budget)

    target = os.path.join(workdir, slug)
    src = None
    if version:
        url = ("https://downloads.wordpress.org/plugin/"
               f"{slug}.{version}.zip")
        dest = os.path.join(workdir, f"{slug}-{version}.zip")
        target = os.path.join(workdir, f"{slug}-{version}")
        if not os.path.isdir(target):
            if not os.path.isfile(dest):
                urllib.request.urlretrieve(url, dest)
            with zipfile.ZipFile(dest) as z:
                z.extractall(target)
        src = target
    else:
        src = pb.download(slug, workdir)
    if not src:
        return {"slug": slug, "error": "descarga fallida"}

    def es_ruido(f: str) -> bool:
        return pb.is_noise(f)

    # --- POI-REACH ---
    poi = poi_audit(src)
    poi_clean = []
    for f in poi["findings"]:
        if es_ruido(f["file"]):
            continue
        gadgets = [g for g in f.get("gadgets", [])
                   if not es_ruido(g["file"])]
        f["gadgets"] = gadgets
        if f["verdict"] == "POI-REACH" and not gadgets:
            # gadget solo en librerias: no es alcance real
            f["verdict"] = "POI-AUTH"
        poi_clean.append(f)
    poi["findings"] = poi_clean

    # --- MAGIC-CONFUSION ---
    mag = confusion_audit(src)
    mag_clean = [f for f in mag["findings"]
                 if not es_ruido(f["file"])]
    mag["findings"] = mag_clean

    signal.alarm(0)  # presupuesto cumplido: cancelar
    return {"slug": slug, "version": version or "latest",
            "installs": pb.installs_for(slug),
            "poi": {"summary": poi["summary"],
                    "findings": poi_clean},
            "magic": {
                "summary": {
                    "confusion": sum(
                        1 for f in mag_clean
                        if f["verdict"] == "MAGIC-CONFUSION"),
                    "guarded": sum(
                        1 for f in mag_clean
                        if f["verdict"]
                        == "CONFUSION-GUARDED")},
                "findings": mag_clean}}


def _populares(n: int) -> list:
    """Top popular de wordpress.org via API publica."""
    import urllib.request
    url = ("https://api.wordpress.org/plugins/info/1.2/"
           "?action=query_plugins&request%5Bbrowse%5D=popular"
           f"&request%5Bper_page%5D={n}&request%5Bpage%5D=1")
    with urllib.request.urlopen(url, timeout=30) as r:
        data = json.loads(r.read().decode())
    return [p["slug"] for p in
            data.get("plugins", [])][:n]


def main() -> None:
    argv = sys.argv[1:]
    version = ""
    pop_n = 0
    args = []
    skip = False
    for a in argv:
        if skip:
            skip = False
            continue
        if a == "--version" or a == "--populares":
            if a == "--version":
                version = argv[argv.index(a) + 1]
            else:
                pop_n = int(argv[argv.index(a) + 1])
            skip = True
            continue
        if not a.startswith("--"):
            args.append(a)

    workdir = "/tmp/dossier_hunt"
    os.makedirs(workdir, exist_ok=True)

    slugs = args
    if pop_n:
        slugs = _populares(pop_n)
        print(f"[hunt] top popular: {len(slugs)} slugs")
    if not slugs:
        print("uso: dossier_hunt.py slug1 slug2 | "
              "--populares N | slug --version X")
        sys.exit(1)

    results = []
    for i, slug in enumerate(slugs, 1):
        try:
            r = _hunt_slug(slug, workdir, version)
        except TimeoutError as e:
            r = {"slug": slug, "error": "TIMEOUT " + str(e)}
        except Exception as e:
            r = {"slug": slug, "error": f"{type(e).__name__}: {e}"}
        finally_holder = None
        results.append(r)
        sm = r.get("poi", {}).get("summary", {})
        mg = r.get("magic", {}).get("summary", {})
        tag = ""
        if sm.get("poi_reach"):
            tag = " 💥POI-REACH"
        elif sm.get("poi_auth"):
            tag = " •POI-AUTH(pista)"
        if mg.get("confusion"):
            tag += " 💥MAGIC-CONFUSION"
        print(f"[{i}/{len(slugs)}] {slug}: "
              f"installs={r.get('installs', '?')} "
              f"poi={sm.get('poi_reach', 0)}/"
              f"{sm.get('poi_auth', 0)}/"
              f"{sm.get('poi_detected', 0)} "
              f"magic={mg.get('confusion', 0)}"
              f"{tag}", flush=True)
        for f in r.get("poi", {}).get("findings", []):
            if f["verdict"] in ("POI-REACH", "POI-AUTH"):
                print(f"    [{f['verdict']}] {f['file']}:"
                      f"{f['line']} "
                      f"handler={f.get('handler', '?')} "
                      f"gadgets={len(f.get('gadgets', []))}"
                      f"{' [export]' if f.get('export_surface') else ''}")
        for f in r.get("magic", {}).get("findings", []):
            if f["verdict"] == "MAGIC-CONFUSION":
                print(f"    [MAGIC-CONFUSION] {f['file']}:"
                      f"{f['line']} via={f.get('entry_var')}")

    out = os.path.join(workdir, "dossier_hunt.json")
    with open(out, "w") as fh:
        json.dump(results, fh, indent=1)
    print(f"[hunt] JSON completo: {out}")


if __name__ == "__main__":
    main()
