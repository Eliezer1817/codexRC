#!/usr/bin/env python3
# ============================================================
# codexRC - PIPE-HUNT (modo tuberia)
# ------------------------------------------------------------
# Recibe URLs por stdin (una por linea) desde cualquier otra
# herramienta y las caza a traves del Hunter del backend local.
#
#   waybackurls objetivo.com | python3 hunt_pipe.py
#   cat urls.txt | python3 hunt_pipe.py --xsspro --workers 8
#   cat urls.txt | python3 hunt_pipe.py --no-wait          (solo encola)
#
# Cada URL se envia como un job del Hunter (misma API que la
# interfaz web). Con --wait (default) el script vigila cada job
# hasta terminar e imprime un resumen final.
# ============================================================
import argparse
import json
import sys
import time
import urllib.request
import urllib.error

API = "http://127.0.0.1:8000"


def post(path, payload):
    req = urllib.request.Request(
        API + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())


def get(path):
    with urllib.request.urlopen(API + path, timeout=30) as r:
        return json.loads(r.read().decode())


def main():
    ap = argparse.ArgumentParser(description="codexRC PIPE-HUNT: caza URLs desde stdin")
    ap.add_argument("--workers", type=int, default=4, help="sondas simultaneas por caza (1-8)")
    ap.add_argument("--max-pages", type=int, default=25)
    ap.add_argument("--delay", type=float, default=0.15, help="pausa por sonda (cortesia)")
    ap.add_argument("--xsspro", action="store_true", help="activar bateria XSS-PRO")
    ap.add_argument("--blind", action="store_true", help="activar blind XSS (ESCRIBE en el blanco)")
    ap.add_argument("--blind-endpoint", default="", help="colector blind (ej. GHOSTHOOK)")
    ap.add_argument("--no-xsspro", dest="xsspro", action="store_false")
    ap.add_argument("--no-wait", action="store_true", help="solo encolar, no esperar resultados")
    args = ap.parse_args()

    urls = [l.strip() for l in sys.stdin if l.strip() and not l.startswith("#")]
    if not urls:
        print("PIPE-HUNT: nada por stdin. Uso: waybackurls sitio.com | python3 hunt_pipe.py")
        return 1
    print(f"PIPE-HUNT · {len(urls)} URLs encolando ({args.workers} workers)")

    jobs = []
    for i, u in enumerate(urls, 1):
        payload = {
            "url": u,
            "max_pages": args.max_pages,
            "workers": args.workers,
            "delay": args.delay,
            "opt_get": True, "opt_forms": True, "opt_headers": True, "opt_dom": True,
            "opt_paths": True, "opt_api": True, "opt_api_js": True, "opt_idor": True,
            "opt_params_plus": True, "opt_csp": True,
            "opt_xss_pro": args.xsspro,
            "opt_blind": args.blind,
        }
        if args.blind and args.blind_endpoint:
            payload["blind_endpoint"] = args.blind_endpoint
        try:
            r = post("/api/hunter", payload)
            jobs.append((u, r["job_id"]))
            print(f"  [{i}/{len(urls)}] {u} -> job {r['job_id']}")
        except Exception as exc:
            print(f"  [{i}/{len(urls)}] {u} -> FALLO: {exc}")
    if args.no_wait or not jobs:
        return 0

    print("\nPIPE-HUNT · vigilando cazas (Ctrl+C para dejarlas correr)")
    pend = dict(jobs)
    total = {"findings": 0, "altas": 0, "ok": 0, "bad": 0}
    while pend:
        time.sleep(5)
        for url, jid in list(pend.items()):
            try:
                j = get(f"/api/jobs/{jid}")
            except Exception:
                continue
            if j.get("status") in ("finished", "failed", "interrupted"):
                del pend[url]
                fnd = j.get("findings", [])
                altas = len([f for f in fnd if f.get("severity") == "alta"])
                total["findings"] += len(fnd)
                total["altas"] += altas
                if j["status"] == "finished":
                    total["ok"] += 1
                    print(f"✓ {url} · {len(fnd)} hallazgos ({altas} altas)")
                else:
                    total["bad"] += 1
                    print(f"✗ {url} · {j['status']}: {j.get('error', '?')[:80]}")
    print(f"\nPIPE-HUNT ══ {total['ok']} cazas OK, {total['bad']} fallidas, "
          f"{total['findings']} hallazgos, {total['altas']} ALTAS 💥")
    return 0


if __name__ == "__main__":
    sys.exit(main())
