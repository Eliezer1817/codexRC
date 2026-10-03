#!/usr/bin/env python3
"""v0.61.0 VDP-FRESH: cazar los VDP RECIEN AGREGADOS a Patchstack.

Palanca de corpus fresco: los plugins que entran NUEVOS al directorio
VDP (patchstack.com/database/vdp) aun no fueron revisados por nadie.
Este modulo mantiene snapshots del mapa VDP y detecta:

  ALTAS    slugs con VDP nuevo (blanco de caza inmediata)
  BOUNTY  plugins ya conocidos que ahora si pagan (sube prioridad)
  BAJAS   VDP retirado (dejar de cazar para reportar)

CLI:
  python3 core/vdp_fresh.py --snapshot          # guarda linea base
  python3 core/vdp_fresh.py --diff vdp_mapa.json
      compara el mapa NUEVO contra el snapshot -> vdp_nuevos.json
  python3 core/vdp_fresh.py --estado            # resumen del snapshot

Flujo semanal: extraer mapa (navegador, GOLDEN LIST) -> --diff ->
vdp_nuevos.json -> hunt_wide --vdp-nuevos (prioridad maxima).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
SNAPSHOT = os.path.join(ROOT, "vdp_snapshot.json")
NUEVOS = os.path.join(ROOT, "vdp_nuevos.json")


def _cargar(path: str) -> dict:
    if not os.path.isfile(path):
        print(f"no existe {path}")
        sys.exit(1)
    return json.load(open(path))


def snapshot(path: str = None) -> dict:
    """Guarda el mapa VDP actual como linea base con fecha."""
    path = path or os.path.join(ROOT, "vdp_mapa.json")
    mapa = _cargar(path)
    snap = {"fecha": _hoy(), "total": len(mapa), "mapa": mapa}
    with open(SNAPSHOT, "w") as f:
        json.dump(snap, f, indent=1)
    print(f"snapshot: {len(mapa)} VDP guardados -> vdp_snapshot.json")
    return snap


def _hoy() -> str:
    import time
    return time.strftime("%Y-%m-%d")


def diff(nuevo_path: str) -> dict:
    """Compara el mapa NUEVO contra el snapshot: altas/bajas/bounty."""
    if not os.path.isfile(SNAPSHOT):
        print("sin snapshot previo: correr --snapshot primero")
        sys.exit(1)
    snap = json.load(open(SNAPSHOT))
    viejo = snap.get("mapa", {})
    nuevo = _cargar(nuevo_path)

    altas = {s: d for s, d in nuevo.items() if s not in viejo}
    bajas = {s: d for s, d in viejo.items() if s not in nuevo}
    bounty = {}
    for s, d in nuevo.items():
        if s in viejo and d.get("bounty") and \
                not viejo[s].get("bounty"):
            bounty[s] = d

    out = {"fecha": _hoy(), "snapshot_previo": snap.get("fecha"),
           "total_viejo": len(viejo), "total_nuevo": len(nuevo),
           "altas": altas, "bounty_nuevos": bounty, "bajas": bajas}
    with open(NUEVOS, "w") as f:
        json.dump(out, f, indent=1)

    # slugs de caza = altas + los que ahora pagan
    cazar = list(altas) + list(bounty)
    print(f"VDP-FRESH vs {snap.get('fecha')}: "
          f"+{len(altas)} altas, +{len(bounty)} con bounty nuevo, "
          f"-{len(bajas)} bajas")
    for s, d in list(altas.items())[:12]:
        print(f"  + {s} ({d.get('installs', '?')} installs, "
              f"bounty {d.get('bounty') or 'sin monto'})")
    if len(altas) > 12:
        print(f"  ... y {len(altas) - 12} mas")
    print(f"cazar: {len(cazar)} -> vdp_nuevos.json")
    return out


def estado() -> None:
    if not os.path.isfile(SNAPSHOT):
        print("sin snapshot: correr --snapshot primero")
        return
    snap = json.load(open(SNAPSHOT))
    pagables = sum(1 for d in snap["mapa"].values() if d.get("bounty"))
    print(f"snapshot del {snap['fecha']}: {snap['total']} VDP "
          f"({pagables} con bounty)")


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="VDP-FRESH")
    ap.add_argument("--snapshot", action="store_true")
    ap.add_argument("--diff", metavar="MAPA_NUEVO")
    ap.add_argument("--estado", action="store_true")
    ap.add_argument("--mapa", default=os.path.join(ROOT, "vdp_mapa.json"))
    args = ap.parse_args()
    if args.snapshot:
        snapshot(args.mapa)
    elif args.diff:
        diff(args.diff)
    elif args.estado:
        estado()
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
