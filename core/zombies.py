#!/usr/bin/env python3
"""ZOMBIE-KILL — mata procesos zombis y duplicados del backend CodexRC.

Leccion aprendida (27/09/2026, supervisor del bot de trading): pgrep/pkill -f
matchea el PROPIO bash del comando (falso zombi). Este modulo NO usa pgrep:
lee /proc directamente y excluye su propio PID y el de su padre.

Criterios:
 1. Estado Z (zombi real: no consume CPU, el kernel los reapa con su padre;
    si el padre es nuestro server muerto, quedan colgando).
 2. DUPLICADOS: dos+ procesos python ejecutando backend/app.py. El mas viejo
    (menor PID, no, mayor tiempo de inicio -> el de menor PID suele ser el
    primero) SOBREVIVE; el resto muere por PID con kill -9, nunca pkill -f.

Uso:
  python3 core/zombies.py            # listado (no mata nada)
  python3 core/zombies.py --kill    # mata duplicados (deja 1 vivo)
"""
import os
import signal
import sys
import time

MARCA = "backend/app.py"
EXCLUIR = {os.getpid(), os.getppid()}


def _procos() -> dict:
    pinfo = {}
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as fh:
                cmd = fh.read().replace(b"\x00", b" ").decode("utf-8", "replace").strip()
            if not cmd:
                continue
            with open(f"/proc/{pid}/stat") as fh:
                estado = fh.read().split(") ", 1)[1].split(" ")[0]
            pinfo[int(pid)] = {"cmd": cmd, "estado": estado}
        except (OSError, IndexError, UnicodeDecodeError):
            continue
    return pinfo


def listar() -> list:
    """[(pid, estado, cmd, es_duplicado)] de procesos CodexRC + zombis."""
    procs = _procos()
    out = []
    vivos_backend = []
    for pid, p in sorted(procs.items()):
        if p["estado"] == "Z":
            out.append({"pid": pid, "tipo": "ZOMBIE", "cmd": p["cmd"][:120], "matar": False})
        elif pid not in EXCLUIR and MARCA in p["cmd"] and p["estado"] not in ("Z",):
            vivos_backend.append(pid)
            out.append({"pid": pid, "tipo": "backend", "cmd": p["cmd"][:120], "matar": False})
    # duplicados: dejar 1 (el de menor PID = el mas antiguo), matar el resto
    for item in out:
        if item["tipo"] == "backend" and len(vivos_backend) > 1 and item["pid"] != vivos_backend[0]:
            item["tipo"] = "DUPLICADO"
            item["matar"] = True
    return out


def matar(sec: float = 0.0) -> dict:
    """Mata DUPLICADOS por PID (kill -9). Zombis: avisa (los reapa el padre)."""
    resultado = {"matados": [], "zombis": [], "error": ""}
    for item in listar():
        if item["tipo"] == "DUPLICADO":
            try:
                os.kill(item["pid"], signal.SIGKILL)
                resultado["matados"].append(item["pid"])
                time.sleep(sec)
            except OSError as exc:
                resultado["error"] = str(exc)[:120]
        elif item["tipo"] == "ZOMBIE":
            resultado["zombis"].append(item["pid"])
    if resultado["zombis"]:
        resultado["error"] += (f" ({len(resultado['zombis'])} zombis Z reales: los limpia su "
                              "proceso padre al morir; si persisten, kill al padre).")
    return resultado


def main() -> int:
    if "--kill" in sys.argv:
        r = matar()
        print(f"[ZOMBIES] matados por PID: {r['matados'] or 'ninguno'}")
        if r["zombis"]:
            print(f"[ZOMBIES] zombis Z reales (los reapa el padre): {r['zombis']}")
        if r["error"]:
            print(f"[ZOMBIES] nota: {r['error']}")
        return 0
    items = listar()
    if not items:
        print("[ZOMBIES] todo limpio: 1 backend vivo, 0 zombis, 0 duplicados")
        return 0
    for it in items:
        print(f"  PID {it['pid']:>7} {it['tipo']:<10} {it['cmd']}")
    dup = sum(1 for i in items if i["tipo"] == "DUPLICADO")
    print(f"\n[ZOMBIES] {'⚠ ' + str(dup) + ' duplicados: corre core/zombies.py --kill' if dup else 'sin duplicados'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
