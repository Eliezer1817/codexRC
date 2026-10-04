"""LAB SEMANTIC-CACHE (v0.80): 8 escenarios deterministas.

Principio del diseno aprobado:
    LAB ORACLE KNOWS THE TRUTH
    ENGINE ONLY SEES OBSERVABLE EVIDENCE

El lab escribe su ground truth (verdad interna: keys,
decisiones del edge/cache/origin) a un archivo lateral que
el MOTOR (semantic_engine) JAMAS lee. Solo el regresor lo
usa para validar que el escenario representa la clase que
pretende representar y comparar contra el veredicto.

Al motor solo llegan: requests, responses, headers, bodies,
timing, marcadores y observaciones de estado.
"""
import json
import os
import sys
import threading
from http.server import (BaseHTTPRequestHandler,
                         ThreadingHTTPServer)

TRUTHS = {
    "collision_legitima": {
        "clase": "collision legitima (alias por diseno)",
        "verdad_interna": (
            "Todos los paths (excepto sondas de "
            "especificidad) sirven el MISMO recurso por "
            "diseno. Sin estado compartido: stateless."),
        "esperado": "BENIGN"},
    "collision_problematica": {
        "clase": "collision problematica",
        "verdad_interna": (
            "La cache keyea por PRIMER SEGMENTO del path: "
            "todo /seg/* comparte una entrada. El origin "
            "sirve contenido DISTINTO por path completo. "
            "B recibe el cuerpo+ETag de A."),
        "esperado": "DEMO"},
    "fragmentation_legitima": {
        "clase": "fragmentation legitima (Vary)",
        "verdad_interna": (
            "El origin varia el contenido por Cookie y lo "
            "declara con Vary: Cookie. Sin cache."),
        "esperado": "BENIGN"},
    "fragmentation_problematica": {
        "clase": "fragmentation problematica",
        "verdad_interna": (
            "Origin y cache distinguen el CASE del nombre "
            "del header (RFC 7230 3.2 lo define insensible): "
            "dos entradas y dos contenidos para un par "
            "que deberia ser equivalente."),
        "esperado": "INCONSISTENT"},
    "cross_contamination": {
        "clase": "cross-semantic contamination",
        "verdad_interna": (
            "Cache colapsa por primer segmento Y el origin "
            "sirve semantica distinta por path (JSON en a, "
            "HTML en b): B recibe contenido de semantica "
            "ajena."),
        "esperado": "DEMO"},
    "ambiguous_baseline": {
        "clase": "baseline ambiguo",
        "verdad_interna": (
            "El servidor rota el cuerpo en cada request: "
            "nada es caracterizable."),
        "esperado": "UNKNOWN"},
    "normalization_legitima": {
        "clase": "normalizacion legitima total",
        "verdad_interna": (
            "El edge/cache tratan el case del header de "
            "forma insensible (normalizado) con entrada "
            "compartida: A y B comparten estado en "
            "acuerdo."),
        "esperado": "CONSISTENT"},
    "layer_disagreement": {
        "clase": "desacuerdo real entre capas sin impacto",
        "verdad_interna": (
            "El contenido es insensible al case (edge "
            "normaliza), pero la cache keyea CRUDO con slot "
            "unico: solo el primer case-form visto obtiene "
            "persistencia; el otro jamas hace HIT."),
        "esperado": "SUSPICIOUS"},
}

ALIAS_BODY = "ALIAS-SHARED-CONTENT-42"
SPEC_BODY = "SPECIFICITY-PROBE-CONTENT"


class LabState:
    def __init__(self, mode):
        self.mode = mode
        self.store = {}
        self.slot = {}
        self.rot = 0
        self.lock = threading.Lock()


def _seg(path):
    parts = [p for p in path.split("/") if p]
    return parts[0] if parts else "/"


class Handler(BaseHTTPRequestHandler):
    state = None

    def log_message(self, *a):
        pass

    def _send(self, body, etag, ct="text/plain", status=200,
              cache="MISS", age=0, vary=None):
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("ETag", etag)
        self.send_header("X-Cache", cache)
        self.send_header("Age", str(age))
        if vary:
            self.send_header("Vary", vary)
        b = body.encode()
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        st = self.state
        mode = st.mode
        path = self.path.split("?")[0]
        # http.server NORMALIZA el case: para distinguir el
        # case crudo hay que leer el texto original
        raw_headers = self.headers.as_string()
        with st.lock:
            if mode == "ambiguous_baseline":
                st.rot += 1
                self._send("CONTENT-%d" % st.rot,
                           'W/"rot-%d"' % st.rot)
                return
            if path.startswith("/x-specificity"):
                self._send(SPEC_BODY, 'W/"spec"')
                return
            # modos de case: aplican a CUALQUIER path PERO
            # solo cuando la sonda envia el header (fase 2
            # usa paths virgenes nunca tocados)
            if (mode in ("fragmentation_problematica",
                         "normalization_legitima",
                         "layer_disagreement")
                    and "cache-probe: " in raw_headers.lower()):
                raw = "X-Cache-Probe: " in raw_headers
                if mode == "fragmentation_problematica":
                    name = "UPPER" if raw else "LOWER"
                    key = (path, name)
                    if st.store.get(key):
                        self._send("CONTENT-FROM-%s" % name,
                                   'W/"%s"' % name.lower(),
                                   cache="HIT", age=1)
                    else:
                        st.store[key] = True
                        self._send("CONTENT-FROM-%s" % name,
                                   'W/"%s"' % name.lower())
                    return
                if mode == "normalization_legitima":
                    key = (path, "norm")
                    if st.store.get(key):
                        self._send("CONTENT-NORMALIZED",
                                   'W/"norm"', cache="HIT",
                                   age=1)
                    else:
                        st.store[key] = True
                        self._send("CONTENT-NORMALIZED",
                                   'W/"norm"')
                    return
                # layer_disagreement: contenido insensible al
                # case; slot por path para el PRIMER case-form
                slot = st.slot.setdefault(path, raw)
                if slot == raw:
                    key = (path, "UP" if raw else "LO")
                    if st.store.get(key):
                        self._send("CONTENT-NORM", 'W/"norm"',
                                   cache="HIT", age=1)
                    else:
                        st.store[key] = True
                        self._send("CONTENT-NORM", 'W/"norm"')
                else:
                    self._send("CONTENT-NORM", 'W/"norm"')
                return
            if path.startswith("/cache-probe"):
                if mode == "fragmentation_legitima":
                    if "cache-probe=1" in (
                            self.headers.get("Cookie") or ""):
                        self._send("CONTENT-FOR-COOKIE",
                                   'W/"cookie"',
                                   vary="Cookie")
                    else:
                        self._send("CONTENT-PLAIN",
                                   'W/"plain"', vary="Cookie")
                    return
                self._send("PROBE-CONTENT-PLAIN", 'W/"pc"')
                return
            # resto de paths
            if mode == "collision_legitima":
                self._send(ALIAS_BODY, 'W/"alias-42"')
                return
            if mode in ("collision_problematica",
                        "cross_contamination"):
                key = _seg(path)
                hit = st.store.get(key)
                if hit:
                    body, etag, ct = hit
                    self._send(body, etag, ct=ct, cache="HIT",
                               age=1)
                    return
                if mode == "cross_contamination":
                    if path.endswith("/a"):
                        body, etag, ct = ("JSON-OF-A",
                                          'W/"json-a"',
                                          "application/json")
                    elif path.endswith("/b"):
                        body, etag, ct = ("<html>HTML-OF-B"
                                          "</html>",
                                          'W/"html-b"',
                                          "text/html")
                    else:
                        body, etag, ct = ("ORIGIN-%s" % path,
                                          'W/"et-%s"' % key,
                                          "text/plain")
                else:
                    body = "ORIGIN-%s" % path
                    etag = 'W/"et-%s"' % path.replace("/", "_")
                    ct = "text/plain"
                st.store[key] = (body, etag, ct)
                self._send(body, etag, ct=ct)
                return
            self._send("ORIGIN-%s" % path,
                       'W/"et-%s"' % path.replace("/", "_"))
            return


def main():
    port = int(sys.argv[1])
    mode = sys.argv[2]
    if mode not in TRUTHS:
        print("modo desconocido: %s" % mode)
        sys.exit(2)
    truth = dict(TRUTHS[mode])
    truth["mode"] = mode
    truth["port"] = port
    # ORACLE: archivo lateral. El motor JAMAS lo lee.
    opath = "/tmp/semantic_lab_oracle_%d.json" % port
    with open(opath, "w") as f:
        json.dump(truth, f)
    Handler.state = LabState(mode)
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("semantic lab %s en %d (oracle: %s)"
          % (mode, port, opath))
    srv.serve_forever()


if __name__ == "__main__":
    main()
