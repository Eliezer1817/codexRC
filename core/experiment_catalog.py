"""CATALOGO DE EXPERIMENTOS (v0.81.0): sondas HTTP de solo
lectura con CONTRATO pre-registrado.

Cada experimento declara ANTES de ejecutar que resultados
apoyarian o refutarian que hipotesis. El contrato se evalua
despues con el bundle de resultados acumulado: nada se
racionaliza a posteriori.

Orden de ejecucion: fijo por dependencia (INTRA -> CROSS ->
SESSION -> VIRGIN -> TIME). La parte adaptativa es PARAR
temprano cuando el juez converge, y el gap ledger que queda
si no converge.
"""

import hashlib
import http.client
import ssl
import time
import urllib.parse

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0 Safari/537.36")
_CTX = ssl.create_default_context()


def _parts(url):
    p = urllib.parse.urlsplit(url)
    scheme = p.scheme or "https"
    host = p.hostname
    port = p.port or (443 if scheme == "https" else 80)
    path = p.path or "/"
    return scheme, host, port, path


def _open(url, timeout):
    scheme, host, port, _ = _parts(url)
    if scheme == "https":
        return http.client.HTTPSConnection(
            host, port, timeout=timeout, context=_CTX)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _fp(resp):
    body = resp.read()
    return {
        "status": resp.status,
        "body_hash": hashlib.sha256(body).hexdigest()[:16],
        "content_type": (resp.getheader("Content-Type") or
                         "").split(";")[0],
    }


def _get(conn, path):
    conn.request("GET", path, headers={
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection": "keep-alive",
    })
    r = conn.getresponse()
    fp = _fp(r)
    fp["set_cookie"] = (resp_setcookie(r) or None)
    return fp


def resp_setcookie(resp):
    vals = resp.msg.get_all("Set-Cookie") or []
    return "; ".join(v.split(";")[0] for v in vals) if vals else ""


# ---------------- experimentos ----------------

def exp_intra(url, timeout):
    """INTRA-CONN: 3 GETs sobre UNA misma conexion viva."""
    _, _, _, path = _parts(url)
    conn = _open(url, timeout)
    try:
        fps = [_get(conn, path) for _ in range(3)]
    finally:
        conn.close()
    hashes = [f["body_hash"] for f in fps]
    return {"cost": 3, "results": {
        "intra_var": len(set(hashes)) > 1, "hashes": hashes},
        "observations": fps}


def exp_cross(url, timeout):
    """CROSS-CONN: 2 conexiones x 2 GETs. Separa varianza
    intra-conexion de varianza entre conexiones."""
    _, _, _, path = _parts(url)
    out = []
    for _ in range(2):
        conn = _open(url, timeout)
        try:
            out.append([_get(conn, path)["body_hash"]
                        for _ in range(2)])
        finally:
            conn.close()
    within = out[0][0] != out[0][1] or out[1][0] != out[1][1]
    across = out[0][0] != out[1][0]
    return {"cost": 4, "results": {
        "within_var": within, "across_var": across,
        "pairs": out}, "observations": out}


def exp_session(url, timeout):
    """SESSION: 2 GETs sin cookies + 2 GETs con cookie-jar
    (cookies entregadas por el propio target)."""
    _, _, _, path = _parts(url)
    conn = _open(url, timeout)
    try:
        bare = [_get(conn, path) for _ in range(2)]
        jar_cookie = bare[0]["set_cookie"] or ""
        jar = [_get(conn, path) for _ in range(2)]
    finally:
        conn.close()
    # re-enviar con cookie explicita si el target entrego una
    if jar_cookie:
        conn = _open(url, timeout)
        try:
            for j in jar:
                j["body_hash"] = None
            conn.request("GET", path, headers={
                "User-Agent": UA, "Cookie": jar_cookie,
                "Connection": "keep-alive"})
            r = conn.getresponse()
            jar[0]["body_hash"] = hashlib.sha256(
                r.read()).hexdigest()[:16]
            conn.request("GET", path, headers={
                "User-Agent": UA, "Cookie": jar_cookie,
                "Connection": "keep-alive"})
            r = conn.getresponse()
            jar[1]["body_hash"] = hashlib.sha256(
                r.read()).hexdigest()[:16]
        finally:
            conn.close()
    bare_h = [f["body_hash"] for f in bare]
    jar_h = [f["body_hash"] for f in jar]
    bare_stable = len(set(bare_h)) == 1
    jar_stable = len(set(jar_h)) == 1
    session_effect = (bare_stable and jar_stable
                      and bare_h[0] != jar_h[0])
    cookies_irrelevant = (bare_stable and jar_stable
                          and bare_h[0] == jar_h[0])
    return {"cost": 4, "results": {
        "bare_stable": bare_stable, "jar_stable": jar_stable,
        "session_effect": session_effect,
        "cookies_irrelevant": cookies_irrelevant,
        "jar_cookie": bool(jar_cookie)},
        "observations": {"bare": bare_h, "jar": jar_h}}


def exp_virgin(url, timeout):
    """VIRGIN: recurso fresco nunca solicitado: 2 GETs misma
    conexion + 1 GET conexion nueva."""
    _, host, port, _ = _parts(url)
    path = f"/x-adaptive-virgin-{int(time.time()*1000)%9973}"
    conn = _open(url, timeout)
    try:
        h1 = _get(conn, path)["body_hash"]
        h2 = _get(conn, path)["body_hash"]
    finally:
        conn.close()
    conn = _open(url, timeout)
    try:
        h3 = _get(conn, path)["body_hash"]
    finally:
        conn.close()
    return {"cost": 3, "results": {
        "virgin_intra_var": h1 != h2,
        "virgin_across_var": h1 != h3},
        "observations": [h1, h2, h3]}


def exp_time(url, timeout):
    """TIME-OFFSET: mismo recurso tras un delay fijo."""
    _, _, _, path = _parts(url)
    conn = _open(url, timeout)
    try:
        h1 = _get(conn, path)["body_hash"]
        time.sleep(2.0)
        h2 = _get(conn, path)["body_hash"]
    finally:
        conn.close()
    return {"cost": 2, "results": {"time_var": h1 != h2},
        "observations": [h1, h2]}


EXPERIMENTS = [
    {"id": "INTRA-CONN", "cost": 3, "run": exp_intra,
     "touches": ["H1", "H3"]},
    {"id": "CROSS-CONN", "cost": 4, "run": exp_cross,
     "touches": ["H1", "H3"]},
    {"id": "SESSION", "cost": 4, "run": exp_session,
     "touches": ["H2", "H4"]},
    {"id": "VIRGIN", "cost": 3, "run": exp_virgin,
     "touches": ["H1", "H3"]},
    {"id": "TIME-OFFSET", "cost": 2, "run": exp_time,
     "touches": ["H5"]},
]


def contract(exp_id, bundle):
    """CONTRATO determinista: dado el bundle de resultados
    acumulado, devuelve acciones (hyp, accion, nota).
    Cada nota cita la observacion que la produce."""
    acts = []
    r = bundle.get(exp_id, {}).get("results", {})
    if exp_id == "INTRA-CONN":
        if r.get("intra_var"):
            acts.append(("H1", "CONTRADICT",
                "varianza intra-conexion: LB por conexion "
                "predice estabilidad dentro de la conexion"))
            acts.append(("H3", "CONTRADICT",
                "varianza intra-conexion: cache predice "
                "estabilidad dentro de la conexion"))
    elif exp_id == "CROSS-CONN":
        if r.get("within_var") and \
                "INTRA-CONN" not in bundle:
            acts += contract("INTRA-CONN", bundle)
        elif r.get("across_var"):
            acts.append(("H1", "SUPPORT",
                "estable dentro, varianza entre conexiones: "
                "consistente con LB por conexion"))
            acts.append(("H3", "SUPPORT",
                "estable dentro, varianza entre conexiones: "
                "consistente con estado por conexion"))
    elif exp_id == "SESSION":
        if r.get("cookies_irrelevant"):
            acts.append(("H2", "CONTRADICT",
                "cookies del propio target no alteran la "
                "respuesta: personalizacion por sesion "
                "descartada"))
            acts.append(("H4", "CONTRADICT",
                "cookies no alteran la respuesta: gestion "
                "por cookie descartada"))
        elif r.get("session_effect"):
            acts.append(("H2", "SUPPORT",
                "con cookies la respuesta cambia: mecanismo "
                "de sesion presente"))
            acts.append(("H4", "SUPPORT",
                "con cookies la respuesta cambia: mecanismo "
                "de cookie presente"))
        elif not r.get("bare_stable") and not r.get("jar_stable") \
                and not r.get("session_effect"):
            acts.append(("H2", "CONTRADICT",
                "ambos brazos (con y sin cookies) varian: "
                "las cookies no estabilizan nada"))
            acts.append(("H4", "CONTRADICT",
                "ambos brazos varian: las cookies no "
                "estabilizan nada"))
    elif exp_id == "VIRGIN":
        cross = bundle.get("CROSS-CONN", {}).get("results", {})
        if cross.get("across_var"):
            if r.get("virgin_across_var"):
                acts.append(("H3", "CONTRADICT",
                    "recurso virgen nunca cacheado tambien "
                    "varia entre conexiones: no es cache"))
                acts.append(("H1", "SUPPORT",
                    "la varianza afecta a recursos virgenes: "
                    "consistente con LB global"))
            elif r.get("virgin_intra_var"):
                acts.append(("H1", "CONTRADICT",
                    "recurso virgen varia dentro de la misma "
                    "conexion: LB por conexion descartada"))
                acts.append(("H3", "CONTRADICT",
                    "recurso virgen varia intra-conexion: "
                    "cache descartada"))
            else:
                acts.append(("H1", "CONTRADICT",
                    "recurso virgen estable entre conexiones "
                    "mientras el blanco varia: LB global "
                    "descartada"))
                acts.append(("H3", "SUPPORT",
                    "la varianza se confina al recurso "
                    "conocido: consistente con cache"))
    elif exp_id == "TIME-OFFSET":
        intra = bundle.get("INTRA-CONN", {}).get("results", {})
        if r.get("time_var"):
            acts.append(("H5", "SUPPORT",
                "el recurso cambia tras un delay fijo: "
                "dinamica temporal observable"))
        elif not intra.get("intra_var") and not r.get("time_var"):
            acts.append(("H5", "CONTRADICT",
                "sin dinamica ni per-request ni tras delay: "
                "ninguna variacion observable en la ventana"))
    return acts
