#!/usr/bin/env python3
# ============================================================
# codexRC - LAB-AB-SITE (v0.68.0): sitio NO-WordPress de prueba
# ------------------------------------------------------------
# Laboratorio local para validar REG-BOT + AB-DIFF sin tocar a
# ningun tercero (misma filosofia que WP-LAB, pero para apps
# genericas). Simula una app "Laravel-like" con:
#   - registro (username, email, password estricta, confirm)
#   - verificacion por CODIGO (6 digitos) al mailbox mock
#   - login por email+password
#   - /api/me: datos de la sesion (id, email, links)
#   - /api/user/<id>: SIN owner check  <- bug IDOR a detectar
#   - /api/user/<id>/notes: CON owner check <- caso a REFUTAR
#   - /mockmail/<email>: buzon mock (compatible mail.tm shape)
#
# Uso:
#   python3 core/lab_ab_site.py 8899     # levanta en :8899
#   python3 core/ab_diff.py http://127.0.0.1:8899 \
#       --mock http://127.0.0.1:8899
# ============================================================
import hashlib
import http.server
import json
import random
import re
import sys
import time
import urllib.parse
from http.cookies import SimpleCookie

USERS = {}        # email -> user dict
PENDING = {}      # email -> {"code","ts"}
MAILBOX = {}      # email -> [messages]
SESSIONS = {}      # token -> email
CODE_TTL = 600     # 10 minutos como en la vida real


def _user(email, username, password):
    return {"id": len(USERS) + 1, "email": email, "username": username,
            "password": password, "notes": "NOTA-PRIVADA-" + email}


HOMEPAGE_ANON = """<!doctype html><html><body>
<h1>AppLab</h1>
<a href="/register">Crear cuenta</a>
<a href="/login">Iniciar sesi&oacute;n</a>
</body></html>"""

HOMEPAGE_IN = """<!doctype html><html><body>
<h1>AppLab</h1>
<p>Bienvenido. Tu panel:</p>
<a href="/api/me">Mi perfil (API)</a>
</body></html>"""

REGISTER_PAGE = """<!doctype html><html><body>
<h1>Crear cuenta</h1>
<form action="/register" method="post">
<input name="username" type="text" required placeholder="Nombre de usuario">
<input name="email" type="email" required placeholder="Tu correo">
<input name="password" type="password" required
 placeholder="Minimo 8, mayuscula, numero y simbolo">
<input name="password_confirm" type="password" required
 placeholder="Repite la contrasena">
<button type="submit">Registrarme</button>
</form></body></html>"""

VERIFY_PAGE = """<!doctype html><html><body>
<h1>Verifica tu correo</h1>
<p>Te enviamos un codigo de 6 digitos. Caduca en 10 minutos.</p>
<form action="/verify" method="post">
<input name="codigo" type="text" required placeholder="Codigo de verificacion">
<button type="submit">Verificar</button>
</form></body></html>"""

LOGIN_PAGE = """<!doctype html><html><body>
<h1>Iniciar sesi&oacute;n</h1>
<form action="/login" method="post">
<input name="email" type="email" required placeholder="Tu correo">
<input name="password" type="password" required placeholder="Contrasena">
<button type="submit">Entrar</button>
</form></body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, *a):
        pass

    def _session_email(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        if "session" in c:
            return SESSIONS.get(c["session"].value)
        return None

    def _html(self, body, status=200, headers=None):
        b = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(b)

    def _json(self, obj, status=200):
        b = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def _redirect(self, to, headers=None):
        self.send_response(302)
        self.send_header("Location", to)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode() if n else ""
        return {k: v[0] for k, v in
                urllib.parse.parse_qs(raw).items()}

    # ---------------- GET ----------------

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        path = u.path
        email = self._session_email()

        if path == "/":
            return self._html(HOMEPAGE_IN if email else HOMEPAGE_ANON)
        if path == "/register":
            return self._html(REGISTER_PAGE)
        if path == "/verify":
            return self._html(VERIFY_PAGE)
        if path == "/login":
            return self._html(LOGIN_PAGE)
        if path.startswith("/mockmail/"):
            mbox = urllib.parse.unquote(path[len("/mockmail/"):])
            return self._json(MAILBOX.get(mbox, []))
        if path == "/api/me":
            if not email:
                return self._json({"error": "no autenticado"}, 401)
            usr = USERS[email]
            return self._json({
                "id": usr["id"], "email": usr["email"],
                "username": usr["username"],
                "links": ["/api/user/{}".format(usr["id"]),
                          "/api/user/{}/notes".format(usr["id"])]})
        m = re.match(r"^/api/user/(\d+)$", path)
        if m:
            # BUG INTENCIONAL: exige sesion pero NO owner check
            if not email:
                return self._json({"error": "no autenticado"}, 401)
            uid = int(m.group(1))
            for usr in USERS.values():
                if usr["id"] == uid:
                    return self._json({"id": usr["id"],
                                       "email": usr["email"],
                                       "username": usr["username"]})
            return self._json({"error": "not found"}, 404)
        m = re.match(r"^/api/user/(\d+)/notes$", path)
        if m:
            # GATE CORRECTO: owner check presente
            if not email:
                return self._json({"error": "no autenticado"}, 401)
            usr = USERS[email]
            if usr["id"] != int(m.group(1)):
                return self._json({"error": "no es tuyo"}, 403)
            return self._json({"notes": usr["notes"]})
        return self._html("<h1>404</h1>", 404)

    # ---------------- POST ----------------

    def do_POST(self):
        u = urllib.parse.urlparse(self.path)
        path = u.path
        d = self._body()

        if path == "/register":
            email = d.get("email", "").strip().lower()
            pw = d.get("password", "")
            uname = d.get("username", "")
            if not email or "@" not in email:
                return self._html("<p>correo invalido</p>", 400)
            if not re.search(r"[A-Z]", pw) or not re.search(r"\d", pw) \
                    or not re.search(r"[!@#$%&]", pw) or len(pw) < 8:
                return self._html("<p>contrasena debil</p>", 400)
            if d.get("password_confirm", "") != pw:
                return self._html("<p>las contrasenas no coinciden</p>", 400)
            if email in USERS:
                return self._html("<p>ese usuario ya existe</p>", 409)
            if any(x["username"] == uname for x in USERS.values()):
                return self._html("<p>ese usuario ya existe</p>", 409)
            USERS[email] = _user(email, uname, pw)  # creado, pendiente
            code = str(random.randrange(100000, 999999))
            PENDING[email] = {"code": code, "ts": time.time()}
            MAILBOX.setdefault(email, []).append({
                "subject": "Verifica tu cuenta",
                "text": "Tu codigo de verificacion es {}. Caduca en 10 "
                        "minutos.".format(code),
                "html": ""})
            return self._redirect("/verify")

        if path == "/verify":
            email = self._session_email()
            if not email:
                # sin sesion: buscar el pendiente por su codigo
                code = d.get("codigo", "")
                match = [e for e, p in PENDING.items() if p["code"] == code]
                if not match:
                    return self._html("<p>codigo invalido o expirado</p>", 400)
                if time.time() - PENDING[match[0]]["ts"] > CODE_TTL:
                    return self._html("<p>codigo expirado</p>", 400)
                email = match[0]
            else:
                p = PENDING.get(email)
                if not p or d.get("codigo") != p["code"] or \
                        time.time() - p["ts"] > CODE_TTL:
                    return self._html("<p>codigo invalido o expirado</p>", 400)
            PENDING.pop(email, None)
            tok = hashlib.sha1(email.encode()).hexdigest()[:20]
            SESSIONS[tok] = email
            return self._redirect("/login",
                                  headers={"Set-Cookie":
                                           "session=" + tok + "; Path=/"})

        if path == "/login":
            email = d.get("email", "").strip().lower()
            pw = d.get("password", "")
            usr = USERS.get(email)
            if not usr or usr["password"] != pw:
                return self._html("<p>credenciales incorrectas</p>", 401)
            tok = hashlib.sha1((email + "s").encode()).hexdigest()[:20]
            SESSIONS[tok] = email
            return self._redirect("/",
                                  headers={"Set-Cookie":
                                           "session=" + tok + "; Path=/"})

        return self._html("<h1>404</h1>", 404)


def _register_seed():
    pass  # sin usuarios: REG-BOT debe crear A y B el solito


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print("LAB-AB-SITE en http://127.0.0.1:{}".format(port), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
