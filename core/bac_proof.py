#!/usr/bin/env python3
# ============================================================
# codexRC - BAC-PROOF (v0.67.0, AUTHZ-PROOF capa 4)
# ------------------------------------------------------------
# Validacion DINAMICA de candidatos BAC/IDOR en WP-LAB local:
# levanta WordPress (SQLite, sin MySQL) + PHP server, instala el
# plugin bajo prueba, crea un objeto victima del admin y dispara
# cada accion candidata como ANONIMO / SUSCRIPTOR / ADMIN.
# Difiere las respuestas y emite evidencia de ejecucion:
#
#   DEMO-BAC-DINAMICO     el suscriptor obtiene lo mismo que el
#                         admin sobre el objeto ajeno
#   DEMO-UNAUTH-DINAMICO  el anonimo obtiene lo mismo que el
#                         admin (nopriv explotado)
#   REFUTADO-DINAMICO     el suscriptor/anonimo es bloqueado
#                         (gate/owner funciona en ejecucion real)
#                         -> alimenta FP-MEMORIA (capa 5)
#
# Requisitos: php + pdo_sqlite en PATH. Todo local: cero
# interaccion con terceros (regla mVDP: lectura A->B, sin impacto).
# ============================================================
import http.cookiejar
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

WP_CLI_URL = ("https://raw.githubusercontent.com/wp-cli/builds/"
              "gh-pages/phar/wp-cli.phar")
SQLITE_ZIP = ("https://downloads.wordpress.org/plugin/"
              "sqlite-database-integration.latest-stable.zip")
CANDIDATO_VEREDICTOS = ("CANDIDATO-BAC", "CANDIDATO-IDOR",
                        "PRIVILEGIO-DEBIL")


def _run(cmd: List[str], cwd: Optional[str] = None) -> Tuple[int, str]:
    env = dict(os.environ, WP_CLI_ALLOW_ROOT="1")
    p = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True,
                       text=True, timeout=180)
    return p.returncode, (p.stdout + p.stderr).strip()


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Lab:
    """WordPress + SQLite + php -S, todo local e idempotente."""

    def __init__(self, workdir: str):
        self.workdir = os.path.abspath(workdir)
        self.wp = os.path.join(self.workdir, "wp")
        self.cli = os.path.join(self.workdir, "wp-cli.phar")
        self.port = 0
        self.proc: Optional[subprocess.Popen] = None

    # ---------- provision ----------
    def ensure(self, admin_user="admin", admin_pass="adminpass123",
               sub_user="subwp", sub_pass="subpass123") -> bool:
        os.makedirs(self.workdir, exist_ok=True)
        if not os.path.isfile(self.cli):
            urllib.request.urlretrieve(WP_CLI_URL, self.cli)
        if not os.path.isfile(os.path.join(self.wp, "wp-config.php")):
            if not os.path.isdir(self.wp):
                rc, out = _run(["php", self.cli, "core", "download",
                                "--path=" + self.wp, "--quiet"])
                if rc:
                    return False
            pd = os.path.join(self.wp, "wp-content", "plugins")
            z = os.path.join(self.workdir, "sqlite.zip")
            if not os.path.isdir(os.path.join(pd,
                                              "sqlite-database-integration")):
                urllib.request.urlretrieve(SQLITE_ZIP, z)
                import zipfile
                zipfile.ZipFile(z).extractall(pd)
                os.remove(z)
            shutil.copy(
                os.path.join(pd, "sqlite-database-integration", "db.copy"),
                os.path.join(self.wp, "wp-content", "db.php"))
            _run(["php", self.cli, "config", "create", "--path=" + self.wp,
                  "--dbname=lab", "--dbuser=lab", "--dbpass=labpass",
                  "--dbhost=127.0.0.1", "--dbprefix=wp_", "--skip-check"])
            self.port = self.port or _free_port()
            rc, _ = _run(["php", self.cli, "core", "install",
                          "--path=" + self.wp,
                          "--url=http://127.0.0.1:%d" % self.port,
                          "--title=WP-LAB", "--admin_user=" + admin_user,
                          "--admin_password=" + admin_pass,
                          "--admin_email=lab@example.com", "--skip-email"])
            if rc:
                return False
        self.port = self.port or self._detect_port()
        # siteurl/home SIN sufijo de subruta: las cookies de sesion
        # se emiten con path raiz y llegan a wp-admin (bug real:
        # core install con el drop-in agrega /wp al siteurl)
        url = "http://127.0.0.1:%d" % self.port
        cur = _run(["php", self.cli, "option", "get", "siteurl",
                    "--path=" + self.wp])[1].strip()
        if cur != url:
            _run(["php", self.cli, "option", "update", "siteurl", url,
                  "--path=" + self.wp])
            _run(["php", self.cli, "option", "update", "home", url,
                  "--path=" + self.wp])
        # usuarios del A/B
        _run(["php", self.cli, "user", "create", sub_user,
              "sub@example.com", "--path=" + self.wp,
              "--role=subscriber", "--user_pass=" + sub_pass])
        return True

    def _detect_port(self) -> int:
        try:
            out = _run(["php", self.cli, "option", "get", "siteurl",
                        "--path=" + self.wp])[1]
            return int(re.search(r":(\d+)", out).group(1))
        except Exception:
            return 8111

    # ---------- ciclo de vida ----------
    def start(self) -> bool:
        if self.proc:
            return True
        self.port = self.port or _free_port()
        self.proc = subprocess.Popen(
            ["php", "-S", "127.0.0.1:%d" % self.port, "-t", self.wp],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # wait until responde
        for _ in range(40):
            try:
                urllib.request.urlopen(
                    "http://127.0.0.1:%d/" % self.port, timeout=2)
                return True
            except Exception:
                import time
                time.sleep(0.25)
        return False

    def stop(self) -> None:
        if self.proc:
            self.proc.terminate()
            self.proc.wait()
            self.proc = None

    # ---------- plugin bajo prueba ----------
    def install_plugin(self, plugin_root: str, slug: str) -> bool:
        dest = os.path.join(self.wp, "wp-content", "plugins", slug)
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        shutil.copytree(plugin_root, dest)
        rc, _ = _run(["php", self.cli, "plugin", "activate", slug,
                      "--path=" + self.wp])
        return rc == 0

    def seed_victim(self, meta_keys=None,
                    meta_val="LAB-SECRET-987654") -> Optional[str]:
        """Post del admin con metas secretos (objeto victima).
        Se siembran TODAS las claves que el plugin lee, para que el
        eco del handler contenga el canario si logra leer el meta."""
        rc, out = _run(["php", self.cli, "post", "create",
                        "--path=" + self.wp, "--post_title=victima",
                        "--post_status=publish", "--post_author=1",
                        "--porcelain"])
        if rc:
            return None
        pid = out.strip().split("\n")[-1]
        for k in set(list(meta_keys or []) + ["lab_secret"]):
            _run(["php", self.cli, "post", "meta", "update", pid, k,
                  meta_val, "--path=" + self.wp])
        return pid

    # ---------- http ----------
    def _opener(self):
        cj = http.cookiejar.CookieJar()
        return urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj))

    def login(self, user: str, pwd: str):
        """Login por cookie: exito = wordpress_logged_in_* presente."""
        cj = http.cookiejar.CookieJar()
        op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj))
        data = urllib.parse.urlencode(
            {"log": user, "pwd": pwd, "wp-submit": "Log In",
             "redirect_to": "http://127.0.0.1:%d/wp-login.php" % self.port
             }).encode()
        ok = False
        try:
            op.open("http://127.0.0.1:%d/wp-login.php" % self.port,
                    data, timeout=30)
        except Exception:
            pass
        for c in cj:
            if c.name.startswith("wordpress_logged_in"):
                ok = True
        return op if ok else None

    def ajax(self, op, action: str, fields: Dict[str, str]) -> Dict[str, Any]:
        fields = dict(fields)
        fields["action"] = action
        data = urllib.parse.urlencode(fields).encode()
        url = "http://127.0.0.1:%d/wp-admin/admin-ajax.php" % self.port
        try:
            r = op.open(url, data, timeout=30)
            return {"status": r.status,
                    "body": r.read().decode(errors="ignore")[:200]}
        except urllib.error.HTTPError as e:
            return {"status": e.code,
                    "body": e.read().decode(errors="ignore")[:200]}
        except Exception as e:
            return {"status": 0, "body": "error:" + str(e)[:80]}


def _normal(body: str, secret: str) -> str:
    """Normaliza el body para comparar sin ruido dinamico."""
    b = body.strip()
    if secret and secret in b:
        return "SECRET"
    if b in ("0", "-1", "0", ""):
        return "DENEGADO"
    return b[:40]


def prove(plugin_root: str, slug: str = "", workdir: str = "",
          actions: Optional[List[str]] = None) -> Dict[str, Any]:
    """Prueba dinamica A/B de los candidatos de un plugin.

    Devuelve {lab, resultados:[{accion, veredicto, evidencia}]}.
    Los REFUTADO alimentan FP-MEMORIA (huella dinamica).
    """
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
    from core.gates_audit import scan_path

    slug = slug or os.path.basename(os.path.normpath(plugin_root))
    gates = scan_path(plugin_root)
    cands = [h for h in gates.get("handlers", [])
             if h.get("veredicto") in CANDIDATO_VEREDICTOS
             or (actions and h.get("accion") in actions)]
    if actions:
        cands += [h for h in gates.get("handlers", [])
                  if h.get("accion") in actions and h not in cands]
    rep: Dict[str, Any] = {"plugin": slug, "candidatos": len(cands),
                           "resultados": []}
    if not cands:
        return rep

    workdir = workdir or os.environ.get("CODEXRC_HOME",
                                        os.path.expanduser("~/.codexrc"))
    workdir = os.path.join(workdir, "wp_lab")
    lab = Lab(workdir)
    if not (lab.ensure() and lab.start()):
        rep["error"] = "lab no disponible (php/pdo_sqlite?)"
        return rep
    rep["lab"] = "http://127.0.0.1:%d" % lab.port
    try:
        if not lab.install_plugin(plugin_root, slug):
            rep["error"] = "plugin no activable"
            return rep
        secret = "LAB-SECRET-987654"
        # claves de meta que el plugin realmente lee (canario)
        keys = set(["lab_secret"])
        for dirpath, _d, files in os.walk(plugin_root):
            for f in files:
                if f.endswith(".php"):
                    try:
                        src = open(os.path.join(dirpath, f),
                                   encoding="utf-8",
                                   errors="ignore").read()
                    except Exception:
                        continue
                    keys |= set(re.findall(
                        r"get_post_meta\s*\(\s*[^,]+,\s*'([\w\-]+)'",
                        src))
        pid = lab.seed_victim(meta_keys=keys, meta_val=secret)
        fields = {"post_id": pid or "1"}
        anon = lab._opener()
        adm = lab.login("admin", "adminpass123")
        sub = lab.login("subwp", "subpass123")
        for h in cands:
            accion = h["accion"]
            # accion admin-ajax: 'wp_ajax_x' -> 'x', 'nopriv' aparte
            ax = accion.replace("wp_ajax_nopriv_", "").replace("wp_ajax_", "")
            rows = {"anon": lab.ajax(anon, ax, fields)}
            if sub:
                rows["sub"] = lab.ajax(sub, ax, fields)
            if adm:
                rows["adm"] = lab.ajax(adm, ax, fields)
            has = {k: (secret in v["body"]) for k, v in rows.items()}
            res = {"accion": accion, "veredicto": "INCONCLUSIVO",
                   "evidencia": rows}
            if has.get("anon"):
                res["veredicto"] = "DEMO-UNAUTH-DINAMICO"
            elif has.get("sub"):
                res["veredicto"] = "DEMO-BAC-DINAMICO"
            elif has.get("adm"):
                # el admin (dueno del objeto) SI obtiene el secreto y
                # el suscriptor/anonimo NO: la autorizacion funciona
                res["veredicto"] = "REFUTADO-DINAMICO"
            rep["resultados"].append(res)
            # alimentar FP-MEMORIA con la refutacion dinamica
            if res["veredicto"] == "REFUTADO-DINAMICO":
                try:
                    from core import fp_memory
                    fh = {"type": "bac", "file": h.get("archivo_callback",
                                                        h.get("archivo", "")),
                          "line": h.get("linea_callback",
                                        h.get("linea_hook", 1))}
                    fp_memory.learn(fh, plugin_root, gates,
                                    refuted_by="WP-LAB",
                                    reason="bloqueado en ejecucion real "
                                           "(A/B sub denegado)",
                                    plugin=slug)
                except Exception:
                    pass
    finally:
        lab.stop()
    return rep


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else ""
    if root:
        slug = sys.argv[2] if len(sys.argv) > 2 else ""
        out = prove(root, slug=slug)
        print(json.dumps(out, indent=1, ensure_ascii=False))
    else:
        print("uso: python3 core/bac_proof.py <plugin_root> [slug]")
