"""
codexRC - Backend único de la aplicación.

Termux solo inicia este proceso; toda la lógica de auditoría, autenticación,
pipeline y consulta de CVEs se ejecuta aquí y el frontend consume la API.

Ejecutar:
    python backend/app.py
"""

from datetime import datetime, timezone
from pathlib import Path
import json
import logging
from logging.handlers import RotatingFileHandler
import sys
import time
import uuid
from typing import Any, Dict
import requests
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from flask import Flask, g, jsonify, request, send_file, send_from_directory

# Permite ejecutar tanto `python backend/app.py` como `python -m backend.app`.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import threading

from core.auth import AuthManager
from core.cve_matcher import CVEMatcher
from core.deep_scan import DomainMap, cookie_flags, detect_waf, tls_audit
from core.hunter import Spider, XSSHunter, DeepHunter
from core.pipeline import Pipeline
from core.recon import Recon
from core.tech_detect import TechDetector

NODE_ORDER = ["recon", "tech_detect", "auth_status", "security_audit", "domain_map", "cve_match"]


app = Flask(__name__, static_folder=str(ROOT / "frontend"), static_url_path="")
JOBS: Dict[str, Dict[str, Any]] = {}
VERSION = "0.18.0"
REPORTS_DIR = ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
LOGGER = logging.getLogger("codexRC")
LOGGER.setLevel(logging.INFO)
LOGGER.propagate = False
if not LOGGER.handlers:
    handler = RotatingFileHandler(
        REPORTS_DIR / "backend.log",
        maxBytes=2_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(message)s"))
    LOGGER.addHandler(handler)


def log_event(event: str, **fields: Any) -> None:
    """Escribe eventos JSONL sin incluir secretos."""
    safe_fields = {key: value for key, value in fields.items() if key not in {"password", "token", "cookies"}}
    LOGGER.info(json.dumps({"ts": utc_now(), "event": event, **safe_fields}, ensure_ascii=False, default=str))


def safe_url(url: str) -> str:
    """Oculta parámetros potencialmente sensibles de las URLs registradas."""
    parsed = urlparse(url)
    query = [(key, "[redacted]") for key, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(query), ""))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


STARTED_AT = utc_now()


def valid_target(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


@app.before_request
def begin_request():
    g.request_id = uuid.uuid4().hex[:12]
    g.request_started = time.perf_counter()


@app.after_request
def finish_request(response):
    response.headers["X-Request-ID"] = g.get("request_id", "unknown")
    duration = round(time.perf_counter() - g.get("request_started", time.perf_counter()), 3)
    log_event(
        "http_request",
        request_id=g.get("request_id"),
        method=request.method,
        path=request.path,
        status=response.status_code,
        duration=duration,
    )
    return response


@app.errorhandler(Exception)
def handle_unexpected_error(exc):
    request_id = g.get("request_id", "unknown")
    log_event(
        "unhandled_error",
        request_id=request_id,
        method=request.method,
        path=request.path,
        error_type=type(exc).__name__,
        error=str(exc),
    )
    return jsonify({
        "error": "internal_error",
        "message": "El backend encontró un error inesperado.",
        "request_id": request_id,
        "version": VERSION,
    }), 500


def safe_auth_info(auth: AuthManager) -> Dict[str, Any]:
    """Devuelve estado de autenticación sin exponer cookies ni tokens."""
    info = auth.get_auth_info()
    headers = {
        key: "[redacted]" if key.lower() == "authorization" else value
        for key, value in info.get("headers", {}).items()
    }
    return {
        "authenticated": info.get("authenticated", False),
        "method": info.get("method"),
        "cookie_names": sorted(info.get("cookies", {}).keys()),
        "headers": headers,
        "login_debug": info.get("login_debug", {}),
    }


def save_scan_log(job: Dict[str, Any]) -> str:
    """Guarda el resultado completo del escaneo como JSON descargable."""
    path = REPORTS_DIR / f"codexrc_{job['id']}.json"
    path.write_text(
        json.dumps(job, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return str(path)


def build_auth(data: Dict[str, Any], target_url: str = None) -> AuthManager:
    auth = AuthManager()
    if data.get("cookies"):
        if not isinstance(data["cookies"], dict):
            raise ValueError("cookies debe ser un objeto name/value")
        auth.set_cookies(data["cookies"])
    elif data.get("bearer_token"):
        auth.set_bearer_token(str(data["bearer_token"]))
    elif data.get("custom_header_name") and data.get("custom_header_value"):
        auth.set_custom_header(
            str(data["custom_header_name"]), str(data["custom_header_value"])
        )
    elif data.get("username") and data.get("password"):
        login_url = str(data.get("login_url") or "").strip()
        if not login_url and target_url:
            # con SOLO la URL del sitio: encontrar la pagina de login solo
            login_url = auth.discover_login_url(str(target_url))
            log_event("auth_discovery", request_id=g.get("request_id"),
                      login_url_discovered=login_url)
        if not login_url:
            raise ValueError(
                "Falta la URL de login y no se pudo descubrir desde la URL objetivo"
            )
        # auto-verificacion: endpoints de cuenta que exijan sesion (401 anonimo)
        auth.auto_verify_urls = []
        if not data.get("verification_url"):
            try:
                cands = auth.discover_account_urls(str(target_url or login_url))
                auth.auto_verify_urls = auth.probe_account_candidates(cands)
                log_event("auth_discovery", request_id=g.get("request_id"),
                          account_urls=auth.auto_verify_urls)
            except Exception as exc:
                log_event("auth_discovery_error", request_id=g.get("request_id"),
                          error=str(exc))
        auth.login_with_credentials(
            login_url=login_url,
            username=str(data["username"]),
            password=str(data["password"]),
            username_field=data.get("username_field"),
            password_field=data.get("password_field"),
            success_indicator=data.get("success_indicator"),
            failure_indicator=data.get("failure_indicator"),
            verify_url=data.get("verify_url"),
        )
    return auth


def execute_scan(url: str, data: Dict[str, Any], job: Dict[str, Any] = None) -> Dict[str, Any]:
    """Ejecuta el pipeline completo actualizando el job en vivo (nodo a nodo)."""
    scan_started = time.perf_counter()
    log_event("scan_started", request_id=g.get("request_id"), url=safe_url(url), auth_requested=bool(
        data.get("cookies") or data.get("bearer_token") or data.get("username")
    ))
    auth = build_auth(data, target_url=url)
    session = auth.get_session()
    cfg = _auth_config_of(data)
    if cfg:
        LAST_AUTH_CONFIG.clear()
        LAST_AUTH_CONFIG.update(cfg)
        LAST_AUTH_CONFIG["_for_url"] = url

    def emit(msg: str) -> None:
        if job is not None:
            job.setdefault("live_log", []).append({"ts": utc_now(), "msg": msg})

    def node_state(name: str, status: str, duration=None, error=None) -> None:
        if job is not None:
            nodes = job.setdefault("pipeline", {}).setdefault("nodes", {})
            nodes[name] = {"status": status, "duration": duration, "error": error}

    def node_recon(ctx: Dict[str, Any]) -> Dict[str, Any]:
        return {"recon": Recon(session).run(ctx["url"])}

    def node_tech(ctx: Dict[str, Any]) -> Dict[str, Any]:
        return {"technologies": TechDetector(session).detect(ctx["url"])}

    def node_cve(ctx: Dict[str, Any]) -> Dict[str, Any]:
        matcher = CVEMatcher()
        try:
            return {"cve_report": matcher.match_technologies(ctx.get("technologies", []))}
        finally:
            matcher.close()

    def node_auth_info(ctx: Dict[str, Any]) -> Dict[str, Any]:
        if auth.auth_method:
            session_check = None
            vurl = str(data.get("verification_url") or "").strip()
            # una pagina de login NUNCA sirve para verificar sesion (en apps
            # JavaScript siempre parece "no logueado"): si el campo tiene un
            # login, ignorarlo y autodescubrir un endpoint de cuenta.
            _vp = urlparse(vurl).path.lower()
            if vurl and any(k in _vp for k in ("login", "signin", "sign-in", "entrar", "iniciar-sesion")):
                log_event("auth_discovery", request_id=g.get("request_id"),
                          verification_url_ignored=vurl)
                vurl = ""
            if vurl:
                session_check = auth.verify_session(vurl)
            else:
                candidatos = list(getattr(auth, "auto_verify_urls", []) or [])
                if not candidatos:
                    try:
                        candidatos = auth.discover_account_urls(url)
                    except Exception:
                        candidatos = []
                for cand in candidatos:
                    chk = auth.verify_session(cand)
                    if chk.get("authenticated"):
                        session_check = chk
                        break
                    if session_check is None:
                        session_check = chk
                if session_check is None:
                    session_check = auth.verify_session(url)
                # datos personales del usuario (nombre) si no aparecio todavia
                if session_check and session_check.get("authenticated") and not session_check.get("username"):
                    try:
                        extra = auth.fetch_user_profile(url)
                        if extra:
                            base = session_check.get("profile") or {}
                            base["user_data"] = extra
                            session_check["profile"] = base
                            found = auth._find_username(extra)
                            if found:
                                session_check["username"] = found
                                session_check["signals"].append("username_detected")
                    except Exception as exc:
                        log_event("auth_profile_error", request_id=g.get("request_id"), error=str(exc))
        else:
            session_check = {
                "verified": False,
                "authenticated": False,
                "username": None,
                "reason": "no_auth_method",
            }
        return {
            "auth_info": safe_auth_info(auth),
            "session_check": session_check,
        }

    def node_security(ctx: Dict[str, Any]) -> Dict[str, Any]:
        recon = ctx.get("recon", {})
        headers = recon.get("headers", {}) or {}
        waf = detect_waf(headers)
        tls = tls_audit(ctx["url"])
        cookies = cookie_flags(headers)
        present = len(recon.get("security_headers", {}) or {})
        missing = len(recon.get("missing_security_headers", []) or [])
        total = present + missing
        return {
            "security_audit": {
                "waf": waf,
                "tls": tls,
                "cookies": cookies,
                "headers_score": {"present": present, "total": total},
            }
        }

    def node_domain(ctx: Dict[str, Any]) -> Dict[str, Any]:
        return {"domain_map": DomainMap().run(ctx["url"])}

    NODE_FUNCS = {
        "recon": node_recon,
        "tech_detect": node_tech,
        "auth_status": node_auth_info,
        "security_audit": node_security,
        "domain_map": node_domain,
        "cve_match": node_cve,
    }

    # resumenes legibles por nodo (para el log en vivo)
    def human_line(name: str, out: Dict[str, Any]) -> str:
        try:
            if name == "recon":
                r = out["recon"]
                bits = [f"HTTP {r.get('status_code')}"]
                if r.get("server"):
                    bits.append(f"server: {str(r.get('server'))[:40]}")
                bits.append(f"{len(r.get('headers') or {})} cabeceras")
                return "RECON · " + " · ".join(bits)
            if name == "tech_detect":
                techs = [t.get("name", "?") for t in out.get("technologies", [])][:6]
                n = len(out.get("technologies", []))
                return f"TECH-DETECT · {n} tecnologias: " + (", ".join(techs) if techs else "ninguna")
            if name == "auth_status":
                chk = out.get("session_check", {})
                ok = chk.get("authenticated")
                who = chk.get("username")
                return "AUTH · sesion " + ("CONFIRMADA" if ok else "no confirmada") + (f" · usuario: {who}" if who else "")
            if name == "security_audit":
                sa = out["security_audit"]
                waf = sa["waf"].get("waf") or "sin WAF/CDN detectado"
                tls = sa["tls"]
                tls_txt = f"TLS {tls.get('protocol', '?')}, vence en {tls.get('days_left')}d" if tls.get("enabled") else "TLS: sin acceso"
                return f"SECURITY · WAF: {waf} · {tls_txt} · cabeceras seguras: {sa['headers_score']['present']}/{sa['headers_score']['total']}"
            if name == "domain_map":
                dm = out["domain_map"]
                ips = ", ".join(dm.get("ips", [])[:3]) or "?"
                return f"DOMAIN · IPs: {ips} · subdominios: {dm['subdomains']['count']}"
            if name == "cve_match":
                rep = out["cve_report"]
                return f"CVE · {rep.get('total_cves_found', 0)} CVEs conocidos · {len(rep.get('high_priority', []))} de prioridad alta"
        except Exception:
            pass
        return f"{name} completado"

    ctx: Dict[str, Any] = {"url": url}
    results: Dict[str, Any] = {}
    emit(f"objetivo fijado: {url}")
    emit(f"pipeline armado · {len(NODE_ORDER)} nodos · motor trabajando...")

    for name in NODE_ORDER:
        node_state(name, "running")
        emit(f">> {name} ejecutando...")
        t0 = time.perf_counter()
        try:
            out = NODE_FUNCS[name](ctx)
            if isinstance(out, dict):
                ctx.update(out)
            dur = round(time.perf_counter() - t0, 3)
            entry = {"status": "success", "data": out, "error": None, "duration": dur}
            node_state(name, "success", dur)
            emit(f"OK {name} ({dur}s) · {human_line(name, out)}")
        except Exception as exc:
            dur = round(time.perf_counter() - t0, 3)
            entry = {"status": "failed", "data": {}, "error": str(exc), "duration": dur}
            node_state(name, "failed", dur, str(exc)[:200])
            emit(f"XX {name} fallo ({dur}s): {str(exc)[:140]}")
        results[name] = entry
        if job is not None:
            job.setdefault("results", {})[name] = entry

    scan = {
        "pipeline": {"nodes": {n: (job or {}).get("pipeline", {}).get("nodes", {}).get(n) or {} for n in NODE_ORDER}},
        "results": results,
        "auth_method": auth.auth_method,
        "authenticated": auth.is_authenticated(),
    }
    auth_data = scan["results"].get("auth_status", {}).get("data", {})
    session_check = auth_data.get("session_check", {})
    recon_data = scan["results"].get("recon", {}).get("data", {}).get("recon", {})
    scan["connection"] = {
        "backend": "connected",
        "target_reachable": recon_data.get("status_code") is not None,
        "target_status_code": recon_data.get("status_code"),
        "target_final_url": recon_data.get("final_url"),
        "auth_configured": bool(auth.auth_method),
        "auth_method": auth.auth_method,
        "session_verified": bool(session_check.get("verified")),
        "authenticated": bool(session_check.get("authenticated", False)),
        "username": session_check.get("username"),
        "user_profile": session_check.get("profile"),
        "verification_reason": session_check.get("reason"),
        "verification_url": session_check.get("url"),
    }
    scan["diagnostics"] = {
        "request_id": g.get("request_id"),
        "duration": round(time.perf_counter() - scan_started, 3),
        "completed_nodes": len(scan["results"]),
        "failed_nodes": [name for name, result in scan["results"].items() if result["status"] == "failed"],
    }
    for name, result in scan["results"].items():
        log_event(
            "scan_node", request_id=g.get("request_id"), url=safe_url(url), node=name,
            status=result["status"], duration=result["duration"], error=result["error"],
        )
    log_event("scan_connection", request_id=g.get("request_id"), **scan["connection"])
    return scan


@app.get("/")
def dashboard():
    # el navegador del celular (y a veces tabs viejas) cachean el HTML viejo
    # y el usuario no vuelve a ver los cambios aunque el server ya este
    # actualizado. Forzamos "no-store" para que SIEMPRE pida la version fresca.
    resp = send_from_directory(app.static_folder, "index.html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "codexRC-backend", "version": VERSION, "time": utc_now()})


@app.get("/api/info")
def info():
    return jsonify({
        "name": "codexRC",
        "version": VERSION,
        "backend": "connected",
        "started_at": STARTED_AT,
        "log_format": "jsonl",
        "features": ["session_verification", "username_detection", "structured_logs"],
    })


@app.get("/api/status")
def status():
    return jsonify({
        "status": "ok",
        "backend": "connected",
        "version": VERSION,
        "started_at": STARTED_AT,
        "jobs_in_memory": len(JOBS),
        "reports_directory": str(REPORTS_DIR),
    })


@app.post("/api/scan")
def start_scan():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()
    if not valid_target(url):
        return jsonify({"error": "url debe ser una URL http(s) valida"}), 400

    job_id = uuid.uuid4().hex[:8]
    job = {
        "id": job_id,
        "url": url,
        "created_at": utc_now(),
        "status": "running",
        "version": VERSION,
        "pipeline": {"nodes": {n: {"status": "pending"} for n in NODE_ORDER}},
        "live_log": [],
        "results": {},
    }
    JOBS[job_id] = job

    request_id = g.get("request_id")

    def run_job() -> None:
        # el hilo corre fuera del ciclo de request de Flask: proveer contexto
        with app.app_context():
            g.request_id = request_id
            try:
                scan = execute_scan(url, data, job=job)
                job.update(scan)
                job["status"] = "finished"
                report_path = save_scan_log(job)
                job["log_file"] = str(Path(report_path).relative_to(ROOT))
                job["log_url"] = f"/api/jobs/{job_id}/log"
                save_scan_log(job)
                job.setdefault("diagnostics", {})["report_file"] = job["log_file"]
                log_event("scan_finished", request_id=g.get("request_id"), job_id=job_id, url=safe_url(url), report=job["log_file"])
            except Exception as exc:
                job["status"] = "failed"
                job["error"] = str(exc)
                job.setdefault("live_log", []).append({"ts": utc_now(), "msg": f"XX ERROR FATAL: {str(exc)[:200]}"})
                log_event("scan_failed", request_id=g.get("request_id"), url=safe_url(url), error_type=type(exc).__name__, error=str(exc))

    threading.Thread(target=run_job, daemon=True).start()
    return jsonify({"job_id": job_id, "status": "running", "poll_url": f"/api/jobs/{job_id}"}), 202


HUNTER_NODES = ["spider", "param_map", "xss_get", "xss_forms", "xss_headers", "xss_dom", "report"]


AUTH_FIELDS = ("cookies", "bearer_token", "custom_header_name", "custom_header_value",
               "username", "password", "login_url", "username_field", "password_field",
               "success_indicator", "verification_url")
LAST_AUTH_CONFIG: Dict[str, Any] = {}


def _auth_config_of(data: Dict[str, Any]) -> Dict[str, Any]:
    return {k: data[k] for k in AUTH_FIELDS if data.get(k)}


PRIVATE_PATHS = ("app", "dashboard", "account", "panel", "cabinet", "user",
                 "profile", "wallet", "trade", "member", "personal", "my-account",
                 "referrals", "deposits", "withdrawals", "settings", "history",
                 "transactions", "billing", "balance", "exchange", "admin")


def _descubrir_zona_privada(session, base_url: str, emit) -> list:
    """Sondea rutas tipicas de zona privada comparando GET logueado vs GET anonimo.
    Solo lectura, sin marcadores. Devuelve URLs semilla para la araña."""
    from urllib.parse import urljoin as _ujoin
    anon = requests.Session()
    seeds: list = []
    try:
        shell_ref = session.get(base_url, timeout=12, allow_redirects=True).text
    except Exception:
        shell_ref = ""
    for path in PRIVATE_PATHS:
        u = _ujoin(base_url, "/" + path)
        try:
            r_auth = session.get(u, timeout=10, allow_redirects=False)
            r_anon = anon.get(u, timeout=10, allow_redirects=False)
        except Exception:
            continue
        if r_auth.status_code != 200:
            continue
        ct = (r_auth.headers.get("content-type") or "").lower()
        if "html" not in ct and "json" not in ct:
            continue
        if r_anon.status_code in (401, 403, 301, 302, 303, 307, 308):
            emit(f"[auth-zone] 💥 zona privada confirmada: /{path} "
                 f"(200 logueado vs {r_anon.status_code} anonimo)")
            seeds.append(u)
        elif "html" in ct:
            html = r_auth.text
            spa = ("app-root" in html or 'id="root"' in html or "ng-version" in html)
            if spa and html != shell_ref:
                emit(f"[auth-zone] candidata SPA: /{path} (shell distinta a la del login)")
                seeds.append(u)
    if not seeds:
        emit("[auth-zone] sin rutas privadas obvias; pega la URL del panel logueado "
             "como objetivo del hunter para cazar ahi")
    else:
        emit(f"[auth-zone] {len(seeds)} paginas privadas sembradas en la araña")
    return seeds[:5]


@app.post("/api/hunter")
def start_hunter():
    """HUNTER MODE: arana + corpus XSS automatico, con log de terminal detallado."""
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()
    if not valid_target(url):
        return jsonify({"error": "url debe ser una URL http(s) valida"}), 400

    opts = {
        "get": bool(data.get("opt_get", True)),
        "forms": bool(data.get("opt_forms", True)),
        "headers": bool(data.get("opt_headers", True)),
        "dom": bool(data.get("opt_dom", True)),
        "paths": bool(data.get("opt_paths", True)),
        "api": bool(data.get("opt_api", True)),
        "api_js": bool(data.get("opt_api_js", True)),
        "idor": bool(data.get("opt_idor", True)),
        "params_plus": bool(data.get("opt_params_plus", True)),
    }
    max_pages = min(int(data.get("max_pages") or 25), 100)

    job_id = uuid.uuid4().hex[:8]
    job = {
        "id": job_id,
        "type": "hunter",
        "url": url,
        "created_at": utc_now(),
        "status": "running",
        "version": VERSION,
        "options": opts,
        "pipeline": {"nodes": {n: {"status": "pending"} for n in HUNTER_NODES}},
        "live_log": [],
        "findings": [],
        "results": {},
    }
    JOBS[job_id] = job

    def node_state(name, status, duration=None, error=None):
        job["pipeline"]["nodes"][name] = {"status": status, "duration": duration, "error": error}

    request_id = g.get("request_id")

    def run_hunter():
        with app.app_context():
            g.request_id = request_id
            def emit(msg):
                job["live_log"].append({"ts": utc_now(), "msg": msg})
            try:
                emit(f"[hunter] codexRC v{VERSION} · objetivo fijado: {url}")
                emit("[hunter] modo activo seguro: rutas + BAC API + params ocultos + reflexion. "
                    "Solo lectura A->B, sin payloads de exploit, sin endpoints que escriban")

                if _auth_config_of(data):
                    emit("[hunter] auth: usando las credenciales provistas en este formulario")
                    hunter_data = data
                elif data.get("inherit_auth") and LAST_AUTH_CONFIG:
                    emit("[hunter] auth: HEREDANDO la sesion del ultimo escaneo "
                         f"({', '.join(k for k in LAST_AUTH_CONFIG if k != '_for_url')})")
                    hunter_data = dict(LAST_AUTH_CONFIG)
                    hunter_data["_inherited"] = True
                else:
                    emit("[hunter] auth: SIN sesion, cazando como visitante anonimo")
                    hunter_data = {k: v for k, v in data.items()
                                   if k in ("cookies", "bearer_token", "custom_header_name",
                                            "custom_header_value", "username", "password",
                                            "login_url", "username_field", "password_field",
                                            "success_indicator", "verification_url")}
                auth = build_auth(hunter_data, target_url=url)
                session = auth.get_session()

                seed_urls: list = []
                if hunter_data.get("cookies") or hunter_data.get("bearer_token") or \
                        (hunter_data.get("username") and hunter_data.get("password")):
                    seed_urls = _descubrir_zona_privada(session, url, emit)

                node_state("spider", "running")
                t0 = time.perf_counter()
                spider_out = Spider(session, timeout=15).run(
                    url, emit, max_pages=max_pages, seed_urls=seed_urls)
                node_state("spider", "success", round(time.perf_counter() - t0, 2))
                job["results"]["spider"] = {"status": "success", "data": {"summary": {
                    "pages": spider_out["pages"],
                    "param_count": len(spider_out["param_targets"]),
                    "form_count": len(spider_out["forms"]),
                    "js_endpoints": spider_out["js_endpoints"],
                    "dom_candidates": len(spider_out["dom_candidates"]),
                }}}

                node_state("param_map", "running")
                t0 = time.perf_counter()
                emit("[params] inventario de objetivos:")
                for t in spider_out["param_targets"][:80]:
                    emit(f"[params]   {t['param']} en {urlparse(t['url']).path or '/'}")
                node_state("param_map", "success", round(time.perf_counter() - t0, 2))
                job["results"]["param_map"] = {"status": "success", "data": {
                    "targets": spider_out["param_targets"], "forms": spider_out["forms"]}}

                hunter = XSSHunter(session, emit, delay=float(data.get("delay", 0.15)))
                deep = DeepHunter(session, emit, delay=float(data.get("delay", 0.15)))
                api_hits: list = []

                def run_paths():
                    fnd, hits = deep.test_paths(url)
                    api_hits.extend(hits)
                    return fnd


                def battery(node, key, runner):
                    if not opts.get(key):
                        node_state(node, "success", 0.0)
                        job["results"][node] = {"status": "success", "data": {"skipped": True}}
                        return []
                    node_state(node, "running")
                    t0 = time.perf_counter()
                    before = len(job["findings"])
                    found = runner() or []
                    for f in found:
                        job["findings"].append(f)
                    node_state(node, "success", round(time.perf_counter() - t0, 2))
                    job["results"][node] = {"status": "success", "data": {
                        "found": len(job["findings"]) - before,
                        "details": [f for f in found]}}
                    return found

                # baterias activas seguras: superficie, API-JS, BAC API, IDOR, params ocultos
                battery("surface", "paths", run_paths)

                def run_api_js():
                    fnd, hits = deep.discover_api_from_js(url, spider_out.get("js_files", []))
                    api_hits.extend(hits)
                    return fnd

                battery("api_js", "api_js", run_api_js)
                battery("bac_api", "api", lambda: deep.test_api(url, api_hits))
                battery("idor", "idor", lambda: deep.test_idor(url, api_hits))
                battery("params_plus", "params_plus", lambda: _bateria_get(
                    hunter, {"param_targets": deep.discover_hidden_params(url, spider_out["pages"])}))

                # las 4 baterias del corpus
                battery("xss_get", "get", lambda: _bateria_get(hunter, spider_out))
                battery("xss_forms", "forms", lambda: _bateria_forms(hunter, spider_out))
                battery("xss_headers", "headers", lambda: _bateria_headers(hunter, spider_out))
                battery("xss_dom", "dom", lambda: _bateria_dom(hunter, spider_out))

                job["status"] = "finished"
                node_state("report", "success", 0.0)
                job["summary"] = {
                    "total": len(job["findings"]),
                    "alta": len([f for f in job["findings"] if f["severity"] == "alta"]),
                    "media": len([f for f in job["findings"] if f["severity"] == "media"]),
                    "baja": len([f for f in job["findings"] if f["severity"] == "baja"]),
                    "info": len([f for f in job["findings"] if f["severity"] == "info"]),
                }
                emit(f"[hunter] ═══ CAZA TERMINADA ═══ {job['summary']['total']} hallazgos "
                     f"({job['summary']['alta']} altos · {job['summary']['media']} medios)")
                report_path = save_scan_log(job)
                job["log_file"] = str(Path(report_path).relative_to(ROOT))
                job["log_url"] = f"/api/jobs/{job_id}/log"
                save_scan_log(job)
                log_event("hunter_finished", request_id=g.get("request_id"), url=safe_url(url),
                          summary=job["summary"])
            except Exception as exc:
                job["status"] = "failed"
                job["error"] = str(exc)
                emit(f"[hunter] XX ERROR FATAL: {str(exc)[:200]}")
                log_event("hunter_failed", request_id=g.get("request_id"), url=safe_url(url),
                          error_type=type(exc).__name__, error=str(exc))

    threading.Thread(target=run_hunter, daemon=True).start()
    return jsonify({"job_id": job_id, "status": "running", "poll_url": f"/api/jobs/{job_id}"}), 202


@app.get("/api/jobs")
def list_jobs():
    return jsonify(list(JOBS.values()))


@app.get("/api/jobs/<job_id>")
def get_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    resp = dict(job)
    # seccion aparte: filtraciones de datos de usuarios (lo que importa)
    resp["leaks"] = [f for f in job.get("findings", []) if f.get("leak")]
    return jsonify(resp)


@app.get("/api/jobs/<job_id>/log")
def download_job_log(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    path = REPORTS_DIR / f"codexrc_{job_id}.json"
    if not path.exists():
        return jsonify({"error": "Log not found"}), 404
    return send_file(path, as_attachment=True, download_name=path.name, mimetype="application/json")


@app.get("/api/pipeline/schema")
def pipeline_schema():
    return jsonify({
        "nodes": [
            {"id": "input", "label": "TARGET", "type": "input"},
            {"id": "recon", "label": "RECON", "type": "process"},
            {"id": "tech_detect", "label": "TECH-DETECT", "type": "process"},
            {"id": "auth_status", "label": "AUTH-STATUS", "type": "process"},
            {"id": "security_audit", "label": "SECURITY", "type": "process"},
            {"id": "domain_map", "label": "DOMAIN-MAP", "type": "process"},
            {"id": "cve_match", "label": "CVE-MATCH", "type": "process"},
            {"id": "report", "label": "REPORT", "type": "output"},
        ],
        "edges": [
            {"from": "input", "to": "recon"},
            {"from": "recon", "to": "tech_detect"},
            {"from": "tech_detect", "to": "auth_status"},
            {"from": "auth_status", "to": "security_audit"},
            {"from": "security_audit", "to": "domain_map"},
            {"from": "domain_map", "to": "cve_match"},
            {"from": "cve_match", "to": "report"},
        ],
    })


def _bateria_get(hunter, spider_out):
    return hunter.test_params(spider_out.get("param_targets", []))


def _bateria_forms(hunter, spider_out):
    return hunter.test_forms(spider_out)


def _bateria_headers(hunter, spider_out):
    return hunter.test_headers(spider_out)


def _bateria_dom(hunter, spider_out):
    return hunter.test_dom(spider_out)


@app.route("/hunter.html")
def hunter_page():
    return send_from_directory(app.static_folder, "hunter.html")


if __name__ == "__main__":
    print("\ncodexRC backend running at http://127.0.0.1:8000\n")
    app.run(host="0.0.0.0", port=8000, debug=False)
