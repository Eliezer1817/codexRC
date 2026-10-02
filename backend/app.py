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
import os
import traceback
import logging
from logging.handlers import RotatingFileHandler
import sys
import time
import uuid
from typing import Any, Dict
import requests
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from flask import Flask, g, jsonify, request, send_file, send_from_directory, Response

# Permite ejecutar tanto `python backend/app.py` como `python -m backend.app`.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import threading

from core.auth import AuthManager
from core.cve_matcher import CVEMatcher
from core.deep_scan import DomainMap, cookie_flags, detect_waf, tls_audit
from core.waf_guard import WafGuard, GuardedSession, CooldownActive
from core.hunter import Spider, XSSHunter, DeepHunter, BlindXSS, XSSPro
from core.pipeline import Pipeline
from core.recon import Recon
from core.tech_detect import TechDetector

NODE_ORDER = ["recon", "tech_detect", "auth_status", "security_audit", "domain_map", "cve_match"]


app = Flask(__name__, static_folder=str(ROOT / "frontend"), static_url_path="")
JOBS: Dict[str, Dict[str, Any]] = {}
# --- estabilidad (v0.21.1): sin carreras, sin fugas, sin jobs colgados ---
JOBS_LOCK = threading.RLock()
MAX_JOBS = 40              # indice en memoria: los terminados mas viejos se podan
MAX_LIVE_LOG = 400         # log vivo por job: se conserva la cola (los mas nuevos)
MAX_JOB_SECONDS = 45 * 60  # watchdog: job corriendo mas de 45 min -> marcado colgado


def _emit(job: Dict[str, Any], msg: str) -> None:
    """Append al log vivo con tope: un job largo no puede comerse la memoria."""
    line = {"ts": utc_now(), "msg": msg}
    log = job.setdefault("live_log", [])
    log.append(line)
    if len(log) > MAX_LIVE_LOG:
        del log[:len(log) - MAX_LIVE_LOG]


def _register_job(job: Dict[str, Any]) -> None:
    """Alta de job con lock y poda: nunca dos hilos pisando el indice."""
    with JOBS_LOCK:
        job["_t_start"] = time.time()
        JOBS[job["id"]] = job
        _prune_jobs()


def _prune_jobs() -> None:
    if len(JOBS) <= MAX_JOBS:
        return
    fin = [(k, j.get("created_at", "")) for k, j in JOBS.items()
           if j.get("status") in ("finished", "failed", "interrupted")]
    fin.sort(key=lambda x: x[1])
    for k, _ in fin[:len(JOBS) - MAX_JOBS]:
        JOBS.pop(k, None)


def _watchdog_loop() -> None:
    """Marca jobs colgados: el hunter nunca deja la UI en 'running' eterno."""
    while True:
        time.sleep(60)
        try:
            with JOBS_LOCK:
                for job in list(JOBS.values()):
                    if job.get("status") != "running":
                        continue
                    t0 = job.get("_t_start")
                    if t0 and (time.time() - t0) > MAX_JOB_SECONDS:
                        job["status"] = "failed"
                        job["error"] = ("watchdog: el job supero 45 min y se "
                                        "marca como colgado; reintentar la caza")
                        _emit(job, "XX WATCHDOG: job excedio el limite de "
                                   "tiempo y se marca colgado")
                        log_event("job_stalled", job_id=job.get("id"),
                                  url=safe_url(job.get("url", "")))
        except Exception:
            pass


def _load_persisted_jobs() -> None:
    """Arranque frio: recupera los ultimos jobs del disco; un job 'running'
    en disco significa que el servidor se reinicio en mitad de caza."""
    try:
        reports = sorted(REPORTS_DIR.glob("codexrc_*.json"))[-MAX_JOBS:]
    except Exception:
        return
    for path in reports:
        try:
            job = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(job, dict) or not job.get("id"):
            continue
        if job.get("status") == "running":
            job["status"] = "interrupted"
            job["error"] = ("el servidor se reinicio mientras corria "
                            "(auto-update o reinicio): reintentar la caza")
        with JOBS_LOCK:
            JOBS.setdefault(job["id"], job)
VERSION = "0.56.2"
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
        origin = urlparse(url).netloc
        per_origin = dict(cfg)
        per_origin["_for_url"] = url
        LAST_AUTH_CONFIGS[origin] = per_origin

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
            # Propagar el error real de auth.py si fallo un intento explicito
            razon_real = "no_auth_method"
            _debug = auth.login_debug
            if _debug and _debug.get("success") is False:
                razon_real = _debug.get("razon") or "credenciales_rechazadas"
            elif _debug and _debug.get("resultado") == "login_api_fallo":
                razon_real = "api_rechazo_credenciales_o_bloqueo"
                # extraer status de la ultima prueba
                for r in _debug.get("respuestas_servidor", []):
                    if r.get("status") in (401, 403, 405):
                        razon_real = f"rechazo_servidor_HTTP_{r.get('status')}"
                        break
            
            session_check = {
                "verified": False,
                "authenticated": False,
                "username": None,
                "reason": razon_real,
                "login_debug": _debug
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


@app.get("/assets/<path:filename>")
def assets(filename):
    """Logo/imagenes del repo (assets/ vive en la raiz, fuera de frontend/)."""
    resp = send_from_directory(str(ROOT / "assets"), filename)
    resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "codexRC-backend", "version": VERSION, "time": utc_now()})


@app.post("/api/decompile")
def api_decompile():
    """DECOMPILE: bytecode DEX -> pseudocodigo legible de metodos."""
    data = request.get_json(silent=True) or {}
    path = (data.get("path") or "").strip()
    top = int(data.get("top") or 25)
    all_m = bool(data.get("all_methods"))
    if not path:
        return jsonify({"error": "falta 'path' (apk o dex)"}), 400
    import os
    if not os.path.exists(path):
        return jsonify({"error": "path inexistente", "path": path}), 404
    from core.decompile import decompile_path
    try:
        res = decompile_path(path, all_methods=all_m, top=top)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"target": path, "count": len(res), "findings": res})


@app.post("/api/re")
def api_re():
    """REVERSE: ingenieria inversa (DEX/class/ELF: estructura interna)."""
    data = request.get_json(silent=True) or {}
    path = (data.get("path") or "").strip()
    top = int(data.get("top") or 30)
    if not path:
        return jsonify({"error": "falta 'path' (apk, jar, dex, binario...)"}), 400
    import os
    if not os.path.exists(path):
        return jsonify({"error": "path inexistente", "path": path}), 404
    from core.re_engine import analyze_path
    try:
        res = analyze_path(path, top=top)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"target": path, "count": len(res), "findings": res})


@app.post("/api/bin")
def api_bin():
    """BIN-AUDIT: analisis binario/nativo (secrets, endpoints, imports)."""
    data = request.get_json(silent=True) or {}
    path = (data.get("path") or "").strip()
    top = int(data.get("top") or 25)
    if not path:
        return jsonify({"error": "falta 'path' (binario, zip, apk, jar...)"}), 400
    import os
    if not os.path.exists(path):
        return jsonify({"error": "path inexistente", "path": path}), 404
    from core.bin_audit import audit_path
    try:
        res = audit_path(path, top=top)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"target": path, "count": len(res), "findings": res})


@app.post("/api/patterns")
def api_patterns():
    """CVE-MATCH: patrones globales de fallos historicos sobre PHP."""
    data = request.get_json(silent=True) or {}
    path = (data.get("path") or "").strip()
    top = int(data.get("top") or 20)
    if not path:
        return jsonify({"error": "falta 'path' (archivo o carpeta PHP)"}), 400
    import os
    if not os.path.exists(path):
        return jsonify({"error": "path inexistente", "path": path}), 404
    from core.pattern_match import scan_path
    try:
        res = scan_path(path, top=top)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"target": path, "count": len(res), "findings": res})


@app.post("/api/taint")
def api_taint():
    """TAINT-TRACE: flujo fuente->sink sobre codigo PHP local."""
    data = request.get_json(silent=True) or {}
    path = (data.get("path") or "").strip()
    top = int(data.get("top") or 20)
    if not path:
        return jsonify({"error": "falta 'path' (archivo o carpeta PHP)"}), 400
    import os
    if not os.path.exists(path):
        return jsonify({"error": "path inexistente", "path": path}), 404
    from core.taint_trace import trace_path
    try:
        res = trace_path(path, top=top)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"target": path, "count": len(res), "findings": res})


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


@app.post("/api/vendor_farm")
def api_vendor_farm():
    """VENDOR-FARM: familias de vendor con installs en rango pagable.
    Devuelve familias con paga estimada (tabla Patchstack), excluyendo
    slugs ya auditados del corpus."""
    data = request.get_json(force=True, silent=True) or {}
    try:
        from core.vendor_farm import run
        res = run(
            tag=data.get("tag"),
            browse=data.get("browse", "popular"),
            pages=int(data.get("pages", 5)),
            min_installs=int(data.get("min", 10000)),
            max_installs=int(data.get("max", 200000)),
            family_min=int(data.get("family_min", 2)),
            exclude_dir=data.get("exclude_dir"),
            exclude_slugs=data.get("exclude_slugs"))
        return jsonify(res)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.post("/api/auth_token")
def api_auth_token():
    """Loguea (con credenciales dadas o heredadas del ultimo escaneo) y
    devuelve el header Authorization listo para usar en curl. SOLO local:
    es tu propio token de sesion, no lo compartas ni lo pegues en ningun lado."""
    data = request.get_json(force=True, silent=True) or {}
    url = str(data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "falta 'url'"}), 400
    keys = ("username", "password", "login_url", "username_field",
            "password_field", "success_indicator", "verification_url",
            "cookies", "bearer_token", "custom_header_name",
            "custom_header_value")
    cfg = {k: data[k] for k in keys if data.get(k)}
    origin = urlparse(url).netloc
    if not _auth_config_of(cfg):
        heredada = LAST_AUTH_CONFIGS.get(origin) or (
            LAST_AUTH_CONFIG
            if urlparse(LAST_AUTH_CONFIG.get("_for_url", "")).netloc == origin
            else None)
        if heredada:
            cfg = dict(heredada)
        else:
            return jsonify({
                "error": "sin credenciales: pasa username/password (y login_url "
                         "opcional), o corre primero un escaneo con sesion para "
                         "heredarla"}), 400
    try:
        auth = build_auth(cfg, target_url=url)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500
    hdr = auth.session.headers.get("Authorization")
    return jsonify({
        "origin": origin,
        "authenticated": bool(auth.authenticated),
        "method": auth.auth_method,
        "scheme": (auth.login_debug or {}).get("session_scheme"),
        "authorization": hdr,
        "cookie_names": sorted(auth.session.cookies.get_dict().keys()),
    })



@app.get("/api/hunt_status")
def api_hunt_status():
    """Progreso vivo de las cazas por lotes (WIDE-HUNT / RETRO-HUNT)."""
    def _n(path):
        try:
            with open(path) as f:
                return sum(1 for _ in f)
        except Exception:
            return 0
    def _tail(path, n=5):
        try:
            lines = open(path, errors="ignore").read().strip().splitlines()
            return lines[-n:]
        except Exception:
            return []
    out = {"wide": {}, "retro": {}}
    w = out["wide"]
    try:
        corpus = json.load(open(ROOT / "wide_corpus.json"))
        w["total_corpus"] = corpus.get("total") or len(corpus.get("plugins", []))
    except Exception:
        w["total_corpus"] = 3260
    w["hechos"] = _n(ROOT / "hechos" / "hunt_wide_done.txt")
    w["ultimos"] = _tail(ROOT / "hechos" / "wide_hunt.log" if (ROOT / "hechos" / "wide_hunt.log").exists() else ROOT / "hechos" / "wide_hunt_results.json.jsonl")
    r = out["retro"]
    try:
        corpus_r = json.load(open(ROOT / "wide_corpus.json"))
        cooldown = "2026-06-01"
        r["total_cola"] = sum(
            1 for p in corpus_r.get("plugins", [])
            if (p.get("last_updated") or "")[:10] < cooldown or not p.get("last_updated")
        )  # universo real pre-cooldown, calculado del corpus vivo (no un numero fijo del lanzamiento)
    except Exception:
        r["total_cola"] = 1007
    r["hechos"] = _n(ROOT / "hechos" / "retro_done.txt")
    r["ultimos"] = _tail(ROOT / "hechos" / "retro_hunt.log")
    return jsonify(out)


@app.post("/api/universal")
def api_universal():
    """UNIVERSAL-ENGINE: perfilar un blanco (path fuente o URL) y correr
    el motor con eleccion automatica de analizadores + ledger de cobertura."""
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "falta 'target' (path o URL)"}), 400
    if not target.startswith("http://") and not target.startswith("https://"):
        import os
        if not os.path.exists(target):
            return jsonify({"error": "path inexistente", "target": target}), 404
    from core.universal_engine import run
    try:
        res = run(target)
    except Exception as e:
        return jsonify({"error": str(e), "trace": traceback.format_exc()[-400:]}), 500
    return jsonify(res)


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
    _register_job(job)

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


HUNTER_NODES = ["spider", "param_map", "brain", "xss_get", "xss_forms", "xss_headers",
                "xss_dom", "sqli", "path", "ssti", "cache", "graphql", "stealth",
                "cov", "veritas", "chain", "escalada", "self_tune", "report"]


AUTH_FIELDS = ("cookies", "bearer_token", "custom_header_name", "custom_header_value",
               "username", "password", "login_url", "username_field", "password_field",
               "success_indicator", "verification_url")
LAST_AUTH_CONFIG: Dict[str, Any] = {}
# estabilidad: la sesion heredada se guarda POR ORIGEN para que dos cazas
# contra sitios distintos nunca se pisen la sesion de la otra
LAST_AUTH_CONFIGS: Dict[str, Dict[str, Any]] = {}

# GHOST-SHIELD: evasion WAF con memoria. El estado persiste en waf_state.json
# (excluido del repo): la memoria de quien nos bloqueo sobrevive jobs y reinicios.
WAF_GUARD = WafGuard(log=lambda m: None, state_path=str(ROOT / "waf_state.json"))


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


def _create_hunt_job(data: Dict[str, Any], url: str = None):
    """Crea un job de caza y lanza su hilo. Devuelve (job_id, error).
    Reutilizable por /api/hunter y por el LOTE (/api/hunt_batch)."""
    url = url or str(data.get("url", "")).strip()
    if not valid_target(url):
        return None, ("url debe ser una URL http(s) valida", 400)

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
        "csp": bool(data.get("opt_csp", True)),
        "blind": bool(data.get("opt_blind", False)),  # ESCRIBE en el blanco
        "xss_pro": bool(data.get("opt_xss_pro", False)),  # avanzados: stored POSTEA marcador
        "veritas": bool(data.get("opt_veritas", True)),  # navegador real contra FP
        "sqli": bool(data.get("opt_sqli", True)),  # SQLI-BAIT: inyeccion SQL activa
        "stealth": bool(data.get("opt_stealth", True)),  # STEALTH-BAIT: superficie oculta (lectura)
        "path": bool(data.get("opt_path", True)),  # PATH-BAIT: LFI/traversal (lectura)
        "ssti": bool(data.get("opt_ssti", True)),  # SSTI-BAIT: plantillas con fingerprint (lectura)
        "cache": bool(data.get("opt_cache", True)),  # CACHE-BAIT: poisoning/deception (pasivo)
        "graphql": bool(data.get("opt_graphql", True)),  # GraphQL: esquema y batching (lectura)
        "cov": bool(data.get("opt_cov", False)),  # COV-BAIT: cobertura de codigo (navegador real)
    }
    max_pages = min(int(data.get("max_pages") or 25), 100)
    # OVERDRIVE: sondas en vuelo simultaneas (1 = clasico secuencial)
    workers = max(1, min(int(data.get("workers") or 4), 8))
    # GHOST-SHIELD: evasion WAF con memoria (jitter + cooldown por origen)
    opt_waf = bool(data.get("opt_waf", True))
    opt_veritas = bool(data.get("opt_veritas", True))

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
    _register_job(job)

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
                elif data.get("inherit_auth") and (
                        LAST_AUTH_CONFIGS.get(urlparse(url).netloc)
                        or (LAST_AUTH_CONFIG
                            and urlparse(LAST_AUTH_CONFIG.get("_for_url", "")).netloc
                            == urlparse(url).netloc)):
                    emit("[hunter] auth: HEREDANDO la sesion del ultimo escaneo "
                         f"({', '.join(k for k in LAST_AUTH_CONFIG if k != '_for_url')})")
                    cfg_heredada = (LAST_AUTH_CONFIGS.get(urlparse(url).netloc)
                                    or LAST_AUTH_CONFIG)
                    hunter_data = dict(cfg_heredada)
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
                if opt_waf:
                    # los mensajes del guardián (bloqueos, quemado, rehab)
                    # llegan al log vivo de ESTE job
                    WAF_GUARD.log = emit
                    session = GuardedSession.wrap(
                        session, WAF_GUARD,
                        jitter=float(data.get("delay", 0.15)))
                    emit("[hunter] GHOST-SHIELD activo: jitter aleatorio + "
                         "deteccion de bloqueo WAF + cooldown con memoria por origen")

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

                # ---- CEREBRO: fingerprint del blanco + cola de caza rankeada
                node_state("brain", "running")
                t0 = time.perf_counter()
                from core.brain import Brain
                brain_out = Brain(session, emit, timeout=15).run(url, spider_out)
                node_state("brain", "success", round(time.perf_counter() - t0, 2))
                job["results"]["brain"] = {"status": "success", "data": {
                    "fingerprint": brain_out["fingerprint"],
                    "ranked": [
                        {"url": t["url"], "param": t["param"], "score": t["score"],
                         "budget": t["budget"], "why": t["why"]}
                        for t in brain_out["ranked_targets"][:50]]}}
                # las baterias consumen la cola YA ordenada por valor
                spider_out["param_targets"] = brain_out["ranked_targets"]

                hunter = XSSHunter(session, emit, delay=float(data.get("delay", 0.15)),
                                   workers=workers)
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
                    try:
                        found = runner() or []
                    except Exception as exc:      # AISLAMIENTO: una bateria
                        # que explota NO tumba la caza: se marca el nodo en
                        # error, se reporta al log vivo y el pipeline sigue
                        emit(f"💥 [hunter] bateria '{node}' FALLO: "
                             f"{type(exc).__name__}: {str(exc)[:120]} · "
                             f"la caza CONTINUA con las demas")
                        node_state(node, "error", round(time.perf_counter() - t0, 2),
                                   error=f"{type(exc).__name__}: {str(exc)[:200]}")
                        job["results"][node] = {"status": "error", "data": {
                            "error": f"{type(exc).__name__}: {str(exc)[:200]}"}}
                        return []
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
                battery("csp", "csp", lambda: deep.test_csp(url))
                battery("blind", "blind", lambda: BlindXSS(
                    session, emit, delay=float(data.get("delay", 0.15)),
                    timeout=15.0).plant(spider_out, data.get("blind_endpoint", "")))
                battery("xss_pro", "xss_pro", lambda: XSSPro(
                    session, emit, delay=float(data.get("delay", 0.15)),
                    timeout=15.0, workers=workers).run(url, spider_out))
                battery("params_plus", "params_plus", lambda: _bateria_get(
                    hunter, {"param_targets": deep.discover_hidden_params(url, spider_out["pages"])}))

                # las 4 baterias del corpus
                battery("xss_get", "get", lambda: _bateria_get(hunter, spider_out))
                battery("xss_forms", "forms", lambda: _bateria_forms(hunter, spider_out))
                battery("xss_headers", "headers", lambda: _bateria_headers(hunter, spider_out))
                battery("xss_dom", "dom", lambda: _bateria_dom(hunter, spider_out))

                def run_veritas():
                    if not opt_veritas:
                        emit("[veritas] desactivado por el operador")
                        return []
                    from core.veritas import Veritas
                    v = Veritas(emit, max_verify=8)
                    if not v.available():
                        emit("[veritas] Chrome headless no encontrado en el "
                             "sistema: hallazgos quedan como reflexiones")
                        return []
                    v.verify_all(job["findings"])
                    return []   # muta hallazgos in place: confirmados y descartes

                def run_path():
                    from core.path_bait import PathBait
                    return PathBait(session, emit).run(url, spider_out)

                battery("path", "path", run_path)

                def run_ssti():
                    from core.ssti_bait import SstiBait
                    return SstiBait(session, emit).run(url, spider_out)

                battery("ssti", "ssti", run_ssti)

                def run_cache():
                    from core.cache_bait import CacheBait
                    return CacheBait(session, emit).run(url, spider_out)

                battery("cache", "cache", run_cache)

                def run_graphql():
                    from core.graphql_bait import GraphqlBait
                    return GraphqlBait(session, emit).run(url)

                battery("graphql", "graphql", run_graphql)

                def run_cov():
                    from core.cov_bait import CovBait
                    return CovBait(session, emit).run(url, spider_out)

                battery("cov", "cov", run_cov)

                def run_stealth():
                    from core.stealth_bait import StealthBait
                    return StealthBait(session, emit, delay=float(
                        data.get("delay", 0.15))).run(url, spider_out)

                battery("stealth", "stealth", run_stealth)

                def run_sqli():
                    from core.sqli_bait import SqlBait
                    return SqlBait(hunter).run(spider_out.get("param_targets", []))

                battery("sqli", "sqli", run_sqli)

                battery("veritas", "veritas", run_veritas)

                # ---- ENCADENAR HALLAZGOS (cadenas de impacto combinado)
                node_state("chain", "running")
                t0 = time.perf_counter()
                from core.chain import Chainer
                chains = Chainer(emit).run(job["findings"])
                node_state("chain", "success", round(time.perf_counter() - t0, 2))
                job["results"]["chain"] = {"status": "success", "data": {"chains": chains}}

                # ---- ESCALADA: continuar solo despues del aviso critico
                t0 = time.perf_counter()
                try:
                    from core.escalada import Escalador
                    esc_out = Escalador(emit, session).run(url, chains, job["findings"])
                    job["results"]["escalada"] = {"status": "success", "data": esc_out}
                except Exception as exc:
                    emit(f"[escalada] error aislado: {str(exc)[:200]}")
                    job["results"]["escalada"] = {"status": "error", "error": str(exc)[:200]}
                node_state("escalada", "success", round(time.perf_counter() - t0, 2))

                # ---- AUTOCORRECCION (memoria de rendimiento)
                node_state("self_tune", "running")
                t0 = time.perf_counter()
                from core.self_tune import SelfTune
                SelfTune(emit).record(job["findings"],
                                     brain_out.get("fingerprint", {}))
                node_state("self_tune", "success", round(time.perf_counter() - t0, 2))

                job["status"] = "finished"
                node_state("report", "success", 0.0)
                job["summary"] = {
                    "total": len(job["findings"]),
                    "chains": len(chains),
                    "escalaciones": len((job["results"].get("escalada", {}).get("data", {}) or {}).get("escalations", [])),
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
    return job_id, None


# ------------------------- CAZA EN LOTE (v0.25.2) -------------------------
BATCHES: Dict[str, Dict[str, Any]] = {}
BATCHES_LOCK = threading.Lock()
BATCH_PER_TARGET_TIMEOUT = 50 * 60  # 50 min por blanco (watchdog mata a los 45)


def _prune_batches() -> None:
    if len(BATCHES) <= 20:
        return
    for bid in sorted(BATCHES, key=lambda b: BATCHES[b]["created_at"])[:-20]:
        BATCHES.pop(bid, None)


@app.post("/api/hunt_batch")
def start_hunt_batch():
    """LOTE: cola de blancos que se cazan en serie, uno por uno, con la misma
    configuracion. Un blanco que falla no tumba el lote. Devuelve un id de
    lote para seguir el progreso."""
    data = request.get_json(silent=True) or {}
    raw = data.get("targets") or []
    targets, invalid = [], []
    for t in raw:
        t = str(t).strip()
        (targets if valid_target(t) else invalid).append(t)
    if not targets:
        return jsonify({"error": "targets: al menos una URL http(s) valida "
                                 f"(invalidas: {invalid[:5]})"}), 400
    bid = uuid.uuid4().hex[:8]
    batch = {
        "id": bid, "type": "batch", "created_at": utc_now(),
        "status": "running", "version": VERSION,
        "total": len(targets), "done": 0,
        "targets": targets, "invalid_targets": invalid,
        "results": [], "summary": {}, "live_log": [],
    }
    with BATCHES_LOCK:
        BATCHES[bid] = batch
        _prune_batches()

    def bemit(msg: str) -> None:
        with BATCHES_LOCK:
            batch["live_log"].append({"ts": utc_now(), "msg": msg})

    def run_batch() -> None:
        with app.app_context():
            g.request_id = None
            tot_h = alt_h = leak_h = ver_h = 0
            ok = failed = 0
            bemit(f"[lote] === LOTE INICIADO: {len(targets)} blancos ===")
            for i, t in enumerate(targets, 1):
                bemit(f"[lote] ({i}/{len(targets)}) cazando: {t}")
                job_id, err = _create_hunt_job(dict(data, url=t), url=t)
                if err:
                    failed += 1
                    with BATCHES_LOCK:
                        batch["results"].append({"url": t, "status": "invalid",
                                                 "error": err[0]})
                    bemit(f"[lote] XX {t} invalido: {err[0]}")
                    continue
                deadline = time.time() + BATCH_PER_TARGET_TIMEOUT
                while True:
                    j = JOBS.get(job_id) or {}
                    st = j.get("status")
                    if st in ("finished", "failed") or time.time() > deadline:
                        break
                    time.sleep(2.0)
                j = JOBS.get(job_id) or {}
                fs = j.get("findings") or []
                s = j.get("summary") or {}
                nl = len([f for f in fs if f.get("leak")])
                nv = len([f for f in fs if f.get("verificado")])
                row = {"url": t, "job_id": job_id, "status": j.get("status"),
                       "hallazgos": s.get("total", len(fs)), "alta": s.get("alta", 0),
                       "filtraciones": nl, "verificados": nv}
                with BATCHES_LOCK:
                    batch["results"].append(row)
                    batch["done"] += 1
                if j.get("status") == "failed":
                    failed += 1
                    bemit(f"[lote] XX {t} FALLO: {str(j.get('error'))[:100]}")
                else:
                    ok += 1
                    tot_h += row["hallazgos"]; alt_h += row["alta"]
                    leak_h += nl; ver_h += nv
                    bemit(f"[lote] OK {t}: {row['hallazgos']} hallazgos "
                          f"({row['alta']} altos · {nl} filtraciones · {nv} verificados)")
                log_event("batch_target_done", batch_id=bid, url=safe_url(t),
                          status=j.get("status"), summary=s)
            with BATCHES_LOCK:
                batch["status"] = "finished"
                batch["summary"] = {
                    "blancos": len(targets), "ok": ok, "failed": failed,
                    "hallazgos": tot_h, "alta": alt_h,
                    "filtraciones": leak_h, "verificados": ver_h,
                }
            bemit(f"[lote] === LOTE TERMINADO: {ok}/{len(targets)} cazados · "
                  f"{tot_h} hallazgos ({alt_h} altos · {leak_h} filtraciones · "
                  f"{ver_h} verificados) ===")
            log_event("batch_finished", batch_id=bid,
                      summary=batch["summary"])

    threading.Thread(target=run_batch, daemon=True).start()
    return jsonify({"batch_id": bid, "status": "running", "total": len(targets),
                    "invalid_targets": invalid,
                    "poll_url": f"/api/batch/{bid}"}), 202


@app.get("/api/batch/<bid>")
def get_batch(bid: str):
    with BATCHES_LOCK:
        b = BATCHES.get(bid)
        if not b:
            return jsonify({"error": "Lote no encontrado"}), 404
        return jsonify(dict(b))


@app.get("/api/batches")
def list_batches():
    with BATCHES_LOCK:
        return jsonify(list(BATCHES.values()))


@app.post("/api/hunter")
def start_hunter():
    """HUNTER MODE: arana + corpus XSS automatico, con log de terminal detallado."""
    data = request.get_json(silent=True) or {}
    job_id, err = _create_hunt_job(data)
    if err:
        return jsonify({"error": err[0]}), err[1]
    return jsonify({"job_id": job_id, "status": "running", "poll_url": f"/api/jobs/{job_id}"}), 202


@app.get("/api/jobs")
def list_jobs():
    with JOBS_LOCK:
        snapshot = list(JOBS.values())
    return jsonify(snapshot)


@app.get("/api/jobs/<job_id>")
def get_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    resp = dict(job)
    # seccion aparte: filtraciones de datos de usuarios (lo que importa)
    resp["leaks"] = [f for f in job.get("findings", []) if f.get("leak")]
    return jsonify(resp)


@app.get("/api/jobs/<job_id>/export")
def export_job(job_id: str):
    """Exporta el informe de la caza: TXT plano, JSON completo o PDF
    estilizado (Chrome headless, fallback fpdf2)."""
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    fmt = (request.args.get("format") or "txt").strip().lower()
    base = f"codexrc_{job_id}_caza"
    try:
        from core import report_export
        # inline (no "attachment"): en movil Chrome abre directo en el visor,
        # el usuario VE el informe aparecer en lugar de una descarga silenciosa
        # a la carpeta Descargas sin aviso visible (bug real reportado 02/10/2026)
        if fmt == "json":
            return Response(report_export.build_json(job), mimetype="application/json",
                            headers={"Content-Disposition":
                                     f'inline; filename="{base}.json"'})
        if fmt == "pdf":
            data, method = report_export.build_pdf(job)
            if not data:
                return jsonify({"error": "PDF no disponible: no hay navegador "
                                         "Chromium ni fpdf2 instalado "
                                         "(pip install fpdf2)"}), 503
            resp = Response(data, mimetype="application/pdf",
                            headers={"Content-Disposition":
                                     f'inline; filename="{base}.pdf"'})
            resp.headers["X-Pdf-Method"] = method
            return resp
        if fmt != "txt":
            return jsonify({"error": "formato debe ser txt, json o pdf"}), 400
        return Response(report_export.build_txt(job), mimetype="text/plain; charset=utf-8",
                        headers={"Content-Disposition":
                                 f'inline; filename="{base}.txt"'})
    except Exception as exc:
        return jsonify({"error": f"exportando: {type(exc).__name__}: "
                                 f"{str(exc)[:150]}"}), 500


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


@app.errorhandler(Exception)
def _safe_500(exc):
    """Cualquier excepcion no manejada responde JSON y el server sigue vivo."""
    from werkzeug.exceptions import HTTPException
    if isinstance(exc, HTTPException):
        return exc
    log_event("unhandled_error", request_id=g.get("request_id"),
              error_type=type(exc).__name__, error=str(exc)[:200])
    return jsonify({"error": f"{type(exc).__name__}: {str(exc)[:200]}"}), 500


_ARS_TOKENS: Dict[str, float] = {}


def _ars_token_ok(token) -> bool:
    exp = _ARS_TOKENS.get(str(token or ""))
    if not exp:
        return False
    if time.time() > exp:
        _ARS_TOKENS.pop(token, None)
        return False
    return True


@app.post("/api/arsenal/fire")
def api_arsenal_fire():
    """Dispara UN payload elegido contra el blanco del operador.
    Requiere token de desbloqueo (30 min). Registra target+nombre en log.
    Mide tiempo de respuesta (deteccion de inyeccion ciega temporal) y
    si el payload se refleja en la respuesta (deteccion de XSS reflejado).
    Una sola peticion por llamada: demostracion minima."""
    body = request.get_json(silent=True) or {}
    if not _ars_token_ok(body.get("token")):
        return jsonify({"error": "sesion de arsenal expirada o invalida: "
                                 "desbloquea de nuevo"}), 401
    target = str(body.get("target") or "").strip()
    payload = str(body.get("payload") or "")
    nombre = str(body.get("nombre") or "?")
    if not target.startswith(("http://", "https://")):
        return jsonify({"error": "URL del blanco invalida (http/https)"}), 400
    if not payload:
        return jsonify({"error": "payload vacio"}), 400
    # punto de inyeccion: {INJECT} en la URL, o ?q= al final
    if "{INJECT}" in target:
        full = target.replace("{INJECT}", payload)
    else:
        sep = "&" if "?" in target else "?"
        full = target + sep + "q=" + payload
    app.logger.warning("[ARSENAL] DISPARO '%s' -> %s", nombre, target[:160])
    t0 = time.time()
    try:
        r = requests.get(full, timeout=20, allow_redirects=False,
                         headers={"User-Agent": "CodexRC-ARSENAL/audit"})
    except Exception as exc:
        return jsonify({"error": f"conexion fallida: {exc}"[:200]}), 502
    elapsed_ms = int((time.time() - t0) * 1000)
    text = r.text or ""
    return jsonify({
        "status_code": r.status_code,
        "elapsed_ms": elapsed_ms,
        "reflejado": payload in text,
        "url_usada": full[:300],
        "body_head": text[:600],
    })


@app.get("/api/zombies")
def api_zombies_list():
    """Inventario de procesos del backend: 1 legitimo, duplicados, zombis Z."""
    from core.zombies import listar
    return jsonify({"procesos": listar(), "yo": os.getpid()})


@app.post("/api/zombies/kill")
def api_zombies_kill():
    """Mata DUPLICADOS del backend por PID (nunca pkill -f, nunca a si mismo).
    El backend mas antiguo sobrevive; los clones mueren con kill -9."""
    from core.zombies import matar
    r = matar()
    app.logger.warning("[ZOMBIES] kill ejecutado: matados=%s zombis=%s", r["matados"], r["zombis"])
    return jsonify(r)


@app.route("/hunter.html")
def hunter_page():
    return send_from_directory(app.static_folder, "hunter.html")


@app.route("/arsenal.html")
def arsenal_page():
    return send_from_directory(app.static_folder, "arsenal.html")


# ---------- ARSENAL: payloads gateados con contrasena ----------
# Los payloads EXTREMO solo se entregan tras POST con contrasena
# correcta (ARSENAL_PASSWORD, default "extremo"). Cada intento —
# fallido o no — queda registrado en el log del backend (auditoria).
ARS_PASSWORD = os.environ.get("ARSENAL_PASSWORD", "extremo")


def _arsenal_data(unlocked: bool) -> Dict[str, Any]:
    """Inventario del arsenal. Sin desbloquear: los EXTREMO viajan con el
    payload oculto (🔒). Desbloqueado: payload completo."""
    from core.arsenal import CATEGORIES
    categorias = []
    for cid, (titulo, entries) in CATEGORIES.items():
        items = []
        for name, payload, note, nivel in entries:
            extremo = (nivel == "extremo")
            items.append({
                "nombre": name,
                "payload": payload if (unlocked or not extremo) else "🔒 bloqueado",
                "nota": note,
                "extremo": extremo,
            })
        categorias.append({"id": cid, "titulo": titulo, "grupos": [
            {"nombre": "basico + extremo", "items": items}]})
    return {"version": VERSION, "categorias": categorias, "extreme": unlocked}


@app.get("/api/arsenal")
def api_arsenal():
    """Inventario BASICO (verde) visible; EXTREMO oculto hasta contrasena."""
    return jsonify(_arsenal_data(unlocked=False))


@app.post("/api/arsenal/resume")
def api_arsenal_resume():
    """Restaura una sesion de desbloqueo vigente (<=30 min) sin volver a pedir
    contrasena. El token vive en el servidor; el front solo lo guarda."""
    body = request.get_json(silent=True) or {}
    token = str(body.get("token") or "")
    if token not in _ARS_TOKENS:
        return jsonify({"error": "sesion expirada o invalida"}), 401
    restante = _ARS_TOKENS[token] - time.time()
    if restante <= 0:
        _ARS_TOKENS.pop(token, None)
        return jsonify({"error": "sesion expirada o invalida"}), 401
    # refresco del plazo: la actividad extiende otros 30 min (fix pedido del
    # operador: salir de la pagina y volver ya no obliga a re-desbloquear)
    _ARS_TOKENS[token] = time.time() + 1800
    data = _arsenal_data(unlocked=True)
    data["token"] = token
    data["segundos_restantes"] = int(restante)
    app.logger.warning("[ARSENAL] sesion RESTAURADA (quedan %ds)", int(restante))
    return jsonify(data)


@app.post("/api/arsenal/report")
def api_arsenal_report():
    """Genera el informe ordenado de una corrida del arsenal y lo guarda como
    job: trofeos (credenciales) primero, escalas confirmadas por nivel, resto
    de intentos como info. Reutiliza el export PDF/TXT/JSON del hunter."""
    body = request.get_json(silent=True) or {}
    if not _ars_token_ok(body.get("token")):
        return jsonify({"error": "sesion de arsenal expirada o invalida: "
                                 "desbloquea de nuevo"}), 401
    hallazgos = body.get("hallazgos") or []
    trofeos = body.get("trofeos") or []
    resumen = body.get("resumen") or {}
    # trofeo = hallazgo con leak:true -> el export lo pinta en la banda roja
    for t in trofeos:
        t["leak"] = True
        t.setdefault("severity", "critica")
    # orden: confirmados por severidad, luego info (intentos sin confirmar)
    orden = {"critica": 0, "alta": 1, "media": 2, "baja": 3, "info": 4}
    hallazgos.sort(key=lambda f: orden.get(f.get("severity"), 9))
    todo = trofeos + hallazgos
    job = {
        "id": "ars" + uuid.uuid4().hex[:6],
        "url": f"ARSENAL · {resumen.get('blancos', 0)} blancos · {resumen.get('disparos', 0)} disparos",
        "status": "finished", "version": VERSION,
        "findings": todo,
        "leaks": [f for f in todo if f.get("leak")],
        "summary": {
            "total": len(hallazgos),
            "alta": len([f for f in hallazgos if f.get("severity") == "alta"]),
            "media": len([f for f in hallazgos if f.get("severity") == "media"]),
            "baja": len([f for f in hallazgos if f.get("severity") == "baja"]),
            "info": len([f for f in hallazgos if f.get("severity") == "info"]),
            "chains": resumen.get("escalas", 0),
        },
        "results": {"escalada": {"status": "success", "data": {"escalations": [
            {"chain": "corrida de arsenal", "verdict": resumen.get("veredicto", "sin impacto"),
             "poc": "", "playbook": [resumen.get("detalle", "")]}
        ]}}},
    }
    JOBS[job["id"]] = job
    app.logger.warning("[ARSENAL] informe generado: %s (%s hallazgos, %s trofeos)",
                       job["id"], len(hallazgos), len(trofeos))
    return jsonify({"report_id": job["id"],
                    "export_urls": {f: f"/api/jobs/{job['id']}/export?format={f}"
                                    for f in ("pdf", "txt", "json")}})


@app.post("/api/arsenal/extreme")
def api_arsenal_extreme():
    """Desbloquea TODOS los payloads (incl. extremos). Exige contrasena.
    Registra en log cada intento, exitoso o fallido (auditoria)."""
    body = request.get_json(silent=True) or {}
    pw = str(body.get("password") or "")
    remote = request.remote_addr or "?"
    if pw != ARS_PASSWORD:
        app.logger.warning("[ARSENAL] intento de desbloqueo FALLIDO desde %s", remote)
        return jsonify({"error": "contrasena incorrecta"}), 403
    app.logger.warning("[ARSENAL] MODO EXTREMO desbloqueado desde %s", remote)
    token = uuid.uuid4().hex
    _ARS_TOKENS[token] = time.time() + 1800  # 30 min de sesion de disparo
    data = _arsenal_data(unlocked=True)
    data["token"] = token
    return jsonify(data)


if __name__ == "__main__":
    print("\ncodexRC backend running at http://127.0.0.1:8000\n")
    _load_persisted_jobs()
    threading.Thread(target=_watchdog_loop, daemon=True).start()
    # threaded=True: un scan pesado nunca congela el dashboard ni las encuestas
    app.run(host="0.0.0.0", port=8000, threaded=True, debug=False)
