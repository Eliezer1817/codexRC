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
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from flask import Flask, g, jsonify, request, send_file, send_from_directory

# Permite ejecutar tanto `python backend/app.py` como `python -m backend.app`.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.auth import AuthManager
from core.cve_matcher import CVEMatcher
from core.pipeline import Pipeline
from core.recon import Recon
from core.tech_detect import TechDetector


app = Flask(__name__, static_folder=str(ROOT / "frontend"), static_url_path="")
JOBS: Dict[str, Dict[str, Any]] = {}
VERSION = "0.11.8"
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


def execute_scan(url: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Ejecuta el pipeline completo dentro del backend."""
    scan_started = time.perf_counter()
    log_event("scan_started", request_id=g.get("request_id"), url=safe_url(url), auth_requested=bool(
        data.get("cookies") or data.get("bearer_token") or data.get("username")
    ))
    auth = build_auth(data, target_url=url)
    session = auth.get_session()
    pipeline = Pipeline()

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
                # auto: endpoints de cuenta protegidos (credentials) o
                # descubiertos al vuelo (cookies/bearer)
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

    pipeline.add_node("recon", node_recon)
    pipeline.add_node("tech_detect", node_tech)
    pipeline.add_node("cve_match", node_cve)
    pipeline.add_node("auth_status", node_auth_info)
    results = pipeline.run({"url": url})

    scan = {
        "pipeline": pipeline.get_status(),
        "results": {
            name: {
                "status": result.status.value,
                "data": result.data,
                "error": result.error,
                "duration": result.duration,
            }
            for name, result in results.items()
        },
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
        return jsonify({"error": "url debe ser una URL http(s) válida"}), 400

    try:
        scan = execute_scan(url, data)
    except Exception as exc:
        log_event("scan_failed", request_id=g.get("request_id"), url=safe_url(url), error_type=type(exc).__name__, error=str(exc))
        return jsonify({
            "error": "scan_failed",
            "message": str(exc),
            "request_id": g.get("request_id"),
            "version": VERSION,
        }), 500

    scan.setdefault("connection", {
        "backend": "connected",
        "target_reachable": False,
        "auth_configured": False,
        "authenticated": False,
        "verification_reason": "diagnostic_unavailable",
    })
    scan.setdefault("diagnostics", {"request_id": g.get("request_id"), "completed_nodes": 0, "failed_nodes": []})

    job_id = uuid.uuid4().hex[:8]
    job = {
        "id": job_id,
        "url": url,
        "created_at": utc_now(),
        "status": "finished",
        "version": VERSION,
        **scan,
    }
    report_path = save_scan_log(job)
    job["log_file"] = str(Path(report_path).relative_to(ROOT))
    job["log_url"] = f"/api/jobs/{job_id}/log"
    # Reescribe incluyendo la ruta de descarga en el propio informe.
    save_scan_log(job)
    job.setdefault("diagnostics", {})["report_file"] = job["log_file"]
    log_event("scan_finished", request_id=g.get("request_id"), job_id=job_id, url=safe_url(url), report=job["log_file"])
    JOBS[job_id] = job
    return jsonify(job)


@app.get("/api/jobs")
def list_jobs():
    return jsonify(list(JOBS.values()))


@app.get("/api/jobs/<job_id>")
def get_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


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
            {"id": "input", "label": "URL Input", "type": "input"},
            {"id": "recon", "label": "Recon", "type": "process"},
            {"id": "tech_detect", "label": "Tech Detect", "type": "process"},
            {"id": "auth", "label": "Auth", "type": "process"},
            {"id": "cve_match", "label": "CVE Matcher", "type": "process"},
            {"id": "report", "label": "Report", "type": "output"},
        ],
        "edges": [
            {"from": "input", "to": "recon"},
            {"from": "recon", "to": "tech_detect"},
            {"from": "tech_detect", "to": "cve_match"},
            {"from": "input", "to": "auth"},
            {"from": "auth", "to": "cve_match"},
            {"from": "cve_match", "to": "report"},
        ],
    })


if __name__ == "__main__":
    print("\ncodexRC backend running at http://127.0.0.1:8000\n")
    app.run(host="0.0.0.0", port=8000, debug=False)
