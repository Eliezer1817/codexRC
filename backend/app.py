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
import sys
import uuid
from typing import Any, Dict
from urllib.parse import urlparse

from flask import Flask, jsonify, request, send_file, send_from_directory

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
VERSION = "0.4.0"
REPORTS_DIR = ROOT / "reports"
REPORTS_DIR.mkdir(exist_ok=True)
logging.basicConfig(
    filename=str(REPORTS_DIR / "backend.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
LOGGER = logging.getLogger("codexRC")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def valid_target(url: str) -> bool:
    parsed = urlparse(url)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


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


def build_auth(data: Dict[str, Any]) -> AuthManager:
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
    elif data.get("username") and data.get("password") and data.get("login_url"):
        auth.login_with_credentials(
            login_url=str(data["login_url"]),
            username=str(data["username"]),
            password=str(data["password"]),
        )
    return auth


def execute_scan(url: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Ejecuta el pipeline completo dentro del backend."""
    LOGGER.info("scan_started url=%s", url)
    auth = build_auth(data)
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
            verification_url = str(data.get("verification_url") or url)
            session_check = auth.verify_session(verification_url)
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
    for name, result in scan["results"].items():
        LOGGER.info(
            "scan_node url=%s node=%s status=%s duration=%s error=%s",
            url, name, result["status"], result["duration"], result["error"],
        )
    return scan


@app.get("/")
def dashboard():
    return send_from_directory(app.static_folder, "index.html")


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "codexRC-backend", "version": VERSION, "time": utc_now()})


@app.get("/api/info")
def info():
    return jsonify({"name": "codexRC", "version": VERSION, "log_format": "json"})


@app.post("/api/scan")
def start_scan():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()
    if not valid_target(url):
        return jsonify({"error": "url debe ser una URL http(s) válida"}), 400

    try:
        scan = execute_scan(url, data)
    except Exception as exc:
        LOGGER.exception("scan_failed url=%s", url)
        return jsonify({"error": str(exc)}), 500

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
    LOGGER.info("scan_finished id=%s url=%s log=%s", job_id, url, report_path)
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
