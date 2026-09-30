"""
codexRC - Termux-friendly Flask backend + visual dashboard
Run: python backend/app.py
Then open http://localhost:8000  (or the IP shown)
"""

from flask import Flask, request, jsonify, send_from_directory
from pathlib import Path
import sys
import uuid
from datetime import datetime
from typing import Dict, Any, Optional

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.auth import AuthManager
from core.recon import Recon
from core.tech_detect import TechDetector
from core.cve_matcher import CVEMatcher
from core.pipeline import Pipeline

app = Flask(__name__, static_folder=str(ROOT / "frontend"), static_url_path="")

# Simple in-memory job store
JOBS: Dict[str, Dict[str, Any]] = {}


@app.route("/")
def dashboard():
    return send_from_directory(app.static_folder, "index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat() + "Z"})


@app.route("/api/scan", methods=["POST"])
def start_scan():
    data = request.get_json(force=True, silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url is required"}), 400

    auth = AuthManager()

    # Auth methods
    if data.get("cookies"):
        auth.set_cookies(data["cookies"])
    elif data.get("bearer_token"):
        auth.set_bearer_token(data["bearer_token"])
    elif data.get("custom_header_name") and data.get("custom_header_value"):
        auth.set_custom_header(data["custom_header_name"], data["custom_header_value"])
    elif data.get("username") and data.get("password") and data.get("login_url"):
        auth.login_with_credentials(
            login_url=data["login_url"],
            username=data["username"],
            password=data["password"],
        )

    session = auth.get_session()

    pipeline = Pipeline()

    def node_recon(ctx):
        recon = Recon(session)
        return {"recon": recon.run(ctx["url"])}

    def node_tech(ctx):
        detector = TechDetector(session)
        techs = detector.detect(ctx["url"])
        return {"technologies": techs}

    def node_cve(ctx):
        matcher = CVEMatcher()
        try:
            report = matcher.match_technologies(ctx.get("technologies", []))
        finally:
            matcher.close()
        return {"cve_report": report}

    def node_auth_info(ctx):
        return {"auth_info": auth.get_auth_info()}

    pipeline.add_node("recon", node_recon)
    pipeline.add_node("tech_detect", node_tech)
    pipeline.add_node("cve_match", node_cve)
    pipeline.add_node("auth_status", node_auth_info)

    results = pipeline.run({"url": url})

    job_id = str(uuid.uuid4())[:8]
    job = {
        "id": job_id,
        "url": url,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "status": "finished",
        "pipeline": pipeline.get_status(),
        "results": {
            k: {
                "status": v.status.value,
                "data": v.data,
                "error": v.error,
                "duration": v.duration,
            }
            for k, v in results.items()
        },
        "auth_method": auth.auth_method,
        "authenticated": auth.is_authenticated(),
    }
    JOBS[job_id] = job
    return jsonify(job)


@app.route("/api/jobs")
def list_jobs():
    return jsonify(list(JOBS.values()))


@app.route("/api/jobs/<job_id>")
def get_job(job_id):
    job = JOBS.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@app.route("/api/pipeline/schema")
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
    print("\n  codexRC running!")
    print("  Open in browser: http://127.0.0.1:8000")
    print("  Or from other devices use your Termux IP\n")
    app.run(host="0.0.0.0", port=8000, debug=False)
