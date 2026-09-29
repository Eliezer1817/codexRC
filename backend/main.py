"""
codexRC - Local FastAPI Backend + Visual Dashboard support
Run: uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
Then open http://localhost:8000/
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict, Any, List
import uuid
from datetime import datetime
from pathlib import Path

# Core imports
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.auth import AuthManager
from core.recon import Recon
from core.tech_detect import TechDetector
from core.cve_matcher import CVEMatcher
from core.pipeline import Pipeline, NodeStatus

app = FastAPI(
    title="codexRC",
    description="Local backend + visual pipeline for web security auditing",
    version="0.2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory job store (simple for local use)
JOBS: Dict[str, Dict[str, Any]] = {}


class ScanRequest(BaseModel):
    url: str
    # Auth options (choose one style)
    cookies_file: Optional[str] = None
    cookies: Optional[Dict[str, str]] = None
    username: Optional[str] = None
    password: Optional[str] = None
    login_url: Optional[str] = None
    bearer_token: Optional[str] = None
    custom_header_name: Optional[str] = None
    custom_header_value: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
def dashboard():
    html_path = Path(__file__).parent.parent / "frontend" / "index.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>codexRC</h1><p>Frontend not found. Place frontend/index.html</p>")


@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat() + "Z"}


@app.post("/api/scan")
def start_scan(req: ScanRequest):
    job_id = str(uuid.uuid4())[:8]

    auth = AuthManager()
    # Apply auth
    if req.cookies_file:
        try:
            auth.load_cookies_from_file(req.cookies_file)
        except Exception as e:
            raise HTTPException(400, f"Cookies file error: {e}")
    elif req.cookies:
        auth.set_cookies(req.cookies)
    elif req.bearer_token:
        auth.set_bearer_token(req.bearer_token)
    elif req.custom_header_name and req.custom_header_value:
        auth.set_custom_header(req.custom_header_name, req.custom_header_value)
    elif req.username and req.password and req.login_url:
        ok = auth.login_with_credentials(req.login_url, req.username, req.password)
        if not ok:
            # Still continue but mark auth failed
            pass

    session = auth.get_session()

    # Build pipeline
    pipeline = Pipeline()

    def node_recon(ctx):
        recon = Recon(session)
        data = recon.run(ctx["url"])
        return {"recon": data, "html": None}  # html filled later if needed

    def node_tech(ctx):
        detector = TechDetector(session)
        # Re-fetch for HTML if needed
        recon_data = ctx.get("recon", {})
        techs = detector.detect(ctx["url"])
        return {"technologies": techs}

    def node_cve(ctx):
        matcher = CVEMatcher()
        techs = ctx.get("technologies", [])
        report = matcher.match_technologies(techs)
        matcher.close()
        return {"cve_report": report}

    def node_auth_info(ctx):
        return {"auth_info": auth.get_auth_info()}

    pipeline.add_node("recon", node_recon)
    pipeline.add_node("tech_detect", node_tech)
    pipeline.add_node("cve_match", node_cve)
    pipeline.add_node("auth_status", node_auth_info)

    results = pipeline.run({"url": req.url})

    job = {
        "id": job_id,
        "url": req.url,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "status": "finished",
        "pipeline": pipeline.get_status(),
        "results": {k: {"status": v.status.value, "data": v.data, "error": v.error, "duration": v.duration}
                    for k, v in results.items()},
        "auth_method": auth.auth_method,
        "authenticated": auth.is_authenticated(),
    }
    JOBS[job_id] = job
    return job


@app.get("/api/jobs")
def list_jobs():
    return list(JOBS.values())


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(404, "Job not found")
    return JOBS[job_id]


@app.get("/api/pipeline/schema")
def pipeline_schema():
    """Describes the nodes and connections for the visual frontend."""
    return {
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
        ]
    }
