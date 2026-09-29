"""
codexRC - Local FastAPI Backend
Run with: uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="codexRC",
    description="Local backend for codexRC web security auditing pipeline",
    version="0.1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "project": "codexRC",
        "status": "running",
        "message": "Local backend is alive. Visual dashboard coming soon."
    }


@app.get("/health")
def health():
    return {"status": "ok"}
