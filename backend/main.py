from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import database
import scanner
import llm

app = FastAPI(title="SecureLens API")

# Allow the frontend to call this API from any origin (fine for a public demo app)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

database.init_db()


class ScanRequest(BaseModel):
    language: str
    title: str = ""
    code: str


@app.post("/api/scan")
def scan_code(req: ScanRequest):
    if not req.code.strip():
        return {"error": "No code provided."}

    raw_findings = scanner.run_semgrep(req.code, req.language)
    enriched_findings = llm.analyze_findings(raw_findings, req.language)

    title = req.title.strip() or f"Untitled {req.language} scan"
    scan_id = database.save_scan(title, req.language, enriched_findings)

    return {
        "scan_id": scan_id,
        "title": title,
        "language": req.language,
        "findings": enriched_findings,
    }


@app.get("/api/dashboard")
def dashboard():
    return database.get_dashboard_stats()


@app.get("/api/history")
def history():
    return database.get_history()


@app.get("/api/scan/{scan_id}")
def scan_detail(scan_id: str):
    detail = database.get_scan_detail(scan_id)
    if detail is None:
        return {"error": "Scan not found."}
    return detail


# Serve the frontend (index.html, style.css, app.js) for every other route.
# This must be added LAST, after all /api routes above.
app.mount("/", StaticFiles(directory="../frontend", html=True), name="frontend")
