import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import FileResponse
from pydantic import BaseModel
from scanner.sql_injection import run_sql_injection
from utils.rg import generate_report, generate_pdf_report
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    target_url: str
    attack_types: list[str]

@app.post("/analyze")
async def analyze(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = request.target_url.replace("https://", "").replace("/", "_")
    if "sql_injection" in request.attack_types:
        background_tasks.add_task(run_sql_injection, request.target_url, scan_id)
    return {"message": "Scan started", "scan_id": scan_id}

@app.get("/report/{scan_id}")
async def get_report(scan_id: str):
    try:
        return generate_report(scan_id)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Report not found")

@app.get("/report/{scan_id}/pdf")
async def get_report_pdf(scan_id: str):
    try:
        report_data = generate_report(scan_id)
        pdf_path = generate_pdf_report(scan_id, report_data)
        return FileResponse(pdf_path, media_type='application/pdf', filename=f'{scan_id}_report.pdf')
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Report not found")

# Serve React static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)