import sys
from pathlib import Path

# Add project root directory to Python path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from fastapi import FastAPI
from pydantic import BaseModel
from app.graph import DevGuardWorkflow

app = FastAPI(title="DevGuard AI API")
workflow = DevGuardWorkflow()

class CodeReviewRequest(BaseModel):
    code: str
    file_path: str = "main.py"

@app.post("/analyze")
def analyze_code(request: CodeReviewRequest):
    result = workflow.invoke(code=request.code, file_path=request.file_path)
    return result

@app.get("/")
def health_check():
    return {"status": "ok", "message": "DevGuard AI service is running."}