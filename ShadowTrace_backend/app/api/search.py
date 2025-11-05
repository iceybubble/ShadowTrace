from fastapi import APIRouter, BackgroundTasks
from pydantic import BaseModel
import time
from app.services.osint_engine import run_scan

router = APIRouter(prefix="/scan", tags=["OSINT"])

SCAN_CACHE = {}

class Query(BaseModel):
    input_value: str

@router.post("/")
async def start_scan(q: Query, bg: BackgroundTasks):
    qid = str(int(time.time()*1000))
    SCAN_CACHE[qid] = {"status": "scanning"}
    bg.add_task(run_scan, qid, q.input_value)
    return {"query_id": qid, "message": "scan started"}

@router.get("/{query_id}")
async def get_scan(query_id: str):
    return SCAN_CACHE.get(query_id, {"error": "not found"})
