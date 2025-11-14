# app/routers/osint.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.spiderfoot_client import SpiderFootClient
from app.services.osint_processor import store_scan_in_mongo
from app.database.mongo import db


router = APIRouter(prefix="/osint", tags=["OSINT"])

class StoreRequest(BaseModel):
    case_id: str
    scan_id: str
    target: str = None

@router.post("/store")
def store_scan(req: StoreRequest):
    """
    Fetch raw scan results from SpiderFoot and store normalized data into MongoDB.
    """
    raw = SpiderFootClient.get_scan_raw(req.scan_id)
    if raw is None:
        raise HTTPException(status_code=500, detail="Could not fetch scan results from SpiderFoot")
    res = store_scan_in_mongo(case_id=req.case_id, scan_id=req.scan_id, target=req.target or "", raw=raw)
    return {"status": "stored", **res}

@router.get("/entities/{case_id}")
def get_case_entities(case_id: str):
    case = db.osint_cases.find_one({"case_id": case_id}, {"_id": 0, "entities": 1})

    if not case:
        return {"error": "Case not found"}

    entities = case.get("entities", [])

    # Group entities by type
    grouped = {}
    for ent in entities:
        ent_type = ent.get("type", "unknown")
        grouped.setdefault(ent_type, []).append(ent["value"])

    return grouped
