# app/api/search.py
from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from bson import ObjectId
import os

# import the db we created in main.py
# If you keep `db = client["shadowtrace"]` in main.py, import like below.
# If you instead have app.database.mongo.py exposing `db`, import that.
from app.main import db

router = APIRouter(prefix="/search", tags=["search"])

class SearchRequest(BaseModel):
    query: str = Field(..., example="example.com")
    source: Optional[str] = Field("generic", example="whois")   # whois, shodan, google, etc.
    meta: Optional[dict] = None

class SearchResponse(BaseModel):
    id: str
    query: str
    source: str
    status: str
    created_at: datetime

# Helper to convert ObjectId to str
def oid_str(oid):
    return str(oid)

@router.post("/start", response_model=SearchResponse)
async def start_search(payload: SearchRequest = Body(...)):
    """
    Start a search: store the request in DB and return an id.
    Actual OSINT work runs in a separate worker (or called later).
    """
    doc = {
        "query": payload.query,
        "source": payload.source,
        "meta": payload.meta or {},
        "status": "queued",           # queued | running | done | failed
        "results": None,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    res = db.search_logs.insert_one(doc)
    if not res.inserted_id:
        raise HTTPException(status_code=500, detail="failed to create search record")
    return {
        "id": oid_str(res.inserted_id),
        "query": payload.query,
        "source": payload.source,
        "status": doc["status"],
        "created_at": doc["created_at"],
    }

@router.get("/status/{search_id}")
async def get_search_status(search_id: str):
    """
    Fetch the search document by id.
    """
    try:
        oid = ObjectId(search_id)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid search id")

    doc = db.search_logs.find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="search not found")

    # convert ObjectId to str for JSON
    doc["id"] = oid_str(doc["_id"])
    doc.pop("_id", None)
    return doc

@router.post("/run/{search_id}")
async def run_search_now(search_id: str):
    """
    Trigger running the search synchronously.
    This is a simple placeholder runner — replace with real integrations.
    """
    try:
        oid = ObjectId(search_id)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid search id")

    doc = db.search_logs.find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="search not found")

    # update status -> running
    db.search_logs.update_one({"_id": oid}, {"$set": {"status": "running", "updated_at": datetime.utcnow()}})

    # --- Placeholder: simple "fake" result generation ---
    # Replace these blocks with calls to whois, shodan, google scrapers, VirusTotal, etc.
    # Example integrations you will add later:
    # - whois (python-whois or using whois API)
    # - shodan (requires SHODAN_API_KEY and shodan library)
    # - virustotal (API key)
    # - passive DNS / crt.sh / googling with serps API
    try:
        result = {
            "summary": f"Placeholder results for query '{doc['query']}' (source={doc['source']})",
            "data": {
                "sample": True,
                "observed": datetime.utcnow().isoformat()
            }
        }
        db.search_logs.update_one(
            {"_id": oid},
            {"$set": {"status": "done", "results": result, "updated_at": datetime.utcnow()}}
        )
    except Exception as e:
        db.search_logs.update_one(
            {"_id": oid},
            {"$set": {"status": "failed", "error": str(e), "updated_at": datetime.utcnow()}}
        )
        raise HTTPException(status_code=500, detail=f"search failed: {e}")

    doc = db.search_logs.find_one({"_id": oid})
    doc["id"] = oid_str(doc["_id"])
    doc.pop("_id", None)
    return doc
