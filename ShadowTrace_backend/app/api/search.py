# app/api/search.py
from fastapi import APIRouter, HTTPException, Body, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from bson import ObjectId
import whois
import os
import shodan
import traceback

# import db from app.main
from app.main import db

router = APIRouter(prefix="/search", tags=["search"])

class SearchRequest(BaseModel):
    query: str = Field(..., example="example.com")
    source: Optional[str] = Field("generic", example="whois")   # whois, shodan, generic
    meta: Optional[dict] = None

# helper
def oid_str(oid):
    return str(oid)

def run_whois(query: str):
    """Run WHOIS and return a serializable dict."""
    try:
        w = whois.whois(query)
        # whois.whois returns objects with attributes that may not be JSON serializable.
        result = {}
        for k, v in w.items():
            try:
                # convert sets/lists to lists and other objects to string
                if isinstance(v, (list, set, tuple)):
                    result[k] = list(v)
                else:
                    result[k] = str(v)
            except Exception:
                result[k] = repr(v)
        return {"ok": True, "whois": result}
    except Exception as e:
        return {"ok": False, "error": f"whois error: {str(e)}"}

def run_shodan(query: str):
    """Run a simple Shodan host lookup if key exists. Query can be IP or host."""
    key = os.getenv("SHODAN_API_KEY") or ""
    if not key:
        return {"ok": False, "error": "no_shodan_key"}
    try:
        sh = shodan.Shodan(key)
        # try host lookup first (works for IP)
        try:
            info = sh.host(query)
            # simplify result
            return {"ok": True, "shodan": {"ip_str": info.get("ip_str"), "ports": info.get("ports"), "data": info.get("data")[:5] if info.get("data") else []}}
        except shodan.exception.APIError:
            # fallback: search using query as term
            res = sh.search(query, limit=5)
            return {"ok": True, "shodan_search": {"total": res.get("total"), "matches": res.get("matches")[:5]}}
    except Exception as e:
        return {"ok": False, "error": f"shodan error: {str(e)}"}

def worker_run_search(doc_id):
    """
    Background worker that loads the search document, runs integrations,
    and writes results back to the DB.
    """
    try:
        oid = ObjectId(doc_id)
        doc = db.search_logs.find_one({"_id": oid})
        if not doc:
            return

        db.search_logs.update_one({"_id": oid}, {"$set": {"status": "running", "updated_at": datetime.utcnow()}})

        query = doc.get("query")
        source = doc.get("source", "generic")

        results = {"meta": {"query": query, "source": source, "started_at": datetime.utcnow().isoformat()}}

        # WHOIS (for domains)
        try:
            whois_res = run_whois(query)
            results["whois"] = whois_res
        except Exception as e:
            results["whois"] = {"ok": False, "error": str(e)}

        # SHODAN (try, only if api key exists)
        try:
            shodan_res = run_shodan(query)
            results["shodan"] = shodan_res
        except Exception as e:
            results["shodan"] = {"ok": False, "error": str(e)}

        # Add placeholder for other integrations later (VirusTotal, crt.sh, passive DNS)
        results["notes"] = "Add VirusTotal / passive DNS / crt.sh later."

        db.search_logs.update_one(
            {"_id": oid},
            {"$set": {"status": "done", "results": results, "updated_at": datetime.utcnow()}}
        )
    except Exception:
        # write error traceback into doc
        try:
            tb = traceback.format_exc()
            db.search_logs.update_one(
                {"_id": ObjectId(doc_id)},
                {"$set": {"status": "failed", "error": tb, "updated_at": datetime.utcnow()}}
            )
        except Exception:
            pass

@router.post("/start")
async def start_search(payload: SearchRequest = Body(...), background: BackgroundTasks = None):
    """
    Start a search: insert DB doc and queue BackgroundTasks to run integrations.
    """
    doc = {
        "query": payload.query,
        "source": payload.source,
        "meta": payload.meta or {},
        "status": "queued",
        "results": None,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    res = db.search_logs.insert_one(doc)
    if not res.inserted_id:
        raise HTTPException(status_code=500, detail="failed to create search record")

    doc_id = oid_str(res.inserted_id)
    # queue background worker
    if background is not None:
        background.add_task(worker_run_search, doc_id)
    else:
        # fallback: run inline (not recommended)
        worker_run_search(doc_id)

    return {"id": doc_id, "status": "queued", "query": payload.query, "created_at": doc["created_at"]}

@router.get("/status/{search_id}")
async def get_search_status(search_id: str):
    try:
        oid = ObjectId(search_id)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid search id")

    doc = db.search_logs.find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="search not found")

    doc["id"] = oid_str(doc["_id"])
    doc.pop("_id", None)
    # convert datetimes to isoformat
    for k in ("created_at", "updated_at"):
        if k in doc and hasattr(doc[k], "isoformat"):
            doc[k] = doc[k].isoformat()
    return doc

@router.post("/run/{search_id}")
async def run_search_now(search_id: str):
    """
    Run synchronously (blocking) — useful for debugging, not for production.
    """
    try:
        oid = ObjectId(search_id)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid search id")
    doc = db.search_logs.find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="search not found")

    # run worker directly
    worker_run_search(search_id)
    doc = db.search_logs.find_one({"_id": oid})
    doc["id"] = oid_str(doc["_id"])
    doc.pop("_id", None)
    for k in ("created_at", "updated_at"):
        if k in doc and hasattr(doc[k], "isoformat"):
            doc[k] = doc[k].isoformat()
    return doc
