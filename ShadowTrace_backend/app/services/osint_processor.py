# app/services/osint_processor.py
from datetime import datetime
from pymongo import MongoClient
import os
from typing import Dict, Any, List

MONGO_URI = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "shadowtrace")

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]

def extract_entities_from_sf(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Parse SpiderFoot JSON export and return a flat list of normalized entities.
    The exact JSON structure differs by version; this parser handles the common patterns:
    - events or data entries containing type, value, module, note, severity, etc.
    """
    entities = []

    # Common locations: 'events', 'data', 'results', 'items' - try all
    possible_containers = []
    for k in ("events", "data", "results", "items", "scan_data"):
        if k in raw:
            possible_containers.append(raw[k])

    # If top-level is an array, use it
    if not possible_containers and isinstance(raw, list):
        possible_containers = [raw]

    for container in possible_containers:
        if not isinstance(container, list):
            continue
        for item in container:
            # flexible extraction
            ent = {}
            # spiderfoot newer versions often have 'data' or 'value' & 'type'
            ent_type = item.get("type") or item.get("data_type") or item.get("name") or item.get("eventType")
            ent_value = item.get("value") or item.get("data") or item.get("text") or item.get("event")
            module = item.get("module") or item.get("source") or item.get("sourceModule")
            severity = item.get("severity") or item.get("risk") or item.get("confidence")
            timestamp = item.get("timestamp") or item.get("date") or item.get("time")

            if ent_value is None:
                # some items have nested data structures, skip if not simple
                continue

            ent["type"] = (ent_type or "").lower()
            ent["value"] = ent_value
            ent["module"] = module
            ent["severity"] = severity
            try:
                ent["timestamp"] = datetime.fromisoformat(timestamp) if isinstance(timestamp, str) else timestamp
            except Exception:
                ent["timestamp"] = None
            # raw item for traceability
            ent["raw"] = item
            entities.append(ent)

    # de-dupe by (type,value)
    seen = set()
    unique = []
    for e in entities:
        key = (e.get("type"), str(e.get("value")))
        if key in seen:
            continue
        seen.add(key)
        unique.append(e)
    return unique

def store_scan_in_mongo(case_id: str, scan_id: str, target: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize and insert into 'osint_cases' collection.
    Returns the inserted document (or a summary).
    """
    entities = extract_entities_from_sf(raw)
    doc = {
        "case_id": case_id,
        "scan_id": scan_id,
        "target": target,
        "source": "spiderfoot",
        "timestamp": datetime.utcnow(),
        "entity_count": len(entities),
        "entities": entities,
        "raw": raw
    }
    res = db.osint_cases.insert_one(doc)
    return {"inserted_id": str(res.inserted_id), "entity_count": len(entities)}
