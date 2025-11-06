# app/database/es_mapping.py
SCAN_INDEX = "shadowtrace-osint-scans-v2"


# Example mapping - adjust fields as you store them in MongoDB
MAPPING = {
    "properties": {
        "query": {"type": "text"},
        "type": {"type": "keyword"},
        "source": {"type": "keyword"},
        "summary": {"type": "text"},
        "findings": {
            "type": "nested",
            "properties": {
                "ioc": {"type": "keyword"},
                "confidence": {"type": "float"},
                "category": {"type": "keyword"},
                "details": {"type": "text"}
            }
        },
        "timestamp": {"type": "date"},
        "raw": {"type": "object", "enabled": False}  # store raw if you want but not indexed
    }
}
