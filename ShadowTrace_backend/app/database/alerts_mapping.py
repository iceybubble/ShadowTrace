# app/database/alerts_mapping.py

ALERT_INDEX = "shadowtrace_alerts"

ALERT_MAPPING = {
    "properties": {
        "title": {"type": "text"},
        "severity": {"type": "keyword"},
        "description": {"type": "text"},
        "timestamp": {"type": "date"},
        "raw": {"type": "object", "enabled": False}
    }
}
