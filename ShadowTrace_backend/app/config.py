import os
import json
from datetime import datetime
from elasticsearch import Elasticsearch
from app.config import (
    ELASTIC_URL, ELASTIC_USERNAME, ELASTIC_PASSWORD, ELASTIC_VERIFY_SSL
)

#  Initialize Elasticsearch client using config variables
def get_elasticsearch_client():
    if not ELASTIC_URL:
        print("[!] Elasticsearch not configured. Skipping indexing.")
        return None

    try:
        es = Elasticsearch(
            [ELASTIC_URL],
            basic_auth=(ELASTIC_USERNAME, ELASTIC_PASSWORD) if ELASTIC_USERNAME else None,
            verify_certs=ELASTIC_VERIFY_SSL,
        )
        if es.ping():
            print("[+] Connected to Elasticsearch successfully.")
        else:
            print("[!] Elasticsearch connection failed.")
        return es
    except Exception as e:
        print(f"[!] Error initializing Elasticsearch client: {e}")
        return None


#  Your enhanced OSINT scan runner
def run_scan(query: str, scan_type: str):
    """
    Runs an OSINT scan, stores results locally,
    and indexes them automatically into Elasticsearch.
    """

    # 1️ Simulate or replace this with your real OSINT scan logic
    scan_result = {
        "query": query,
        "scan_type": scan_type,
        "timestamp": datetime.utcnow().isoformat(),
        "status": "completed",
        "data": {
            "sources": ["example-source1", "example-source2"],
            "findings": [
                {"title": "Open directory listing", "severity": "medium"},
                {"title": "Possible exposed API key", "severity": "high"}
            ]
        }
    }

    # 2️ Save result locally
    os.makedirs("scans", exist_ok=True)
    filename = f"scans/{query}_{scan_type}.json"
    with open(filename, "w") as f:
        json.dump(scan_result, f, indent=2)
    print(f"[+] Saved scan result locally at: {filename}")

    # 3️ Index to Elasticsearch (if configured)
    es = get_elasticsearch_client()
    if es:
        try:
            index_name = "osint-scans"
            es.index(index=index_name, document=scan_result)
            print(f"[+] Indexed scan result for {query} into '{index_name}'.")
        except Exception as e:
            print(f"[!] Failed to index scan into Elasticsearch: {e}")

    # 4️  Return for API or frontend
    return {
        "query": query,
        "scan_type": scan_type,
        "indexed": bool(es),
        "timestamp": scan_result["timestamp"]
    }
