# app/services/spiderfoot_client.py
import requests
from typing import Optional

SPIDERFOOT_BASE = "http://127.0.0.1:5001"
TIMEOUT = 30

class SpiderFootClient:
    @staticmethod
    def start_scan(scan_name: str, target: str, use_case: str = "all") -> dict:
        url = f"{SPIDERFOOT_BASE}/startscan"
        payload = {"scanname": scan_name, "scantarget": target, "usecase": use_case}
        r = requests.post(url, data=payload, timeout=TIMEOUT)
        return {"status_code": r.status_code, "text": r.text}

    @staticmethod
    def stop_scan(scan_id: str) -> dict:
        # SpiderFoot has multiple variants; try the common stop endpoints
        candidates = [
            f"{SPIDERFOOT_BASE}/scan/stop?scanid={scan_id}",
            f"{SPIDERFOOT_BASE}/scan/stop/{scan_id}",
        ]
        for url in candidates:
            try:
                r = requests.get(url, timeout=TIMEOUT)
                if r.status_code == 200:
                    return {"ok": True, "text": r.text}
            except Exception:
                pass
        return {"ok": False, "error": "stop endpoints failed"}

    @staticmethod
    def get_scan_raw(scan_id: str) -> Optional[dict]:
        """
        Attempt to fetch a JSON export of scan results.
        Tries several common SpiderFoot endpoints / query parameters.
        Returns parsed JSON if successful, else None.
        """
        candidates = [
            f"{SPIDERFOOT_BASE}/scan/results/{scan_id}",
            f"{SPIDERFOOT_BASE}/scan/results/{scan_id}?format=json",
            f"{SPIDERFOOT_BASE}/scan/{scan_id}?format=json",
            f"{SPIDERFOOT_BASE}/scan/{scan_id}/export?format=json",
            f"{SPIDERFOOT_BASE}/export/{scan_id}?format=json",
            f"{SPIDERFOOT_BASE}/scan/{scan_id}/results",
        ]

        for url in candidates:
            try:
                r = requests.get(url, timeout=TIMEOUT)
            except Exception:
                continue
            # Try to decode JSON
            try:
                data = r.json()
                return data
            except ValueError:
                # If endpoint returns HTML or text but contains JSON, try simple extraction
                text = r.text.strip()
                if text.startswith("{") or text.startswith("["):
                    try:
                        import json
                        return json.loads(text)
                    except Exception:
                        pass
                # otherwise continue trying other endpoints
                continue
        return None
