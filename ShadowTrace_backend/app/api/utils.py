from fastapi import APIRouter
import os, requests

router = APIRouter(prefix="/utils", tags=["utils"])

def safe_check(url, headers=None):
    try:
        r = requests.get(url, headers=headers, timeout=5)
        return r.status_code < 500
    except:
        return False

@router.get("/test-keys")
def test_keys():
    results = {}

    # Mongo
    from app.main import db
    try:
        db.command("ping")
        results["mongo"] = "ok"
    except:
        results["mongo"] = "fail"

    # Shodan
    shodan_key = os.getenv("SHODAN_API_KEY", "")
    if shodan_key:
        res = safe_check(f"https://api.shodan.io/api-info?key={shodan_key}")
        results["shodan"] = "ok" if res else "fail"
    else:
        results["shodan"] = "missing"

    # VirusTotal
    vt_key = os.getenv("VT_API_KEY", "")
    if vt_key:
        headers = {"x-apikey": vt_key}
        res = safe_check("https://www.virustotal.com/api/v3/domains/google.com", headers)
        results["virustotal"] = "ok" if res else "fail"
    else:
        results["virustotal"] = "missing"

    # AbuseIPDB
    abuse_key = os.getenv("ABUSEIPDB_KEY", "")
    if abuse_key:
        headers = {"Key": abuse_key, "Accept": "application/json"}
        res = safe_check("https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8", headers)
        results["abuseipdb"] = "ok" if res else "fail"
    else:
        results["abuseipdb"] = "missing"

    return results
