from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from bson import ObjectId
import os, re, requests, traceback, whois, shodan, dns.resolver, concurrent.futures
from ipwhois import IPWhois

from app.main import db
from app.database.elastic import index_doc
from app.database.es_mapping import SCAN_INDEX

router = APIRouter(prefix="/search", tags=["search"])

############################################
# Models
############################################
class SearchRequest(BaseModel):
    query: str = Field(..., example="example.com or john_doe or +918*********")
    source: Optional[str] = Field("auto", example="auto")
    meta: Optional[dict] = None

############################################
# Entity Detection
############################################
IPV4 = re.compile(r"^\s*(?:\d{1,3}\.){3}\d{1,3}\s*$")
DOMAIN = re.compile(r"^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")
EMAIL = re.compile(r"^[^@]+@[^@]+\.[^@]+$")
PHONE = re.compile(r"^\+?\d[\d\s\-()]{5,}$")
USERNAME = re.compile(r"^[a-zA-Z0-9_.-]{3,}$")

def detect_entity(q: str) -> str:
    q = q.strip()
    if IPV4.match(q):
        parts = list(map(int, q.split(".")))
        if (parts[0]==10) or (parts[0]==172 and 16<=parts[1]<=31) or (parts[0]==192 and parts[1]==168):
            return "private_ip"
        return "ip"
    if EMAIL.match(q): return "email"
    if DOMAIN.match(q): return "domain"
    if PHONE.match(q): return "phone"
    if USERNAME.match(q): return "username"
    return "unknown"

############################################
# Helper Functions
############################################
def safe_dns(name, rec="A"):
    try:
        ans = dns.resolver.resolve(name, rec, lifetime=4)
        return [i.to_text() for i in ans]
    except Exception as e:
        return {"error": str(e)}

def whois_domain(domain):
    try:
        w = whois.whois(domain)
        return {"ok": True, "data": {k:(list(v) if isinstance(v,(list,set,tuple)) else str(v)) for k,v in w.items()}}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def ip_rir(ip):
    try:
        return {"ok": True, "rir": IPWhois(ip).lookup_rdap(depth=1)}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def http_head(target):
    try:
        r = requests.head(f"http://{target}", timeout=3, allow_redirects=True)
        return {"status": r.status_code, "headers": dict(r.headers)}
    except Exception as e:
        return {"error": str(e)}

def email_gravatar(email):
    import hashlib
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{h}?d=404"
    try:
        r = requests.head(url, timeout=3)
        return {"exists": r.status_code == 200, "url": url}
    except Exception as e:
        return {"error": str(e)}

def shodan_search(q):
    key = os.getenv("SHODAN_API_KEY","")
    if not key:
        return {"ok": False, "error": "Shodan key missing"}
    try:
        s = shodan.Shodan(key)
        try:
            info = s.host(q)
            return {"ok": True, "host": info}
        except:
            r = s.search(q, limit=3)
            return {"ok": True, "matches": r.get("matches")}
    except Exception as e:
        return {"ok": False, "error": str(e)}

############################################
# Fast concurrent username reconnaissance
############################################
def social_probe(username):
    socials = {
        "github": f"https://github.com/{username}",
        "twitter": f"https://twitter.com/{username}",
        "reddit": f"https://www.reddit.com/user/{username}",
        "instagram": f"https://www.instagram.com/{username}"
    }

    def check(site, url):
        try:
            r = requests.head(url, timeout=2, allow_redirects=True)
            return site, {"exists": (r.status_code == 200), "status": r.status_code, "url": url}
        except Exception as e:
            return site, {"error": str(e)}

    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(check, s, u) for s, u in socials.items()]
        for future in concurrent.futures.as_completed(futures):
            site, result = future.result()
            out[site] = result
    return out

############################################
# External Threat Intel APIs
############################################
VT_KEY = os.getenv("VT_API_KEY","")
ABUSE_KEY = os.getenv("ABUSEIPDB_KEY","")
HIBP_KEY = os.getenv("HIBP_API_KEY","00000000000000000000000000000000")

def vt_ip_lookup(ip):
    if not VT_KEY:
        return {"ok": False, "error": "VT key missing"}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                         headers={"x-apikey": VT_KEY}, timeout=6)
        return {"ok": r.ok, "data": r.json() if r.ok else r.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def vt_domain_lookup(domain):
    if not VT_KEY:
        return {"ok": False, "error": "VT key missing"}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                         headers={"x-apikey": VT_KEY}, timeout=6)
        return {"ok": r.ok, "data": r.json() if r.ok else r.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def abuseipdb_check(ip):
    if not ABUSE_KEY:
        return {"ok": False, "error": "AbuseIPDB key missing"}
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         params={"ipAddress": ip, "maxAgeInDays": 90},
                         headers={"Key": ABUSE_KEY, "Accept": "application/json"}, timeout=6)
        return {"ok": r.ok, "data": r.json().get("data") if r.ok else r.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def hibp_check(email):
    try:
        encoded = requests.utils.quote(email)
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}?truncateResponse=false"
        headers = {"hibp-api-key": HIBP_KEY, "User-Agent": "ShadowTrace OSINT Engine"}
        r = requests.get(url, headers=headers, timeout=6)
        if r.status_code == 200:
            return {"ok": True, "data": r.json()}
        elif r.status_code == 404:
            return {"ok": False, "message": "No breaches found"}
        else:
            return {"ok": False, "status": r.status_code, "error": r.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}

############################################
# Elasticsearch Integration
############################################
def index_scan_to_elastic(scan_id: str, scan_record: dict):
    try:
        doc = {
            "query": scan_record.get("query"),
            "source": scan_record.get("source"),
            "status": scan_record.get("status"),
            "results": scan_record.get("results"),
            "created_at": scan_record.get("created_at").isoformat() if scan_record.get("created_at") else None,
            "updated_at": datetime.utcnow().isoformat(),
            "raw": scan_record
        }
        index_doc(SCAN_INDEX, doc, doc_id=scan_id)
        print(f"Indexed scan {scan_id} into Elasticsearch.")
    except Exception as e:
        print(f"Failed to index scan {scan_id} in Elasticsearch: {e}")

############################################
# Background Scan Worker
############################################
def run_scan(id):
    try:
        oid = ObjectId(id)
        doc = db.search_logs.find_one({"_id": oid})
        if not doc:
            return

        q = doc["query"].strip()
        etype = detect_entity(q)
        db.search_logs.update_one({"_id": oid}, {"$set": {"status": "running"}})

        res = {"meta": {"query": q, "entity": etype, "time": str(datetime.utcnow())}}

        if etype == "ip":
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = {
                    "ip_rir": executor.submit(ip_rir, q),
                    "shodan": executor.submit(shodan_search, q),
                    "http": executor.submit(http_head, q),
                    "vt": executor.submit(vt_ip_lookup, q),
                    "abuseipdb": executor.submit(abuseipdb_check, q),
                }
                for k, f in futures.items():
                    res[k] = f.result()

            vt_score = res.get("vt", {}).get("data", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
            abuse_score = res.get("abuseipdb", {}).get("data", {}).get("abuseConfidenceScore", 0)

            level = "low"
            if vt_score >= 3 or abuse_score >= 30: level = "medium"
            if vt_score >= 10 or abuse_score >= 75: level = "high"

            res["threat_score"] = {"vt_malicious": vt_score, "abuse_confidence": abuse_score, "risk_level": level}

        elif etype == "private_ip":
            res["note"] = "Private IP; internal scan required."

        elif etype == "domain":
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = {
                    "whois": executor.submit(whois_domain, q),
                    "A": executor.submit(safe_dns, q, "A"),
                    "MX": executor.submit(safe_dns, q, "MX"),
                    "http": executor.submit(http_head, q),
                    "shodan": executor.submit(shodan_search, q),
                    "vt": executor.submit(vt_domain_lookup, q),
                }
                for k, f in futures.items():
                    res[k] = f.result()
            try:
                res["crtsh"] = requests.get(f"https://crt.sh/?q=%25.{q}&output=json", timeout=5).json()[:5]
            except:
                res["crtsh"] = "N/A"

        elif etype == "email":
            domain = q.split("@")[-1]
            res["MX"] = safe_dns(domain, "MX")
            res["gravatar"] = email_gravatar(q)
            res["hibp"] = hibp_check(q)

        elif etype == "phone":
            res["note"] = "Phone OSINT requires external paid data source."

        elif etype == "username":
            res["social"] = social_probe(q)

        else:
            res["note"] = "Unknown input. Try domain/ip/email/username/phone."

        db.search_logs.update_one(
            {"_id": oid},
            {"$set": {"status": "done", "results": res, "updated_at": datetime.utcnow()}}
        )

        # Fetch updated record and index it to Elasticsearch
        updated_doc = db.search_logs.find_one({"_id": oid})
        index_scan_to_elastic(str(oid), updated_doc)

    except Exception:
        tb = traceback.format_exc()
        db.search_logs.update_one({"_id": ObjectId(id)}, {"$set": {"status": "failed", "error": tb}})

############################################
# API Endpoints
############################################
@router.post("/start")
async def start_scan(req: SearchRequest, bg: BackgroundTasks):
    doc = {
        "query": req.query,
        "source": req.source,
        "meta": req.meta,
        "status": "queued",
        "results": None,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    id = str(db.search_logs.insert_one(doc).inserted_id)
    bg.add_task(run_scan, id)
    return {"id": id, "status": "queued", "query": req.query}

@router.get("/status/{id}")
async def status(id):
    try:
        oid = ObjectId(id)
    except:
        raise HTTPException(status_code=400, detail="invalid id")

    d = db.search_logs.find_one({"_id": oid})
    if not d:
        raise HTTPException(status_code=404, detail="not found")

    d["id"] = id
    d.pop("_id")
    return d

@router.post("/run/{id}")
async def run_now(id: str):
    run_scan(id)
    return await status(id)
