from fastapi import APIRouter, HTTPException, Body, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from bson import ObjectId
import os, re, requests, socket, traceback, whois, shodan, dns.resolver
from ipwhois import IPWhois

from app.main import db

router = APIRouter(prefix="/search", tags=["search"])

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

def detect_entity(q):
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
        ans = dns.resolver.resolve(name, rec, lifetime=5)
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
        r = requests.head(f"http://{target}", timeout=5, allow_redirects=True)
        return {"status": r.status_code, "headers": dict(r.headers)}
    except Exception as e:
        return {"error": str(e)}

def email_gravatar(email):
    import hashlib
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{h}?d=404"
    try:
        r = requests.head(url, timeout=5)
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
            r = s.search(q, limit=5)
            return {"ok": True, "matches": r.get("matches")}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def social_probe(username):
    socials = {
        "github": f"https://github.com/{username}",
        "twitter": f"https://twitter.com/{username}",
        "reddit": f"https://www.reddit.com/user/{username}",
        "instagram": f"https://www.instagram.com/{username}"
    }
    out = {}
    for site,url in socials.items():
        try:
            r = requests.head(url, timeout=5, allow_redirects=True)
            out[site] = {"exists": r.status_code == 200, "status": r.status_code, "url": url}
        except Exception as e:
            out[site] = {"error": str(e)}
    return out


############################################
# VirusTotal & AbuseIPDB
############################################

VT_KEY = os.getenv("VT_API_KEY","")
ABUSE_KEY = os.getenv("ABUSEIPDB_KEY","")

def vt_ip_lookup(ip):
    if not VT_KEY:
        return {"ok": False, "error": "VT key missing"}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                         headers={"x-apikey": VT_KEY}, timeout=8)
        return {"ok": r.ok, "data": r.json() if r.ok else r.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def vt_domain_lookup(domain):
    if not VT_KEY:
        return {"ok": False, "error": "VT key missing"}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}",
                         headers={"x-apikey": VT_KEY}, timeout=8)
        return {"ok": r.ok, "data": r.json() if r.ok else r.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def abuseipdb_check(ip):
    if not ABUSE_KEY:
        return {"ok": False, "error": "AbuseIPDB key missing"}
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check",
                         params={"ipAddress": ip, "maxAgeInDays": 90},
                         headers={"Key": ABUSE_KEY, "Accept": "application/json"}, timeout=8)
        return {"ok": r.ok, "data": r.json().get("data") if r.ok else r.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}


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
            res["ip_rir"] = ip_rir(q)
            res["shodan"] = shodan_search(q)
            res["http"] = http_head(q)

            res["vt"] = vt_ip_lookup(q)
            res["abuseipdb"] = abuseipdb_check(q)

            try:
                vt_score = res["vt"]["data"]["data"]["attributes"]["last_analysis_stats"]["malicious"]
            except:
                vt_score = 0

            try:
                abuse_score = res["abuseipdb"]["data"]["abuseConfidenceScore"]
            except:
                abuse_score = 0

            level = "low"
            if vt_score >= 3 or abuse_score >= 30:
                level = "medium"
            if vt_score >= 10 or abuse_score >= 75:
                level = "high"

            res["threat_score"] = {
                "vt_malicious": vt_score,
                "abuse_confidence": abuse_score,
                "risk_level": level
            }

        elif etype == "private_ip":
            res["note"] = "Private IP; requires internal network scan"

        elif etype == "domain":
            res["whois"] = whois_domain(q)
            res["A"] = safe_dns(q, "A")
            res["MX"] = safe_dns(q, "MX")
            res["http"] = http_head(q)
            res["shodan"] = shodan_search(q)
            try:
                res["crtsh"] = requests.get(
                    f"https://crt.sh/?q=%25.{q}&output=json", timeout=7
                ).json()[:5]
            except:
                res["crtsh"] = "N/A"

            res["vt"] = vt_domain_lookup(q)

        elif etype == "email":
            domain = q.split("@")[-1]
            res["MX"] = safe_dns(domain,"MX")
            res["gravatar"] = email_gravatar(q)

        elif etype == "phone":
            res["note"] = "Phone OSINT requires external paid data source"

        elif etype == "username":
            res["social"] = social_probe(q)

        else:
            res["note"] = "Unknown input. Try domain/ip/email/username/phone."

        db.search_logs.update_one(
            {"_id": oid},
            {"$set": {"status": "done", "results": res, "updated_at": datetime.utcnow()}}
        )

    except Exception:
        tb = traceback.format_exc()
        db.search_logs.update_one({"_id": ObjectId(id)}, {"$set":{"status":"failed","error":tb}})


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
