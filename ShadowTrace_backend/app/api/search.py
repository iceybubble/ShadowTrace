from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from bson import ObjectId
import os, re, json, time, requests, traceback, whois, shodan, dns.resolver, concurrent.futures, difflib, io
from ipwhois import IPWhois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from PIL import Image
import imagehash
import numpy as np 

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
# HTTP GET helper for OSINT scraping
############################################
def http_get(url, timeout=6, retries=1):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            return r
        except Exception:
            if attempt == retries:
                return None
            time.sleep(0.5)
    return None

############################################
# Profile Parsing and Avatar Analysis
############################################
def parse_profile_html(html_text):
    soup = BeautifulSoup(html_text, "html.parser")
    result = {"display_name": None, "bio": None, "location": None, "avatar": None, "evidence": []}

    # JSON-LD
    for script in soup.select('script[type="application/ld+json"]'):
        try:
            data = json.loads(script.string or "{}")
            if isinstance(data, list):
                data = data[0]
            if data.get("name"):
                result["display_name"] = data["name"]
            if data.get("description"):
                result["bio"] = data["description"]
            if data.get("image"):
                result["avatar"] = data["image"]
        except Exception:
            continue

    # Meta
    og_title = soup.find("meta", property="og:title") or soup.find("meta", attrs={"name":"twitter:title"})
    if og_title and og_title.get("content"):
        result["display_name"] = result["display_name"] or og_title["content"]

    og_desc = soup.find("meta", property="og:description") or soup.find("meta", attrs={"name":"description"})
    if og_desc and og_desc.get("content"):
        result["bio"] = result["bio"] or og_desc["content"]

    og_img = soup.find("meta", property="og:image") or soup.find("meta", attrs={"name":"twitter:image"})
    if og_img and og_img.get("content"):
        result["avatar"] = result["avatar"] or og_img["content"]

    return result

def analyze_avatar(url: str):
    """
    Fetch avatar, return:
      - perceptual hash (phash)
      - simple brightness description
      - likely_face (bool) -> whether a human face was detected
      - face_count (int) -> how many faces were detected (0..n)
    This function never stores the image on disk; it only returns metadata.
    """
    try:
        r = requests.get(url, timeout=5, stream=True)
        r.raw.decode_content = True
        img = Image.open(io.BytesIO(r.content)).convert("RGB")

        # perceptual hash
        ph = str(imagehash.phash(img))

        # brightness heuristic
        avg = img.resize((1,1)).getpixel((0,0))
        desc = "bright image" if sum(avg)/3 > 180 else "dark image"

        # face detection (non-identifying)
        face_count = 0
        likely_face = False
        try:
            import cv2
            # convert PIL -> OpenCV image (BGR)
            np_img = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)
            # load a small Haar cascade shipped with opencv
            cascade = cv2.CascadeClassifier(cv2.data.haarcascades + "haarcascade_frontalface_default.xml")
            if cascade.empty():
                # can't load cascade for some reason
                face_count = 0
            else:
                gray = cv2.cvtColor(np_img, cv2.COLOR_BGR2GRAY)
                faces = cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=4, minSize=(24,24))
                face_count = int(len(faces))
                likely_face = face_count > 0
        except Exception:
            # OpenCV not available or detection failed -> fallback to False
            face_count = 0
            likely_face = False

        return {"hash": ph, "description": desc, "likely_face": likely_face, "face_count": face_count}
    except Exception:
        return None


def similarity_score(a: str, b: str) -> int:
    if not a or not b:
        return 0
    return int(difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio() * 100)

def extract_domains_from_text(text: str):
    if not text:
        return set()
    import re
    domains = set()
    for m in re.findall(r"https?://[^\s\"'>]+", text):
        try:
            d = urlparse(m).netloc
            if d:
                domains.add(d.lower().lstrip("www."))
        except:
            continue
    return domains

def compute_platform_match_score(username: str, platform_entry: dict, all_platforms: dict):
    score = 0
    evidence = platform_entry.get("evidence", [])[:]
    display = platform_entry.get("display_name") or ""
    bio = platform_entry.get("bio") or ""
    avatar = platform_entry.get("avatar")

    # fuzzy match
    sim = similarity_score(display, username)
    if sim >= 80:
        score += 40; evidence.append("display_name_similar")
    elif sim >= 50:
        score += 20; evidence.append("display_name_partial")

    # avatar
    if avatar:
        score += 20; evidence.append("avatar_present")

    # username in bio
    if username.lower() in (display.lower() + " " + bio.lower()):
        score += 15; evidence.append("username_in_bio")

    # domain overlap
    domains_here = extract_domains_from_text((bio or "") + " " + (platform_entry.get("url") or ""))
    for other in all_platforms.values():
        if other is platform_entry: continue
        other_text = (other.get("bio") or "") + " " + (other.get("url") or "")
        if domains_here & extract_domains_from_text(other_text):
            score += 25; evidence.append("shared_website")
            break
    return {"score": min(score, 95), "evidence": list(dict.fromkeys(evidence))}

############################################
# Social Probe — Enhanced
############################################
def social_probe(username):
    socials = {
        "github": f"https://github.com/{username}",
        "twitter": f"https://twitter.com/{username}",
        "reddit": f"https://www.reddit.com/user/{username}",
        "instagram": f"https://www.instagram.com/{username}"
    }

    platforms = {}
    avatar_summary = []

    for site, url in socials.items():
        entry = {"exists": False, "status": None, "url": url}
        try:
            r = http_get(url, timeout=6, retries=1)
            if r:
                entry["status"] = r.status_code
                entry["exists"] = (r.status_code == 200)
                if r.status_code == 200:
                    parsed = parse_profile_html(r.text)
                    entry.update(parsed)
                    if entry.get("avatar"):
                        avinfo = analyze_avatar(entry["avatar"])
                        if avinfo:
                            entry.update(avinfo)
                            avatar_summary.append({"platform": site, **avinfo})
        except Exception as e:
            entry["error"] = str(e)
        platforms[site] = entry

    # compute match scores
    for name, entry in platforms.items():
        ms = compute_platform_match_score(username, entry, platforms)
        entry["match_score"] = ms["score"]
        entry["match_evidence"] = ms["evidence"]

    scores = [v["match_score"] for v in platforms.values() if v.get("exists")]
    confidence = int(sum(scores)/len(scores)) if scores else 0

    return {
        "links_found": [k for k,v in platforms.items() if v.get("exists")],
        "avatar_summary": avatar_summary,
        "confidence": confidence,
        "platforms": platforms
    }

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
        safe_doc = {
            "query": scan_record.get("query"),
            "source": scan_record.get("source"),
            "status": scan_record.get("status"),
            "created_at": scan_record.get("created_at").isoformat() if scan_record.get("created_at") else None,
            "updated_at": datetime.utcnow().isoformat(),
            "results": json.loads(json.dumps(scan_record.get("results"), default=str)),
            "raw": json.loads(json.dumps(scan_record, default=str))
        }
        index_doc(SCAN_INDEX, safe_doc, doc_id=scan_id)
        print(f"[+] Indexed scan {scan_id} into Elasticsearch.")
    except Exception as e:
        print(f"[!] Failed to index scan {scan_id}: {e}")

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
            res["threat_score"] = {"risk_level": "low"}

        elif etype == "phone":
            res["note"] = "Phone OSINT requires external paid data source."

        elif etype == "username":
            profile = social_probe(q)
            res["social_profile"] = profile
            res["social"] = profile.get("platforms", {})
            res["threat_score"] = {"risk_level": "low", "confidence": profile.get("confidence", 0)}

        else:
            res["note"] = "Unknown input. Try domain/ip/email/username/phone."

        db.search_logs.update_one({"_id": oid}, {"$set": {"status": "done", "results": res, "updated_at": datetime.utcnow()}})
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
