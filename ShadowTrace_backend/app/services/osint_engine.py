import time
from app.utils.normalization import normalize
from app.scrapers.github import github
from app.scrapers.reddit import reddit
from app.scrapers.breach_check import breach
from app.scrapers.darkweb_feeds import darkweb
from app.state import SCAN_CACHE   # ✅ FIXED circular import
from app.services.scoring import score
from app.services.correlation import correlate

async def run_scan(qid, value):
    ind, typ = normalize(value)
    results = []

    # Collect OSINT data
    if typ in ["email", "username"]:
        u = ind.split("@")[0] if typ == "email" else ind
        results += await github(u)
        results += await reddit(u)

    if typ == "email":
        results += await breach(ind)

    # Dark web feed match
    results += await darkweb(ind)

    # Scoring
    conf = score(results)
    links = correlate(results)

    # Store result in global memory
    SCAN_CACHE[qid] = {
        "indicator": ind,
        "type": typ,
        "confidence": conf,
        "links": links,
        "sources": results,
        "status": "completed"
    }
