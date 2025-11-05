import time
from app.utils.normalization import normalize
from app.scribers.github import github
from app.scribers.reddit import reddit
from app.scribers.breach_check import breach
from app.scribers.darkweb_feeds import darkweb
from app.api.search import SCAN_CACHE
from app.services.scoring import score
from app.services.correlation import correlate

async def run_scan(qid, value):
    ind, typ = normalize(value)
    results=[]

    if typ in ["email","username"]:
        u = ind.split("@")[0] if typ=="email" else ind
        results+= await github(u)
        results+= await reddit(u)

    if typ=="email":
        results+= await breach(ind)

    results+= await darkweb(ind)

    conf = score(results)
    links = correlate(results)

    SCAN_CACHE[qid] = {
        "indicator": ind,
        "type": typ,
        "confidence": conf,
        "links": links,
        "sources": results
    }
