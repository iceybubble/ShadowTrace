import httpx
from app.config import settings

async def darkweb(indicator):
    hits=[]
    async with httpx.AsyncClient(timeout=10) as c:
        for feed in settings.DARK_FEEDS:
            r = await c.get(feed)
            if r.status_code == 200 and indicator.lower() in r.text.lower():
                hits.append({"platform":"darkweb","url":feed,"title":"Seen in dark-web dump feed"})
    return hits
