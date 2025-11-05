import httpx
from bs4 import BeautifulSoup

async def github(username):
    url = f"https://github.com/{username}"
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(url)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text,"html.parser")
            return [{
                "platform": "github",
                "url": url,
                "title": soup.title.string if soup.title else ""
            }]
    return []
