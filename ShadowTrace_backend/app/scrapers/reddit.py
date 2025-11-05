import httpx

async def reddit(username):
    url = f"https://www.reddit.com/user/{username}/about.json"
    headers={"User-Agent":"ShadowTrace"}
    async with httpx.AsyncClient(timeout=10, headers=headers) as c:
        r = await c.get(url)
        if r.status_code==200 and r.json().get("data"):
            return [{
                "platform":"reddit",
                "url":url,
                "title":"Reddit profile detected"
            }]
    return []
