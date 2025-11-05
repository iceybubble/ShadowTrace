async def breach(email):
    if email.endswith("@protonmail.com"):
        return [{
            "platform":"breach",
            "title":"Found in breach database (demo)",
            "url":"https://haveibeenpwned.com"
        }]
    return []
