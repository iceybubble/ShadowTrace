import requests
import urllib.parse
from app.config import HIBP_API_KEY

def check_hibp_breaches(email: str):
    """
    Query Have I Been Pwned for breach data.
    Uses test key for development (no paid key required).
    """
    encoded = urllib.parse.quote(email)
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}?truncateResponse=false"
    
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "ShadowTrace OSINT Engine"
    }
    
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return {"found": True, "data": response.json()}
    elif response.status_code == 404:
        return {"found": False, "message": "No breaches found"}
    else:
        return {"found": False, "status": response.status_code, "error": response.text}
