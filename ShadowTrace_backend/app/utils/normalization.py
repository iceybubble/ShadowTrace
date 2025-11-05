import re

def normalize(val):
    v = val.strip()
    if "@" in v: return v.lower(), "email"
    if re.fullmatch(r"\+?\d[\d -]{6,}", v): return re.sub(r"\D","",v), "phone"
    return v.lower(), "username"
