def score(docs):
    s = 10 + len(docs)*10
    if any(d["platform"]=="breach" for d in docs): s+=25
    if any(d["platform"]=="darkweb" for d in docs): s+=30
    return min(100,s)
