from rapidfuzz import fuzz

def correlate(docs):
    links=0
    for i in range(len(docs)):
        for j in range(i+1,len(docs)):
            if fuzz.token_sort_ratio(docs[i]["title"], docs[j]["title"])>50:
                links+=1
    return links
