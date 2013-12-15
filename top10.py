from google import search

def top10(query):
    l = []
    for i in search(query, stop=10):
        l.append(str(i))
    return l
