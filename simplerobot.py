'''Very simple parser for robots.txt that assumes near perfect formatting and returns a list of directories that are disallowed for user agent *
 This parser does not support the wildcard operator

'''


import urllib2
import urlparse
import httplib

def get_robots(domain):
    try:
        data = urllib2.urlopen(urlparse.urljoin(domain, "robots.txt"), timeout=10)
        text = data.read()
    except IOError, e:
        text = ''
    except urllib2.HTTPError, e:
        text = ''
    except httplib.BadStatusLine, e:
        text = ''
    except Exception, e:
        text = ''

    lst = text.split('\n')
    x = -1
    for i in range(len(lst)):
        if lst[i].strip() == "User-Agent: *":
            x = i
            break
    if x == -1:
        return []
    nogo = []
    for i in range(x + 1, len(lst)):
        j = lst[i].split()
        if len(j) > 1 and j[0] == "Disallow:":
            nogo.append(j[1])
    return nogo




    
