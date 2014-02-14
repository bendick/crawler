import urllib
import htmllib
import formatter
import Queue
import urlparse
import threading
from time import clock, ctime
import top10
import sets
import urllib2
import simplerobot
from optparse import OptionParser
import ssl
import httplib
import socket
import ssl_match_hostname

opts = OptionParser()

opts.add_option("-p", dest="PAGES_TO_CRAWL", type="int", help="Number of pages to crawl before crawler exits.", default=200)
opts.add_option("-c", dest="COURTESY_PERIOD", type="float", help="Number of seconds between subsequent requests from one domain.", default=1.0)
opts.add_option("-d", dest="TIMEOUT", type="float", help="Timeout delay (in seconds) for http requests.", default=10)
opts.add_option("-t", dest="THREAD_LIMIT", type="int", help="Number of that will make concurrent http requests.", default=20)
opts.add_option("-l", dest="CRAWLS_PER_DOMAIN", type="int", help="Number of pages from a single domain that can be requested.", default=100)

(options, args) = opts.parse_args()

if len(args) < 1:
    print "No search query supplied."
    exit()

EXCLUDED_EXTENSIONS = ('7z', 'aac', 'ac3', 'aiff', 'ape', 'asf', 'asx', 'asx', 'avi', 'bin', 'css', 'doc', 'dtd', 'exe', 'f4v', 'flv', 'gif', 'gz', 'ico', 'jar', 'jpg', 'js', 'm1v', 'm3u', 'mka', 'mkv', 'mov', 'mp2', 'mp3', 'mp4', 'mpeg', 'mpg', 'ogg', 'pdf', 'png', 'pps', 'ppt', 'rar', 'raw', 'rss', 'swf', 'tar', 'wav', 'wma', 'wmv', 'xls', 'xml', 'xsd', 'zip')

FLAG_HTTP = 0
FLAG_TRUSTED_HTTPS = 1
FLAG_SELFSIGNED_HTTPS = 2
FLAG_MISMATCHED_HTTPS = 3

class Parser(htmllib.HTMLParser):

    def __init__(self, formatter):
        htmllib.HTMLParser.__init__(self, formatter)
        self.links = []
        self.mime = []

    def start_a(self, attrs) :
        if len(attrs) > 0 :
            for attr in attrs:
                if attr[0] == "href" :
                    if len(attr[1]) > 0: #Added this for empty hrefs, should probably choose a more consistent, centralized place for string exclusion
                        self.links.append(attr[1])

    def get_links(self) :
        return self.links

    def clear_links(self) :
        del self.links[:]

    def do_meta(self, attrs):
        for i in attrs:
            self.mime.append(i)

    def get_mime(self):
        return self.mime

    def clear_mime(self):
        del self.mime[:]

    def clear_data(self):
        del self.links[:]
        del self.mime[:]

def check_mime(mime_list):
    for i in mime_list:
        for j in i:
            if j.find("text/html") != -1:
                return True
    return False



class Logger():
    def __init__(self, crawledLock, crawled, pageLock, pages, cList):
        self.crawledLock = crawledLock
        self.crawled = crawled
        self.pageLock = pageLock
        self.pages = pages
        self.cList = cList
        self.sz = 0
        self.er = 0
    def logCrawl(s):
        self.crawledLock.acquire()
        self.crawled.write(s)
        self.crawledLock.release()
    def logPage(s):
        self.pageLock.acquire()
        self.pages.write(s) 
        self.pageLock.release()
        

class ValidHTTPSConnection(httplib.HTTPConnection): #This class implements ssl certificate validation for urllib2 ssl requests
    default_port = httplib.HTTPS_PORT

    def __init__(self, *args, **kwargs):
        httplib.HTTPConnection.__init__(self, *args, **kwargs)

    def connect(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock = ssl.wrap_socket(s, ca_certs="ca-certificates.crt", cert_reqs=ssl.CERT_REQUIRED)
        self.sock.connect((self.host, self.port))
        cert = self.sock.getpeercert()
        ssl_match_hostname.match_hostname(cert, self.host)  #Even after forcing certificate validation the ssl library still does not check if the certificate's hostname matches, matching function pulled from python 3.4 ssl module


class ValidHTTPSHandler(urllib2.HTTPSHandler):
    def https_open(self, req):
            return self.do_open(ValidHTTPSConnection, req)


class CrawlThread(threading.Thread):
    def __init__(self, q, history, dLock, IOLock, log, recent, recLock):
        threading.Thread.__init__(self)
        self.q = q
        self.history = history
        self.dLock = dLock
        self.IOLock = IOLock
        self.log = log
        self._stop = threading.Event()
        self.recent = recent
        self.recLock = recLock

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.isSet()
    

    def run(self):

        format = formatter.NullFormatter()
        htmlparser = Parser(format)

        while True:
            #check to see if the thread's services are no longer required
            if self.stopped():
                return
            #Get the next site to be crawled from the queue
            #Queue class will block until input arrives if get is called on an empty queue with True supplied
            addr = self.q.get(True)
            
            #Check to see if we have crawled the domain in the past options.COURTESY_PERIOD seconds 
            if options.COURTESY_PERIOD > 0:
                urlComponents = urlparse.urlsplit(addr)
                urlDomain = urlComponents[1]
                #Find the next entry that hasn't been requested in options.COURTESY_PERIOD
                while urlDomain in self.recent:
                    self.q.put(addr)
                    addr = self.q.get()
                    urlComponents = urlparse.urlsplit(addr)
                    urlDomain = urlComponents[1]
                self.recent.add(urlDomain)
                #Spawn thread to remove domain from recently crawled list after appropriate time
                until = threading.Timer(options.COURTESY_PERIOD, courtesy, [self.recent, self.recLock, urlDomain]) 
                until.start()

            self.IOLock.acquire()
            print self.history[addr][1], addr
            self.IOLock.release()

            #Fetch html site

            if (len(addr) > 7 and addr[:8] == "https://"): #Check if this is an https url
                try:
                    connType = FLAG_TRUSTED_HTTPS
                    opener = urllib2.build_opener(ValidHTTPSHandler) #Open an SSL connection
                    data = opener.open(addr, timeout=options.TIMEOUT)
                    site = data.read()

                except urllib2.URLError: #Certificate was self-signed or otherwise failed to chain to a CA properly
                    connType = FLAG_SELFSIGNED_HTTPS #Mark as self signed site
                    data = urllib2.urlopen(addr, timeout=options.TIMEOUT) #Proceed with crawl
                    site = data.read()
                    
                except ssl_match_hostname.CertificateError: #cert is validated but hostname does not match
                    connType = FLAG_MISMATCHED_HTTPS #Mark as a possible MITM
                    data = urllib2.urlopen(addr, timeout=options.TIMEOUT) #Proceed with crawl
                    site = data.read()
                    
                    
            else:
                try:
                    connType = FLAG_HTTP
                    data = urllib2.urlopen(addr, timeout=options.TIMEOUT)
                    site = data.read()

                except IOError, e:
                    print "IO Error:", e
                    site = 'HTTP Request Error'
                    self.log.er += 1
                except UnboundLocalError, e:  #The exception "variable 'data' referenced before assignment begins to pop up when I run a large number of threads
                    site = 'HTTP Request Error'
                except urllib2.HTTPError, e:
                    print "IO Error:", e
                    site = 'HTTP Request Error'
                    self.log.er += 1
                except Exception, e:
                    print "Unexpected exception:", e
                

            #Record page we are currently crawling
            self.log.crawledLock.acquire() 
            self.log.crawled.write(addr+'\n\t'+ctime()+"----"+str(len(site))+'B----Depth: '+str(self.history[addr][1])+'\n')
            self.log.sz += len(site)
            self.log.crawledLock.release()

            limiter = "\\\\\\\\\-----/////"
            pref = '\n' + limiter 
            if connType == FLAG_HTTP:
                pref += "Connection: HTTP."
            if connType == FLAG_TRUSTED_HTTPS:
                pref += "Connection: Trusted HTTPS."
            if connType == FLAG_SELFSIGNED_HTTPS:
                pref += "Connection: Untrusted Self-Signed HTTPS."
            if connType == FLAG_MISMATCHED_HTTPS:
                pref += "Connection: Untrusted HTTPS (hostname mismatch)."
            pref += "Site # " + str(len(self.log.cList)) + ": " + addr + limiter + '\n'

            #Write page's data 
            self.log.pageLock.acquire()
            self.log.cList.append(addr)
            self.log.pages.write(pref + site)
            self.log.pageLock.release()

            try:
                htmlparser.feed(site)
                htmlparser.close()
            except htmllib.HTMLParseError, e:
                # print "Encountered pesky HTMLParseError with message", e,"on page", addr
                pass

            links = htmlparser.get_links()


            
            for i in links:
                if i[0] == '/' or (len(i) >= 4 and i[0:4] == "http"):  
                    if i[0] == '/':
                        nextLink = urlparse.urljoin(addr, i)
                    else:
                        nextLink = i
                    nextLink = nextLink.rstrip('/')

                    components = urlparse.urlsplit(nextLink)
                    domain = "http://" + components[1]
                    path = components[2]
                    

                    #Create entry for root domain to track number of pages crawled per site and check robots.txt
                    if not self.history.has_key(domain): 
                        robotlist = simplerobot.get_robots(domain)
                        self.dLock.acquire()
                        self.history[domain] = [1, self.history[addr][1] + 1, robotlist]
                        self.dLock.release()
                        self.q.put(domain)
                        
                    #Add link to the queue and dictionary if it does not fail any of the criteria
                    self.dLock.acquire()
                    if (not self.history.has_key(nextLink)) and self.history[domain][0] < options.CRAWLS_PER_DOMAIN and (not nextLink.endswith(EXCLUDED_EXTENSIONS)) and robot_check(path, domain, self.history):
                        self.history[nextLink] = [0, self.history[addr][1] + 1, []]
                        self.history[domain][0] += 1
                        self.q.put(nextLink)
                    self.dLock.release()
            htmlparser.clear_data()



#Called by timer thread to remove domain from no-crawl list after courtesy period
def courtesy(recent, recLock, domain):
    recLock.acquire()
    recent.remove(domain)
    recLock.release()

def robot_check(addr, domain, d):
    for i in d[domain][2]:
        if i != '' and i in addr:
            # print "axe man is", i
            return False
    return True


def main():
    q = Queue.Queue() #Queue class doesn't require mutual exclusion
    history = {}
    dLock = threading.Lock()
    IOLock = threading.Lock()

    crawledLock = threading.Lock()
    pageLock = threading.Lock()
    crawled = open("crawled", 'w')
    pages = open("pages", 'w')
    cList = []

    log = Logger(crawledLock, crawled, pageLock, pages, cList)
    
    recent = sets.Set()
    recLock = threading.Lock()

    # q.put("http://google.com")
    # q.put('http://nytimes.com')
    # q.put('http://math.poly.edu')
    # seed = "http://math.poly.edu"
    # q.put(seed)
    # history[seed] = [0,0, simplerobot.get_robots(seed)]

    seeds = top10.top10(args[0])
    for i in seeds:
        q.put(i)
        splt = urlparse.urlsplit(i)
        dmn = splt[1]
        history[i] = [0, 0, simplerobot.get_robots(dmn)]

    t = []
    for i in range(options.THREAD_LIMIT):
        t.append(CrawlThread(q, history, dLock, IOLock, log, recent, recLock))
        t[i].start()


    while len(cList) < options.PAGES_TO_CRAWL:
        pass

    for i in range(options.THREAD_LIMIT):
        t[i].stop()

    for i in range(options.THREAD_LIMIT):
        print "Closing thread", i
        t[i].join(2)

    timeElapsed = clock()
    dLock.acquire()
    for i in history:
        if (history[i][0] > 0):
            print history[i][0], "links:", i
    dLock.release()

    print "Crawl completed, huzzah"

    s =  "\n\nCrawled "+str(len(cList))+" pages in "+str(timeElapsed)+" seconds.\n"+"Average speed: "+str(len(cList)/timeElapsed)+ " pages per second.\n"+"Encountered "+str(log.er)+" errors.\n Total size of collected data: "+str(log.sz)+" bytes.\n"
    crawledLock.acquire()
    crawled.write(s)
    print s
    crawledLock.release()
    exit()




main()
