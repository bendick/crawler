	  A multithreaded web crawler. crawl.py is dependent on simplerobots.py, top10.py, google.py and BeautifulSoup.py. If your current directory is not in your PYTHONPATH then these files must be added to a directory that is.

crawl.py  [options] search terms



Optional parameters

	  -p
		Pages to be crawled before the crawler stops. Note that the number of pages actually crawled will exceed this number by slightly less than the number of threads. Default 200.


	  -c
		Courtesy delay. Number of seconds that the crawler will wait before making a subsequent http request to the same domain, excluding requests for robots.txt. Default value of 1.0.

	  -d
		Timeout delay (in seconds) for http requests. Defaults to 10.

	  -t
		Number of threads that will make concurrent http requests. 1 <= t <= 200. Large values of t (greater than 50) will result in a much higher degree of failed requests and http errors. Default value of 20.


	  -l
		Crawls Per Domain: number of pages from a single domain or subdomain that will be allowed on the queue to be crawled. Defaults to 100.

		



Other files:

simplerobots.py
	An unsophisticated robots.txt parser that does not support * and is not very forgiving about formatting inconsistencies. 
	simplerobots.get_robots(domain) :
					Given a domain will return a list of directories disallowed for user-agent *					
	

top10.py
	Function to request the top 10 results for a query from google.

External Libraries:

google.py and BeautifulSoup.py
	  External libraries that are used only for scraping the top 10 results from google of the initial query to seed the webcrawler.
	  Documentation can be found at http://breakingcode.wordpress.com/2010/06/29/google-search-python/ and http://www.crummy.com/software/BeautifulSoup/ respectively.
