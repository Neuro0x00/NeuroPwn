import requests
import re
import json
import random
import time
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

init(autoreset=True)

class URLGenerator:
    def __init__(self, target_url, max_retries=3, delay=2):
        self.target_url = target_url
        self.extracted_urls = set()
        self.max_retries = max_retries
        self.delay = delay 
        self.static_extensions = (
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
            ".woff2", ".ttf", ".eot", ".ico", ".mp3", ".mp4", ".pdf", ".zip",
            ".xml", ".json", ".txt", ".csv", ".tar"
        )

    def is_static_resource(self, url):
        """Check if a URL points to a static resource."""
        return url.lower().endswith(self.static_extensions)

    def wayback_machine(self):
        """ Uses Wayback Machine to find old URLs with parameters. """

        wayback_url = f"https://web.archive.org/cdx/search/cdx?url={self.target_url}/*&output=json&fl=original"

        for attempt in range(1, self.max_retries + 1):
            try:
                response = requests.get(wayback_url, timeout=10)
                
                if response.status_code == 200:
                    urls = [entry[0] for entry in json.loads(response.text)[1:]]
                    self.extract_params(urls)
                    return  # ✅ Success, exit loop
                
                time.sleep(random.uniform(1, self.delay * attempt))  # ✅ Exponential backoff

            except requests.exceptions.Timeout:
                time.sleep(random.uniform(1, self.delay * attempt))  # ✅ Wait before retrying
            
            except requests.exceptions.RequestException as e:
                return  # ❌ Critical error, stop trying

    def extract_js_links(self):
        try:
            response = requests.get(self.target_url, timeout=15)
            soup = BeautifulSoup(response.text, "html.parser")
            js_files = [urljoin(self.target_url, script["src"]) for script in soup.find_all("script") if script.get("src")]
            for js_url in js_files:
                if self.is_static_resource(js_url):
                    continue
                try:
                    js_response = requests.get(js_url, timeout=5)
                    self.extract_params(re.findall(r"(https?://[^\s'\"<>]+)", js_response.text))
                except:
                    continue
        except:
            pass

    def extract_robots_sitemap(self):
        robots_url = urljoin(self.target_url, "/robots.txt")
        sitemap_url = urljoin(self.target_url, "/sitemap.xml")
        for url in [robots_url, sitemap_url]:
            try:
                response = requests.get(url, timeout=5)
                self.extract_params(re.findall(r"(https?://[^\s'\"<>]+)", response.text))
            except:
                continue

    def extract_live_links(self):
        try:
            response = requests.get(self.target_url, timeout=10)
            soup = BeautifulSoup(response.text, "html.parser")
            links = [urljoin(self.target_url, a["href"]) for a in soup.find_all("a", href=True)]
            for link in links:
                if not self.is_static_resource(link):
                    self.extract_params([link])
        except:
            pass

    def extract_params(self, urls):
        unique_param_urls = set()
        target_domain = urlparse(self.target_url).netloc  

        for url in urls:
            parsed = urlparse(url)
        
            if parsed.netloc and parsed.netloc != target_domain:
                continue
            
            if self.is_static_resource(parsed.path):
                continue
        
            path = parsed.path  
            query_params = parsed.query.split("&")

            for param in query_params:
                if "=" in param:
                    key = param.split("=")[0]  
                    unique_key = f"{parsed.scheme}://{parsed.netloc}{path}?{key}="
                    unique_param_urls.add(unique_key)  

        self.extracted_urls.update(unique_param_urls)

    def extract_urls(self):
        self.wayback_machine()
        self.extract_js_links()
        self.extract_robots_sitemap()
        self.extract_live_links()
        return self.extracted_urls

