import requests
import re
import os
import sys
import json
import argparse
import random
from colorama import Fore, Style, init
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs, urlencode

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.waf_detector import WAFDetector
from core.filter_detector import FilterDetector
from core.payload_manager import PayloadManager
from core.payloads import get_payloads_by_context, generate_encoded_payloads  # Import payloads

init(autoreset=True)

class AdvancedXSS:
    def __init__(self, urls, params, headers=None, proxy=None, timeout=5, retries=2):
        self.target_urls = list(urls)
        self.target_params = params
        self.filtered_urls = []
        self.headers = headers or {}
        self.proxy = proxy
        self.timeout = timeout
        self.retries = retries
        self.waf_results = {}

        self.waf_detector = WAFDetector(
            urls=self.target_urls,
            headers=self.headers,
            proxy=self.proxy,
            timeout=self.timeout,
            retries=self.retries
        )

        print(f"\n{Fore.YELLOW}[⚡] Running Advanced XSS Scanning...{Style.RESET_ALL}")

    def user_input_param(self):
        """ Ask user for a specific parameter to test """
        user_param = input(f"\n{Fore.CYAN}Any specific parameter you want to test? (If not, type 'no'):{Style.RESET_ALL} ").strip()
        return None if user_param.lower() == "no" else user_param
    
    def is_static_resource(self, url):
        """Check if a URL points to a static resource like JS, CSS, Images, Fonts, etc."""
        static_extensions = (
            ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
            ".woff2", ".ttf", ".eot", ".ico", ".mp3", ".mp4", ".pdf", ".zip",
            ".xml", ".json", ".txt", ".csv", ".tar"
        )

        # ✅ Check if URL **ends with** a known static file extension
        if url.lower().endswith(static_extensions):
            return True

        # ✅ Check for static **file patterns inside paths**
        static_patterns = re.compile(r"/(js|css|fonts|images|static|assets|scripts|stylesheets)/", re.IGNORECASE)
        if static_patterns.search(url):
            return True
        
        if "?ver=" in url:
            return True

        return False  # ✅ URL is valid for testing
       
    def filter_urls(self, user_param=None):
        """Filters URLs to focus on high-risk parameters, input fields, or reflected parameters for XSS testing."""

        print(f"\n{Fore.CYAN}[🔍] Filtering URLs for Advanced XSS Testing...{Style.RESET_ALL}")

        xss_risky_params = {"search", "query", "s", "input", "comment", "message", "feedback", "email", "page"}
        filtered_results = []
        input_field_urls = []

        # ✅ Step 1: Collect high-risk parameter URLs
        for url in self.target_urls:
            if self.is_static_resource(url):  # ❌ Skip static files
                continue

            try:
                response = requests.get(url, headers=self.headers, proxies=self.proxy, timeout=self.timeout)
                if response.status_code == 404:
                    continue  # Skip this URL if it returns 404
            except requests.exceptions.RequestException as e:
                continue
            
            param_str = f"?{user_param}=FUZZ" if user_param and user_param in self.target_params else ""

            # ✅ Check for high-risk parameters
            if "?" in url:
                param_list = {param.split("=")[0] for param in url.split("?")[1].split("&")}
                if param_list.intersection(xss_risky_params):
                    filtered_results.append(url + param_str)

        # ✅ Step 2: Detect input fields **(Only on valid URLs)**
        for url in self.target_urls:
            if self.is_static_resource(url):  # ❌ Skip static files
                continue

            try:
                response = requests.get(url, headers=self.headers, proxies=self.proxy, timeout=self.timeout)
                if response.status_code == 200 and "text/html" in response.headers.get("Content-Type", ""):
                    soup = BeautifulSoup(response.text, "html.parser")
                    # ✅ Look for user-input fields: input, textarea, select
                    if soup.find_all(["input", "textarea", "select"]):
                        input_field_urls.append(url)  # ✅ Add URL if input fields are found
            except requests.exceptions.RequestException as e:
                continue

        # ✅ Step 3: If either **high-risk params** OR **input fields** are found, return them
        combined_urls = list(set(filtered_results + input_field_urls))[:3]

        if combined_urls:
            self.filtered_urls = combined_urls
            print(f"{Fore.GREEN}[*] URLs for Testing (High-risk params & input fields detected, up to 3):{Style.RESET_ALL}")
            for url in self.filtered_urls:
                print(f"    {Fore.YELLOW}{url}{Style.RESET_ALL}")
            return  # ✅ Stop here if we found high-risk params or input fields

        # ✅ Step 4: Detect Reflected Parameters **(Only on valid URLs)**
        reflected_urls = [url for url in self.find_reflected_urls() if not self.is_static_resource(url)]
        if reflected_urls:
            self.filtered_urls = reflected_urls[:3]
            print(f"{Fore.GREEN}[*] Reflected URLs for Testing (showing up to 3):{Style.RESET_ALL}")
            for url in self.filtered_urls:
                print(f"    {Fore.YELLOW}{url}{Style.RESET_ALL}")
            return  # ✅ Stop here if reflected params found
        print(f"{Fore.GREEN}[*] Using {len(self.filtered_urls)} URLs for XSS testing.{Style.RESET_ALL}") 

        # ❌ **No URLs found** → Ask user for manual input
        print(f"\n{Fore.RED}[❌] No URLs available for further processing.{Style.RESET_ALL}")

        while not self.filtered_urls:
            manual_url = input(f"{Fore.CYAN}Enter a URL to test for XSS (or type 'no' to exit): {Style.RESET_ALL}").strip()

            if manual_url.lower() == "no":
                print(f"{Fore.YELLOW}[ℹ] No manual URL provided. Skipping Advanced XSS Testing.{Style.RESET_ALL}")
                return  

            if manual_url.startswith("http"):  # ✅ Validate the input
                cleaned_url = self.clean_url_for_xss(manual_url)  # ✅ Extract "https://example.com/?s="
                print(f"{Fore.GREEN}[✔] Using cleaned URL: {cleaned_url}{Style.RESET_ALL}")
                self.filtered_urls = [cleaned_url]  # ✅ Use this URL for XSS testing
                return  

        print(f"{Fore.RED}[⚠] Invalid URL format. Please enter a full URL (e.g., https://example.com/page.php?param=value).{Style.RESET_ALL}")
        return

    def clean_url_for_xss(self, url):
        """Removes parameter values and returns a clean URL for XSS testing."""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)  # Parse query parameters

        # ✅ Remove values, keep only param=
        clean_params = {param: "" for param in query_params.keys()}
        clean_query = urlencode(clean_params, doseq=True)

        # ✅ Rebuild the URL with empty parameters
        cleaned_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{clean_query}"
        return cleaned_url
        
    def find_input_field_urls(self):
        """Detects URLs containing input fields where users can enter data."""
        input_field_urls = []

        def check_input_fields(url):
            if self.is_static_resource(url):  # ❌ Skip static files
                return None

            try:
                response = requests.get(url, headers=self.headers, proxies=self.proxy, timeout=self.timeout)
                if "text/html" not in response.headers.get("Content-Type", ""):
                    return None  # Ignore non-HTML responses

                soup = BeautifulSoup(response.text, "html.parser")

                # ✅ Look for user-input fields: input, textarea, select
                if soup.find_all(["input", "textarea", "select"]):
                    return url  # ✅ Return URL if input fields are found

            except requests.exceptions.RequestException:
                return None

            return None  # No input fields found

        # ✅ Multi-threaded input field detection
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(check_input_fields, self.target_urls))

        return [url for url in results if url]  # ✅ Return only valid URLs

    def find_reflected_urls(self):
        """Detects reflected parameters in URLs by sending test requests."""

        def check_reflection(url):
            if self.is_static_resource(url):  # ❌ Skip static files
                return None

            try:
                response = requests.get(url, headers=self.headers, proxies=self.proxy, timeout=self.timeout)
                if response.status_code == 200 and any(param in response.text for param in self.target_params):
                    return url
            except requests.exceptions.RequestException:
                pass
            return None

        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(check_reflection, self.target_urls))

        return [url for url in results if url]

    def check_waf(self):
        """ Runs WAF detection on filtered URLs """
        if not self.filtered_urls:
            print(f"\n{Fore.RED} [❌] No URLs available for WAF detection.{Style.RESET_ALL}")
            return

        self.waf_detector.run_waf_detection(self.filtered_urls)

    def fetch_responses(self):
        """Fetches responses from the filtered URLs and logs any errors."""
        self.responses = {}  # Store only valid responses
        failed_urls = []  # Track failed URLs and their reasons

        def fetch(url):
            """Request URL and return response text if valid."""
            try:
                response = requests.get(url, headers=self.headers, proxies=self.proxy, timeout=self.timeout)

                # Store valid response if status code is 200
                if response.status_code == 200 and "text/html" in response.headers.get("Content-Type", ""):
                    return url, response.text  # Store valid response
                else:
                    # Log the unexpected status code but still return the URL for further processing
                    failed_urls.append(url)
                    return url, None  # Return the URL even if the response is not valid

            except requests.exceptions.Timeout:
                failed_urls.append((url, "Request timed out"))
                return url, None
            except requests.exceptions.TooManyRedirects:
                failed_urls.append((url, "Too many redirects"))
                return url, None
            except requests.exceptions.RequestException as e:
                failed_urls.append((url, f"Request failed: {str(e)}"))
                return url, None

        # Multi-threaded response fetching
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(fetch, self.filtered_urls))

        # Store only valid responses
        self.responses = {url: text for url, text in results if text}

        # Log valid responses count
        if not self.responses:
            print(f"\n{Fore.RED}[❌] No valid responses retrieved.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[🔄] Directly initiating XSS testing on failed URLs...{Style.RESET_ALL}")

            payload_manager = PayloadManager(headers=self.headers, proxy=self.proxy, timeout=self.timeout)
            payloads_per_url = {
                url: get_payloads_by_context().get("html", []) +  
                    get_payloads_by_context().get("javascript", []) +  
                    get_payloads_by_context().get("url", []) +  
                    get_payloads_by_context().get("event_handler", []) +  
                    generate_encoded_payloads(get_payloads_by_context()["html"]) +
                    generate_encoded_payloads(get_payloads_by_context()["javascript"]) 
                for url in failed_urls
            }
            payload_manager.process_payloads(failed_urls, payloads_per_url)

            return False  # Directly start XSS testing on failed URLs

        return True

    def run_dynamic_xss_testing(self):
        """ Calls PayloadManager to analyze reflections and generate payloads. """
        print(f"\n{Fore.CYAN}[🔍] Running Dynamic XSS Testing on Selected URLs...{Style.RESET_ALL}")

        if not self.filtered_urls:
            print(f"{Fore.RED} [❌] No URLs available for XSS testing.{Style.RESET_ALL}")
            return

        payload_manager = PayloadManager(headers=self.headers, proxy=self.proxy, timeout=self.timeout)
        payloads_per_url = payload_manager.analyze_reflections_and_generate_payloads(self.filtered_urls)

        if not payloads_per_url or not any(payloads_per_url.values()):
            print(f"{Fore.RED} [❌] No valid payloads were generated. Stopping XSS testing.{Style.RESET_ALL}")
            return  # Ensure process_payloads() is not called with empty data
    
        # ✅ Step 2: Send payloads and check for XSS reflection
        payload_manager.process_payloads(self.filtered_urls, payloads_per_url)    
    
    def test_xss(self, url, payload):
        """ Test each payload on the given URL """
        xss_url = f"{url}{payload}" if "?" in url else f"{url}?s={payload}"

        try:
            response = requests.get(xss_url, headers=self.headers, proxies=self.proxy, timeout=self.timeout)

            # ✅ Return the reflection message directly for better performance
            if payload in response.text or requests.utils.quote(payload) in response.text:
                return f"{Fore.YELLOW} [✔] XSS Reflected at: {xss_url}{Style.RESET_ALL}"

        except requests.exceptions.RequestException:
            return None

        return None

    def run(self):
        user_param = self.user_input_param()
        self.filter_urls(user_param)
        self.check_waf()

        if not self.filtered_urls:
            return

        filter_detector = FilterDetector(self.filtered_urls, headers=self.headers, proxy=self.proxy, timeout=self.timeout)
        filter_detector.run_filter_detection()

        if self.fetch_responses():
            self.run_dynamic_xss_testing()

if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(description="Advanced XSS Scanner")
        parser.add_argument("--urls", required=True, type=str, help="JSON-encoded list of URLs to test")
        parser.add_argument("--params", required=True, type=str, help="JSON-encoded dictionary of URL parameters")
        args = parser.parse_args()

        urls = json.loads(args.urls)
        params = json.loads(args.params)

        xss_scanner = AdvancedXSS(urls, params)
        xss_scanner.run()
    except Exception as e:
        print(f"{Fore.RED}[❌] Error: {e}{Style.RESET_ALL}")