import os
import re
import requests
import time
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.alert import Alert
from webdriver_manager.chrome import ChromeDriverManager
from core.output_manager import OutputManager  # Assuming you have an OutputManager for saving results

init(autoreset=True)

def delayed_print(message, delay=1):
    print(message)
    time.sleep(delay)

class XSSScanner:
    def __init__(self, target_url, discovered_params, extracted_urls, wordlist="config/xss_payloads.txt", method="GET", headers=None, proxy=None, timeout=5, retries=2, delay=0.1, threads=10, chunk_size=250, verbose=False):
        self.headers = headers or {}
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.timeout = timeout
        self.retries = retries
        self.delay = delay
        self.threads = threads
        self.chunk_size = chunk_size
        self.verbose = verbose
        self.method = method.upper()
        
        self.continue_scanning = True

        # Merge discovered params and extracted URLs
        full_urls = [f"{target_url}?{param}=FUZZ" for param in discovered_params]

        self.target_urls = list(set(full_urls + list(extracted_urls)))

        # Load XSS payloads
        self.xss_payloads = self.load_wordlist(wordlist)

        # Prepare requests (every URL tested with every payload)
        self.test_requests = [(url, param, payload) for url in self.target_urls for param in self.get_params(url) for payload in self.xss_payloads]

        # Divide into chunks
        self.chunks = [self.test_requests[i:i + self.chunk_size] for i in range(0, len(self.test_requests), self.chunk_size)]

        # Initialize results
        self.xss_results = []

    def load_wordlist(self, wordlist_path):
        """ Load XSS payloads from a wordlist file """
        try:
            with open(wordlist_path, "r", encoding="utf-8") as f:
                payloads = [line.strip() for line in f if line.strip()]
                delayed_print(f"{Fore.GREEN}[✔] Loaded {len(payloads)} XSS payloads from {wordlist_path}{Style.RESET_ALL}", 1)
                return payloads
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to load wordlist: {e}{Style.RESET_ALL}")
            return []

    def get_params(self, url):
        """ Extract parameters from the URL if present """
        if "?" in url:
            return [param.split("=")[0] for param in url.split("?")[1].split("&")]
        return []

    def inject_xss(self, url, param, payload):
        if param:
            if "?" in url:
                if f"{param}=" in url:
                    url = re.sub(rf"({param}=)[^&]*", rf"\1{payload}", url)
                else:
                    url += f"&{param}={payload}"
            else:
                url += f"?{param}={payload}"
        for attempt in range(1, self.retries + 1):
            try:
                if self.method == "GET":
                    response = requests.get(url, headers=self.headers, proxies=self.proxy, timeout=self.timeout)
                elif self.method == "POST":
                    response = requests.post(url, headers=self.headers, proxies=self.proxy, timeout=self.timeout, data={param: payload})
                else:
                    return None

                return response  # Successful request

            except requests.exceptions.RequestException:
                if attempt < self.retries:
                    time.sleep(self.delay)  # Retry delay
                else:
                    return None  # Failed after retries

    def test_xss(self, url, param, payload):
        """ Test a single XSS payload on a URL. """
        if not self.continue_scanning:
            return None
        
        response = self.inject_xss(url, param, payload)
                    
        if response:
            # Analyze response for confirmed XSS
            if self.analyze_response(response, payload):
                self.log_xss(url, param, payload)
                
    def analyze_response(self, response, payload):
        """ Analyze response to detect XSS like XSStrike """
        if not response:
            return False

        # Use Selenium to check if the payload executes AND is visible in the browser
        return self.test_xss_with_browser(response.url, payload)
    
    def test_xss_with_browser(self, url, payload):
        """Uses Selenium to check if the payload executes AND is visible in the browser."""
        options = webdriver.ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--incognito")
        options.add_argument("--disable-popup-blocking")

        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        driver.set_page_load_timeout(10)

        try:
            driver.get(url)

            alert_detected = False
            dom_changed = False
            payload_visible = False
            processed_by_browser = False

            try:
                Alert(driver).accept()
                alert_detected = True
            except:
                pass

            dom_elements = ['<script>', 'onerror', 'eval(', 'onclick']
            dom_changed = any(tag in driver.page_source.lower() for tag in dom_elements)

            def is_payload_visible(driver, payload):
                try:
                    return payload in driver.find_element("tag name", "body").text
                except:
                    return False

            payload_visible = is_payload_visible(driver, payload)

            try:
                browser_exec_test = driver.execute_script("return document.readyState;")
                processed_by_browser = browser_exec_test == "complete"
            except:
                pass

            xss_confirmed = alert_detected or (processed_by_browser and dom_changed and payload_visible)
            
            if self.verbose:
                print("\n────────────────────────────────")
                print(f"{Fore.YELLOW}XSS Test for:{Style.RESET_ALL} {url}")
                print(f"{Fore.RED}JavaScript Executed:{Style.RESET_ALL} {'Yes ✅' if alert_detected else 'No ❌'}")
                print(f"{Fore.GREEN}DOM Modified:{Style.RESET_ALL} {'Yes ✅' if dom_changed else 'No ❌'}")
                print(f"{Fore.BLUE}Payload Visible in Browser:{Style.RESET_ALL} {'Yes ✅' if payload_visible else 'No ❌'}")
                print(f"{Fore.MAGENTA}Processed by Browser:{Style.RESET_ALL} {'Yes ✅' if processed_by_browser else 'No ❌'}")
                print(f"{Fore.CYAN}XSS Confirmed:{Style.RESET_ALL} {'Yes ✅' if xss_confirmed else 'No ❌'}")
                
            return xss_confirmed

        except Exception:
            return False
        finally:
            driver.quit()
               
    def process_chunk(self, chunk, chunk_index, total_chunks):
        """ Process a chunk of XSS tests. """
        processed_requests = 0
        total_requests = len(chunk)

        with ThreadPoolExecutor(max_workers=max(1, self.threads // total_chunks)) as executor:
            futures = {executor.submit(self.test_xss, url, param, payload): (url, param, payload) for url, param, payload in chunk}
            for future in as_completed(futures):
                if not self.continue_scanning:
                    break  # Stop processing if interrupted
                processed_requests += 1
                sys.stdout.write(f"\r{Fore.LIGHTCYAN_EX} [!] Processing XSS Chunk {chunk_index + 1}/{total_chunks}: {processed_requests}/{total_requests}{Style.RESET_ALL}")
                sys.stdout.flush()

    def test_xss_all(self):
        """ Run the XSS scanner across all chunks. """
        try:
            delayed_print(f"{Fore.GREEN}[*] Starting XSS Scanning...{Style.RESET_ALL}", 0.50)
            total_chunks = len(self.chunks)

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self.process_chunk, chunk, i, total_chunks): i for i, chunk in enumerate(self.chunks)}

                for future in as_completed(futures):
                    if not self.continue_scanning:
                        break  # Stop processing if interrupted
                    future.result()  # Wait for all chunks to finish

            print(f"\n{Fore.LIGHTGREEN_EX}[✔] XSS Scan Completed!{Style.RESET_ALL}")
            self.save_results()

        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[✋] XSS Scanning interrupted. Exiting gracefully...{Style.RESET_ALL}")
            self.continue_scanning = False

    def log_xss(self, url, param, payload):
        """ Log detected XSS vulnerabilities. """
        print(f"\n\n{Fore.YELLOW}  [✔] XSS Found! URL: {url}={payload}{Style.RESET_ALL}\n")
        self.xss_results.append({"url": url, "parameter": param, "payload": payload})

    def save_results(self):
        """ Save XSS scan results. """
        if self.xss_results:
            os.makedirs("reports", exist_ok=True)
            OutputManager.save_json("reports/xss_results.json", self.xss_results)
        else:
            print(f"{Fore.RED}[✘] No XSS Found.{Style.RESET_ALL}")
