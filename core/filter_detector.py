import requests
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

class FilterDetector:
    def __init__(self, urls, headers=None, proxy=None, timeout=5, threads=10):
        self.urls = urls
        self.headers = headers or {}
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.timeout = timeout
        self.threads = threads  

        # ✅ Characters to Test for Filtering
        self.test_chars = {
            "<": "Blocked",
            ">": "Blocked",
            "\"": "Escaped",
            "'": "Allowed",
            "&": "Escaped"
        }

    def test_filtering(self, url):
        """Tests a URL with different characters and analyzes the response."""
        filtering_results = {}
        
        for char, default_status in self.test_chars.items():
            payload = f"test{char}filter"
            test_url = f"{url}{'&' if '?' in url else '?'}filter_test={payload}"

            try:
                response = requests.get(test_url, headers=self.headers, proxies=self.proxy, timeout=self.timeout)
                
                # ✅ Analyze Response
                if char not in response.text:
                    filtering_results[char] = "Blocked"
                elif re.search(re.escape(char), response.text):
                    filtering_results[char] = "Allowed"
                else:
                    filtering_results[char] = "Escaped"

            except requests.exceptions.RequestException:
                filtering_results[char] = "Error"

        return url, filtering_results

    def run_filter_detection(self):
        """Runs the filter detection using multi-threading."""
        print(f"\n{Fore.CYAN}[🔍] Running Filter Detection on Selected URLs...{Style.RESET_ALL}\n")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.test_filtering, url): url for url in self.urls}

            for future in as_completed(future_to_url):
                url, results = future.result()

                # ✅ Filter out only "Blocked" and "Escaped" characters
                filtered_results = {char: status for char, status in results.items() if status in ["Blocked", "Escaped"]}

                if filtered_results:
                    print(f"{Fore.YELLOW} [⚠] Filtering Detected at: {url + ("test")}{Style.RESET_ALL}")
                    for char, status in filtered_results.items():
                        print(f"    {Fore.RED if status == 'Blocked' else Fore.BLUE}[{char}] → {status}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}    [✔] No Filtration Detected at: {url + ("test")}{Style.RESET_ALL}")

                time.sleep(0.5)  # ✅ Small delay before testing next URL
