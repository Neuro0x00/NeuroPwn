import json
import requests
import re
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

class WAFDetector:
    def __init__(self, urls, headers=None, proxy=None, timeout=3, retries=1, threads=10):
        self.urls = list(set(urls))  # Remove duplicate URLs
        self.headers = headers or {}
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.timeout = timeout
        self.retries = retries
        self.threads = threads  
        self.waf_signatures = self.load_waf_signatures("config/wafsignatures.json")

    def load_waf_signatures(self, file_path):
        """ Load WAF signatures from JSON """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def send_test_request(self, url):
        """ Sends multiple encoded payloads to detect WAF presence """
    
        headers = {**self.headers, "User-Agent": "Mozilla/5.0 (WAF Scanner)"}
        payloads = [
            "<script>alert(1)</script>",  
            "' OR 1=1 --",
            "%3Cscript%3Ealert(1)%3C/script%3E",  # URL Encoded
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",  # HTML Entity Encoded
            "\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E",  # JavaScript Escape
            "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",  # Base64
        ]
    
        for payload in payloads:
            params = {"test": payload}
            try:
                response = requests.get(url, headers=headers, proxies=self.proxy, timeout=self.timeout, params=params)
    
                if response.status_code in [403, 406, 500]:
                    print(f"{Fore.RED}[🔥] WAF Detected! Blocking {payload}{Style.RESET_ALL}")
                    return "Strong WAF (Blocking Most Payloads)"
    
                if payload in response.text:
                    print(f"{Fore.GREEN}[✔] Payload Reflected: {payload}{Style.RESET_ALL}")
                    return "Weak WAF (Payload Reflected)"
    
                # ✅ Detect WAF-Based Challenges
                if "challenge" in response.text.lower() or "captcha" in response.text.lower():
                    print(f"{Fore.YELLOW}[⚠] Possible WAF Challenge (Captcha/JS Challenge){Style.RESET_ALL}")
                    return "WAF Challenge (JS/Captcha Detected)"
    
            except requests.exceptions.RequestException:
                pass
            
        return None   

    def detect_waf(self, url):
        """ Detect WAF - Stop After First Detection """
        response = self.send_test_request(url)
        if not response:
            return None  

        for waf_name, signatures in self.waf_signatures.items():
            if "code" in signatures and str(response.status_code) in signatures["code"]:
                return waf_name

            if "page" in signatures and re.search(signatures["page"], response.text, re.IGNORECASE):
                return waf_name

            if "headers" in signatures:
                for header, value in response.headers.items():
                    if re.search(signatures["headers"], value, re.IGNORECASE):
                        return waf_name

        return None  

    def run_waf_detection(self, urls):
        """ Fast WAF Detection - Stops at First Detection """
        print(f"\n{Fore.MAGENTA}[🔍] Detecting WAF on Selected URLs...{Style.RESET_ALL}\n")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_url = {executor.submit(self.detect_waf, url): url for url in urls}

            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    waf_name = future.result()
                    if waf_name:
                        print(f"{Fore.RED}    [⚠] WAF Detected: {waf_name}{Style.RESET_ALL}")
                        return waf_name  # Stop further checks after first WAF detection
                except Exception:
                    pass

        print(f"{Fore.GREEN}    [✔] No WAF Detected.{Style.RESET_ALL}")
        return None  