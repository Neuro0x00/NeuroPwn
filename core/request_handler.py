import sys
import requests
import hashlib
import time
import json
from core.utils import get_random_headers

class RequestHandler:
    def __init__(self, url, method="GET", headers=None, proxy=None, timeout=3, max_retries=2, delay=0.1, verbose=False):
        self.url = url
        self.method = method.upper()
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.timeout = timeout
        self.max_retries = max_retries
        self.delay = delay
        self.verbose = verbose
        
        # Parse headers from JSON string
        try:
            self.custom_headers = json.loads(headers) if headers else {}
        except json.JSONDecodeError:
            self.custom_headers = {}

    def make_request(self, params=None):
        for attempt in range(1, self.max_retries + 1):
            try:
                headers = get_random_headers(self.custom_headers) 
                full_url = self.url

                if self.method == "GET":
                    response = requests.get(full_url, headers=headers, proxies=self.proxy, timeout=self.timeout, params=params)
                elif self.method == "POST":
                    response = requests.post(full_url, headers=headers, proxies=self.proxy, timeout=self.timeout, data=params)
                else:
                    return None, False
                
                # ✅ **Check for WAF detection**
                waf_detected = response.status_code in [403, 406, 500]

                time.sleep(self.delay)
                return response, waf_detected

            except requests.exceptions.RequestException as e:
                if self.verbose:
                    None
                time.sleep(self.delay)

        return None , False 

    def get_baseline_response(self):
        response, waf_detection = self.make_request({})
        if response:
            return response.status_code, hashlib.md5(response.content).hexdigest(), len(response.text)
        else:
            print("[-] Could not establish a baseline response. Check URL or network connectivity.")
            return None, None, None 
