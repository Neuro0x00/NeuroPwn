import hashlib
import sys
import json
import os
import time
import random
import requests
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.request_handler import RequestHandler
from core.output_manager import OutputManager
from core.html_parser import HTMLParser 
from colorama import Fore, Style, init
from core.url_generator import URLGenerator 
from core.xss_scanner import XSSScanner

init(autoreset=True)

def delayed_print(message, delay=1):
    print(message)
    time.sleep(delay)

class ParameterDiscovery:
    def __init__(self, url, wordlist_path, threads=10, method="GET", headers=None, proxy=None, timeout=3, max_retries=1, delay=0.1, recursive=False, depth=3, save_format="json", verbose=False, inject_params=None, detect_hidden=False, auto_form=False, include_param=None, exclude_param=None, chunk_size=250, output_format="json", xss_scan=False, *args, **kwargs):
        self.url = url
        self.wordlist_path = wordlist_path
        self.auto_form = auto_form
        self.threads = threads
        self.request_handler = RequestHandler(url, method, headers, proxy, timeout, max_retries, delay, verbose)
        self.recursive = recursive  
        self.depth = depth  
        self.verbose = verbose  
        self.save_format = save_format
        self.waf_detected = False 
        self.waf_params = set()
        self.detect_hidden = detect_hidden
        self.chunk_size = chunk_size
        self.output_format = output_format.lower()
        self.xss_scan = xss_scan
        
        self.total_params = 0
        self.processed_params = 0
        self.discovered_params = set()
        self.inject_params = inject_params.split(",") if inject_params else None
        self.hidden_params = set()
        self.include_params = set(include_param.split(",")) if include_param else set()
        self.exclude_params = set(exclude_param.split(",")) if exclude_param else set()
        self.discovered_urls = set()
        self.extracted_urls = set()
        self.waf_detected_params = set()
        
        # Get baseline response
        self.baseline_status, self.baseline_hash, self.baseline_length = self.request_handler.get_baseline_response()
        if self.baseline_status is None:
            print("[-] Failed to retrieve baseline response. Exiting.")
            sys.exit(1)
            
        self.form_params = set()
        if self.auto_form:
            print(" [🔍] Extracting parameters from HTML forms...")
            self.form_params = set(HTMLParser(self.url).extract_form_params())
    
    def load_wordlist(self):
        params = set()  
    
        if self.wordlist_path:
            try:
                with open(self.wordlist_path, "r", encoding="utf-8") as wordlist:
                    for line in wordlist:
                        clean_line = line.strip()
                        if clean_line:  
                            params.add(clean_line)
            except Exception as e:
                print(f"[-] Failed to load wordlist: {e}")

        if self.auto_form and self.form_params:
            params.update(self.form_params)
            
        if self.include_params:
            params.update(self.include_params) 
        
        if self.exclude_params:
            params.difference_update(self.exclude_params) 
            
        return list(params) if params else []

    def test_parameter(self, param, additional_params=None):
        """Tests a single parameter with different values and detects valid ones."""
        try:
            # ✅ values
            self.fuzz_values = [
                "test", "123", "true", "null", "admin", "<script>alert(1)</script>",
                str(random.randint(0, 999999)), 
                str(random.uniform(0, 1)), 
                "A" * 100, 
                "%22test%22", 
                "𐍈",  
                "<b>bold</b>", 
                "' OR 1=1 --",  
                '" OR "" = "',
                "\\x00\\x01\\x02",  
            ]
            
            param_value = random.choice(self.fuzz_values)
            params = {param: param_value}

            # ✅ If additional parameters exist, assign **unique random values**
            if additional_params:
                random.shuffle(self.fuzz_values)  
                assigned_values = set()  
                for p in additional_params:
                    for value in self.fuzz_values:
                        if value not in assigned_values:
                            params[p] = value  
                            assigned_values.add(value)
                            break 

            # ✅ Send request
            start_time = time.time()
            response, waf_detected = self.request_handler.make_request(params=params)
            response_time = time.time() - start_time 
            
            if waf_detected:
                self.waf_detected = True  
                self.waf_params.add(param)
                self.waf_detected_params.add(param)
                return None, None 
            
            if response:
                response_status = response.status_code
                response_hash = hashlib.md5(response.content).hexdigest()
                response_length = len(response.text)

                full_url = f"{self.url}?{param}={params[param]}" if self.request_handler.method == "GET" else self.url
                headers = self.request_handler.custom_headers

                # ✅ **Parameter Detection Logic**
                if response_status != self.baseline_status or \
                        response_hash != self.baseline_hash or \
                        abs(response_length - self.baseline_length) > 20: 
                   
                    keywords = ["forbidden", "access denied", "not allowed", "unauthorized"]
                    if any(keyword in response.text.lower() for keyword in keywords):
                        return param, None
                    
                    # Check if the injected payload is present in the response
                    if param_value in response.text:
                        self.log_valid_parameter(param, param_value)  # Log valid parameters
                        return param, None

                    # Check for changes in specific HTML elements (if applicable)
                    if "<title>" in response.text:
                        if self.baseline_title != response.text.split("<title>")[1].split("</title>")[0]:
                            return param, None
                
                # ✅ **Verbose Mode - Show Request Details**
                if self.verbose:
                    print("\n────────────────────────────────")
                    print(f"{Fore.GREEN}[🔍] Request: {self.request_handler.method} {full_url}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[📡] Headers: {headers}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[✔] Response Status: {response_status}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[✔] Response Length: {response_length}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}[📦] Params: {params}{Style.RESET_ALL}")

                # ✅ Check if new headers appeared
                if self.detect_hidden:
                    new_headers = set(headers.keys()) - set(self.baseline_headers.keys())  # Compare headers
                    if new_headers:
                        print(f"{Fore.LIGHTBLUE_EX} [🔍] Hidden Parameter Detected: {param} (Modified Headers: {', '.join(new_headers)}){Style.RESET_ALL}")
                        self.hidden_params.add(param)
                
                # ✅ Check for unusual response delays
                if self.detect_hidden and response_time > self.baseline_response_time * 1.5:
                    print(f"{Fore.RED} [⏳] Parameter '{param}' causes delay ({response_time:.2f}s) → Possible Blind Parameter!{Style.RESET_ALL}")
                    self.hidden_params.add(param)
            
        except Exception as e:
            if self.verbose:
                None
            pass
        return None, None  # ❌ No valid parameter found

    def extract_urls(self):
        """ Calls URLGenerator to extract URLs with parameters. """
        url_generator = URLGenerator(self.url)
        self.discovered_urls = url_generator.extract_urls()
        return self.discovered_urls
    
    def run(self):
        """Runs the parameter discovery process using multithreading."""
        parameters = self.load_wordlist()
        
        if self.auto_form:
            parameters.extend(self.form_params)
            
        if self.inject_params:
            print(f"{Fore.LIGHTGREEN_EX} [*] Using manually injected parameters: {', '.join(self.inject_params)}{Style.RESET_ALL}")
            parameters=self.inject_params
        else:
            parameters = self.load_wordlist()  

        if self.include_params:
            print(f"{Fore.LIGHTGREEN_EX} [✔] Params included: {self.include_params}{Style.RESET_ALL}")
            
        if self.exclude_params:
            print(f"{Fore.LIGHTGREEN_EX} [✔] Params excluded: {self.exclude_params}{Style.RESET_ALL}")
            
        self.total_params = len(parameters)
        self.hidden_params = set()
        discovered_params = set()

        print(f"{Fore.LIGHTBLUE_EX} [*] Loaded {self.total_params} parameters for testing...{Style.RESET_ALL}")

        chunks = [parameters[i:i + self.chunk_size] for i in range(0, len(parameters), self.chunk_size)]
        chunk_futures = []

        # Submit each chunk for processing in a separate thread
        chunk_size = self.chunk_size  # Adjust chunk size as needed
        chunks = [parameters[i:i + chunk_size] for i in range(0, len(parameters), chunk_size)]

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.process_chunk, chunk, min(self.threads, len(chunk)), i, len(chunks)) 
                   for i, chunk in enumerate(chunks)]

            for future in as_completed(futures):
                try:
                    discovered_params_chunk = future.result()
                    discovered_params.update(discovered_params_chunk)
                    self.processed_params += len(discovered_params_chunk)
                
                except Exception as e:
                    print(f"{Fore.RED} [ERROR] Error in chunk processing: {e}{Style.RESET_ALL}")

        sys.stdout.write("\r" + " " * 50 + "\r")
        sys.stdout.flush()
        
        self.discovered_params.update(discovered_params)
        
        if self.waf_detected_params:
            self.discovered_params.update(self.waf_detected_params)
            
        if self.waf_params:
            print(f"{Fore.RED}\r [⚠️ ] Possible WAF Detected! Some parameters returned 403, 406, or 500 status codes.{Style.RESET_ALL}")

        if self.detect_hidden and self.hidden_params:
            print("\n [🕵️] Hidden Parameters Detected:")
            print(", ".join(self.hidden_params))
        
        if self.discovered_params:
            delayed_print(f"{Fore.CYAN} [✔] Found {len(self.discovered_params)} parameters: {', '.join(self.discovered_params)}{Style.RESET_ALL}", 0.50)
        else:
            print(f"{Fore.RED}\r [-] No parameters discovered.{Style.RESET_ALL}")
        
        self.save_results(self.discovered_params)
        
        if self.recursive:
            print(f"\n {Fore.LIGHTYELLOW_EX}\r[🔍] Extracting URLs with parameters for deeper analysis... {Style.RESET_ALL}")
            self.extracted_urls = self.extract_urls()  
            print(f"{Fore.MAGENTA}\r [✔] Extracted {len(self.extracted_urls)} URLs with parameters.{Style.RESET_ALL}")
            OutputManager.save_txt("reports/extracted_param_urls.txt", self.extracted_urls)
        
        if self.recursive:
            total_urls = list(f"{self.url}?{param}=" for param in self.discovered_params) + list(self.extracted_urls)
        else:
            total_urls = list(f"{self.url}?{param}=" for param in self.discovered_params)

        if self.xss_scan:
            self.run_xss_scanner(total_urls)
            self.run_advanced_xss(total_urls)
        
        return self.discovered_params
        self.save_results(self.discovered_params)        
       
    def extract_urls(self):
        """ Extract URLs with parameters from Wayback, JS files, and live links with retry logic. """
    
        url_generator = URLGenerator(self.url)

        if not self.recursive:
                return set()  

        max_retries = 3  
        for attempt in range(1, max_retries + 1):
            try:
                print(f"{Fore.MAGENTA} [*] Fetching URLs from Wayback Machine... (Attempt {attempt}/{max_retries}){Style.RESET_ALL}")
                url_generator.wayback_machine()
                break  
            except requests.exceptions.Timeout:
                print(f"{Fore.RED} [ERROR] Wayback request timed out! Retrying... ({attempt}/{max_retries}){Style.RESET_ALL}")
                time.sleep(2)  # ⏳ Delay before retrying
            except Exception as e:
                print(f"{Fore.RED} [ERROR] Wayback request failed: {e}{Style.RESET_ALL}")
                return set()  

        print(f"{Fore.MAGENTA} [⏳] Searching for JavaScript files...{Style.RESET_ALL}")
        url_generator.extract_js_links()

        print(f"{Fore.MAGENTA} [⏳] Extracting links from the website...{Style.RESET_ALL}")
        url_generator.extract_live_links()

        self.discovered_urls = url_generator.extracted_urls
        return self.discovered_urls
 
    def process_chunk(self, chunk, threads_per_chunk, chunk_index, total_chunks):
        """Processes a single chunk of parameters."""
        discovered_params_chunk = set()
        chunk_processed_params = 0

        with ThreadPoolExecutor(max_workers=threads_per_chunk) as executor:
            future_to_param = {executor.submit(self.test_parameter, param): param for param in chunk}

            for future in as_completed(future_to_param):
                try:
                    result = future.result()
                    if result is None:
                        continue

                    param, found_params = result

                    if param:
                        discovered_params_chunk.add(param)
                        if found_params:
                            discovered_params_chunk.update(found_params)

                    # Update progress within the chunk
                    chunk_processed_params += 1
                    sys.stdout.write(f"{Fore.LIGHTCYAN_EX}\r[!] Processing Chunk {chunk_index+1}/{total_chunks}: {chunk_processed_params}/{len(chunk)}{Style.RESET_ALL}")
                    sys.stdout.flush()

                except Exception as e:
                    print(f"{Fore.RED}[ERROR] Error in thread execution: {e}{Style.RESET_ALL}")

        return discovered_params_chunk

    def run_xss_scanner(self, total_urls):
        """ Run XSS Scanner """
        if not total_urls:
            print(f"{Fore.RED}[✘] No URLs found for XSS scanning.(There isn't any specific parameter where we can test xss vulnerability{Style.RESET_ALL}")
            return

        delayed_print(f"\n{Fore.LIGHTYELLOW_EX}[*] Running XSS Scanner on discovered parameters & extracted URLs...{Style.RESET_ALL}", 1)
        
        xss_scanner = XSSScanner(
            target_url=self.url,
            discovered_params=self.discovered_params,  
            extracted_urls=self.extracted_urls,  
            method=self.request_handler.method,
            headers=self.request_handler.custom_headers,
            proxy=self.request_handler.proxy,
            verbose=self.verbose,
            threads=self.threads
        ) 
        xss_scanner.test_xss_all()  # Start the XSS scanning process
        
    def run_advanced_xss(self, total_urls):
        """ Calls `advance_xss.py` after XSS scanning with user input prompt """
        if not total_urls:
            print(f"{Fore.RED}[❌] No URLs available for Advanced XSS.{Style.RESET_ALL}")
            return
    
        try:
            script_path = os.path.join(os.path.dirname(__file__), "advance_xss.py")
    
            # ✅ Correct param mapping: {url: param} using discovered params
            param_mapping = {url: None for url in self.discovered_params}
            
            result = subprocess.run(
                ['python3', script_path, '--urls', json.dumps(total_urls), '--params', json.dumps(param_mapping)],
                capture_output=False, text=True
            )
            
            if result.returncode == 0:
                print(f"{Fore.GREEN}[✔] Advanced XSS testing completed successfully.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[❌] Advanced XSS testing encountered an error.{Style.RESET_ALL}")
    
        except Exception as e:
            print(f"{Fore.RED}[ERROR] An error occurred while running advance_xss.py: {e}{Style.RESET_ALL}")

     
    def save_results(self, discovered_params):
        """Save results in user-selected format"""
        output_dir = "reports"
        os.makedirs(output_dir, exist_ok=True)
    
        output_file = f"{output_dir}/parameters.{self.output_format}"

        if self.output_format == "json":
            OutputManager.save_json(output_file, list(discovered_params))
        elif self.output_format == "txt":
            OutputManager.save_txt(output_file, list(discovered_params))
        elif self.output_format == "csv":
            OutputManager.save_csv(output_file, list(discovered_params))
        elif self.output_format == "har":
            OutputManager.save_har(output_file, self.url, list(discovered_params))
        elif self.output_format == "postman":
            OutputManager.save_postman(output_file, self.url, list(discovered_params))
        else:
            print(f"{Fore.RED}\r[⚠] Invalid output format: {self.output_format}, using JSON instead.{Style.RESET_ALL}")
            OutputManager.save_json(f"{output_dir}/parameters.json", list(discovered_params))

