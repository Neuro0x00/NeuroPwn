#!/usr/bin/env python3

import argparse
import os
import time
from core.parameter_discovery import ParameterDiscovery
from colorama import Fore, Style, init

DEFAULT_WORDLIST = "config/params.txt"
REPORT_DIR = "reports"

if not os.path.exists(REPORT_DIR):
    os.makedirs(REPORT_DIR)

init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.CYAN} N   N  EEEEE  U   U  RRRR    OOO   PPPPP  W   W  N   N {Style.RESET_ALL}
{Fore.CYAN} NN  N  E      U   U  R   R  O   O  P   P  W   W  NN  N {Style.RESET_ALL}
{Fore.CYAN} N N N  EEEE   U   U  RRRR   O   O  PPPPP  W W W  N N N {Style.RESET_ALL}
{Fore.CYAN} N  NN  E      U   U  R  R   O   O  P      WW WW  N  NN {Style.RESET_ALL}
{Fore.CYAN} N   N  EEEEE   UUU   R   R   OOO   P      W   W  N   N {Style.RESET_ALL}

{Fore.MAGENTA}        neuropwn v1.0 - Advanced Web Vulnerability Scanner{Style.RESET_ALL}
    """
    print(banner)

def delayed_print(message, delay=1):
    print(message)
    time.sleep(delay)

def main():
    parser = argparse.ArgumentParser(description="neuropwn: Smarter Parameter Discovery")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST, help="Parameter wordlist (default: config/params.txt)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("-o", "--output", choices=["json", "txt", "csv", "har", "postman"], default="json", help="Output format")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method")
    parser.add_argument("--headers", default='{"User-Agent": "neuropwn"}', help="Custom headers in JSON format")
    parser.add_argument("--proxy", help="Proxy for requests (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds")
    parser.add_argument("--retries", type=int, default=3, help="Max retries on request failure")
    parser.add_argument("--delay", type=float, default=0.05, help="Adaptive request delay (default: 50ms)")
    parser.add_argument("--recursive", action="store_true", help="Enable recursive parameter discovery")
    parser.add_argument("--depth", type=int, default=3, help="Max recursion depth")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose mode (show requests)")
    parser.add_argument("--inject", help="Manually specify parameters to test (comma-separated)")
    parser.add_argument("--detect-hidden", action="store_true", help="Detect hidden parameters that do not modify the response body")
    parser.add_argument("--auto-form", action="store_true", help="Extract parameters from HTML forms")
    parser.add_argument("--include-param", help="Test only these parameters (comma-separated)")
    parser.add_argument("--exclude-param", help="Exclude these parameters from testing (comma-separated)")
    parser.add_argument("--xss", action="store_true", help="Enable XSS scanning")  # ✅ Add XSS flag

    args = parser.parse_args()

    print_banner()
    delayed_print(f"{Fore.LIGHTYELLOW_EX}[*] Target: {args.url}{Style.RESET_ALL}", 0.50)
    print(f"{Fore.CYAN} [*] Checking response consistency & behavior...{Style.RESET_ALL}")

    if not os.path.exists(args.wordlist):
        print(f" [-] Wordlist not found: {args.wordlist}")
        return
    
    discovery = ParameterDiscovery(
    url=args.url,
    wordlist_path=args.wordlist,
    auto_form=args.auto_form,
    threads=args.threads,
    method=args.method,
    headers=args.headers,
    proxy=args.proxy,
    timeout=args.timeout,
    max_retries=args.retries,
    delay=args.delay,
    recursive=args.recursive,
    depth=args.depth,
    save_format=args.output,
    verbose=args.verbose,
    inject_params=args.inject,
    detect_hidden=args.detect_hidden,  
    include_param=args.include_param,
    exclude_param=args.exclude_param,
    output_format=args.output,
    xss_scan=args.xss
)
    # Retrieve baseline response
    baseline_status, baseline_hash, baseline_length = discovery.request_handler.get_baseline_response()

    # ✅ PRINT BASELINE RESPONSE WITH DELAY
    delayed_print(f"{Fore.LIGHTYELLOW_EX} [✔] Baseline: Status {baseline_status} | Hash {baseline_hash} | Length {baseline_length}{Style.RESET_ALL}", 0.50)

    discovered_params = discovery.run()

if __name__ == "__main__":
    main()
