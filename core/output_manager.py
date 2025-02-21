import json
import csv
from colorama import init, Fore, Style

init(autoreset=True) 

class OutputManager:
    @staticmethod
    def save_json(filepath, data):
        """Save output in JSON format."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump({"parameters": data}, f, indent=4)
        print(f"{Fore.GREEN}[📂 ] Saved JSON Report: {filepath}{Style.RESET_ALL}")

    @staticmethod
    def save_txt(filepath, data):
        """Save output in TXT format (one parameter per line)."""
        with open(filepath, "w", encoding="utf-8") as f:
            for param in data:
                f.write(param + "\n")
        print(f"{Fore.GREEN}[📂 ] Saved TXT Report: {filepath}{Style.RESET_ALL}")

    @staticmethod
    def save_csv(filepath, data):
        """Save output in CSV format."""
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Parameter"])  # CSV Header
            for param in data:
                writer.writerow([param])
        print(f"{Fore.GREEN}[📂 ] Saved CSV Report: {filepath}{Style.RESET_ALL}")

    @staticmethod
    def save_har(filepath, target_url, data):
        """Save output in HAR format (compatible with Burp Suite)."""
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {"name": "NeuroPwn", "version": "1.0"},
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": f"{target_url}?{param}=FUZZ",
                            "headers": [{"name": "User-Agent", "value": "NeuroPwn"}],
                        }
                    }
                    for param in data
                ],
            }
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(har_data, f, indent=4)
        print(f"{Fore.GREEN}[📂 ] Saved HAR (Burp): {filepath}{Style.RESET_ALL}")

    @staticmethod
    def save_postman(filepath, target_url, data):
        """Save output as a Postman Collection."""
        postman_collection = {
            "info": {
                "name": "NeuroPwn - Parameter Discovery",
                "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json",
            },
            "item": [
                {
                    "name": f"Test {param}",
                    "request": {
                        "method": "GET",
                        "url": {"raw": f"{target_url}?{param}=FUZZ", "host": [target_url], "query": [{"key": param, "value": "FUZZ"}]},
                        "header": [{"key": "User-Agent", "value": "NeuroPwn"}],
                    },
                }
                for param in data
            ],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(postman_collection, f, indent=4)
        print(f"{Fore.GREEN}[📂 ] Saved Postman Collection: {filepath}{Style.RESET_ALL}")
