import requests
from bs4 import BeautifulSoup

class HTMLParser:
    """Extracts form parameters from a given URL."""

    def __init__(self, url, timeout=5):
        self.url = url
        self.timeout = timeout

    def fetch_page(self):
        """Fetches the page HTML content."""
        try:
            print(f"[!] Fetching HTML from: {self.url}")  
            response = requests.get(self.url, timeout=self.timeout)
            response.raise_for_status()  
            return response.text
        except requests.exceptions.RequestException as e:
            return None

    def extract_form_params(self):
        """Extracts parameter names from HTML forms."""
        html_content = self.fetch_page()
        if not html_content:
            print("[-] No HTML content found.")
            return []

        soup = BeautifulSoup(html_content, "lxml")
        params = set()

        # ✅ Debugging: Count total forms found
        forms_found = len(soup.find_all("form"))
        print(f"[✔] Found {forms_found} forms on the page.")

        for form in soup.find_all("form"):
            for input_tag in form.find_all(["input", "textarea", "select"]):
                name = input_tag.get("name")
                if not name:  
                    # ✅ Try extracting from `id` or `placeholder`
                    name = input_tag.get("id") or input_tag.get("placeholder")
                
                if name:
                    params.add(name)
                    
        print(f"[✔] Extracted form parameter: {sorted(params)}")  

        return list(params)
