**🚀 NeuroPwn - Advanced XSS Scanner**

🔎 NeuroPwn is an advanced XSS vulnerability scanner that automates the discovery of parameters and URLs vulnerable to Cross-Site Scripting (XSS). It extracts parameters, analyzes WAF, injects payloads, and detects filter mechanisms for effective penetration testing.

## Features

✅ Automatic Parameter Discovery – Extracts parameters from various sources like Wayback Machine, JavaScript files, robots.txt, and live links.

✅ URL Extraction – Collects URLs with parameters from multiple sources.

✅ XSS Scanner – Tests extracted parameters and URLs with advanced XSS payloads.

✅ WAF Detection – Identifies Web Application Firewalls (WAFs) and suggests bypass techniques.

✅ Filter Detection – Analyzes input filtering mechanisms for better XSS exploitation.

✅ Payload Management – Generates and encodes XSS payloads dynamically.

✅ Custom Headers & Proxies – Allows setting headers and proxies for stealth.

✅ Multi-Threaded Execution – Enhances speed by processing multiple URLs concurrently.

✅ Selenium Integration – Detects DOM-based XSS vulnerabilities with real browser execution.

## Installation:

1️⃣ Clone the Repository git clone:

    https://github.com/Neuro0x00/NeuroPwn.git
    cd NeuroPwn

2️⃣ Install Requirements:

    pip install -r requirements.txt

⚠ Note: Ensure you have Google Chrome installed since Selenium uses it.

    sudo apt install google-chrome -y






## Usage/Examples

1️⃣ 🔍 Parameter Discovery:

    python neuro_pwn.py -u "https://example.com"

3️⃣ 🔍 Parameter Discovery & URL Extraction Find parameters and extract URLs for scanning (recommended):

    python neuro_pwn.py -u "https://example.com" --recursive

2️⃣ 🚀 XSS Scanning (Automatic & Advanced Mode) Scan extracted parameters and URLs for XSS vulnerabilities:

    python neuro_pwn.py -u "https://example.com" --recursive --xss


⚠ Note: Results are automatically saved inside the reports/ directory in JSON, TXT, CSV, HAR, and Postman formats.

## 🔧 Example Output

    [*] Loaded 114 parameters for testing...
    [⚠️ ] Possible WAF Detected! Some parameters returned 403, 406, or 500 status codes.
    [✔] Found 11 parameters: locate, doc, exec, file, query, nav, menu, path, inc, show, conf
    [📂 ] Saved JSON Report: reports/parameters.json
## 🛠️ Contributing

Contributions are welcome! Feel free to submit issues and pull requests.


## 👨‍💻 Author

👤 Neuro0x00

📧 Contact: kharkwalvineet@gmail.com

🔗 GitHub: github.com/Neuro0x00
## Credits

The WAF signatures in /config/wafSignatures.json are taken & modified from sqlmap. I extracted them from sqlmap's waf detection modules 
