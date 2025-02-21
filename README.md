NeuroPwn
🚀 NeuroPwn is an advanced XSS vulnerability scanner that automates the discovery of parameters and URLs vulnerable to Cross-Site Scripting (XSS). It performs parameter discovery, URL extraction, WAF detection, payload injection, and filtration analysis for effective penetration testing.

Features
✅ Automatic Parameter Discovery – Extracts parameters from various sources like Wayback Machine, JavaScript files, robots.txt, and live links.
✅ URL Extraction – Collects URLs with parameters from multiple sources.
✅ XSS Scanner – Tests extracted parameters and URLs with advanced XSS payloads.
✅ WAF Detection – Identifies Web Application Firewalls (WAFs) and suggests bypass techniques.
✅ Filter Detection – Analyzes input filtering mechanisms for better XSS exploitation.
✅ Payload Management – Generates and encodes XSS payloads dynamically.
✅ Custom Headers & Proxies – Allows setting headers and proxies for stealth.
✅ Multi-Threaded Execution – Enhances speed by processing multiple URLs concurrently.
✅ Selenium Integration – Detects DOM-based XSS vulnerabilities with real browser execution.

Installation:

1️⃣ Clone the Repository
git clone https://github.com/yourusername/NeuroPwn.git
cd NeuroPwn

2️⃣ Install Requirements

pip install -r requirements.txt
⚠ Note: Ensure you have Google Chrome installed since Selenium uses it.

sudo apt install google-chrome -y  # Linux
For Windows, install Chrome from Google Chrome.

Usage
1️⃣ 🔍 Parameter Discovery & URL Extraction
Find parameters and extract URLs for scanning:

python neuro_pwn.py -u "https://example.com"

2️⃣ 🚀 XSS Scanning (Automatic & Advanced Mode)
Scan extracted parameters and URLs for XSS vulnerabilities:

python neuro_pwn.py -u "https://example.com" --xss

📂 Saving Results
Results are automatically saved inside the reports/ directory in JSON, TXT, CSV, HAR, and Postman formats.

Contributing
🛠️ Contributions are welcome! Feel free to submit issues and pull requests.

Author
👨‍💻 Your Name (@YourUsername)
📧 Contact: your.email@example.com
🔗 GitHub: github.com/yourusername