"""
CSRF Scanner - Production Grade
Techniques: Token absence detection, SameSite cookie analysis,
Origin/Referer header validation testing, State-change verification,
Double submit cookie pattern check
"""
import requests, re
from urllib.parse import urlparse

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}

CSRF_TOKEN_NAMES = {
    "csrf","csrf_token","csrftoken","_csrf","_token","x-csrf-token",
    "authenticity_token","nonce","request_token","xsrf","xsrf_token",
    "__requestverificationtoken","_wpnonce","form_token","antiforgery",
    "anti_csrf","token","verification_token","form_key","sec",
    "viewstate","__viewstate","_method_token","form_build_id",
}

STATE_CHANGE_ACTIONS = {
    # Auth
    "login","signin","sign_in","logout","signout","register","signup",
    "sign_up","password","passwd","auth","authenticate",
    # Data modification
    "delete","remove","destroy","update","edit","change","modify",
    "save","create","add","insert","new","post","submit","upload",
    "transfer","send","buy","purchase","checkout","payment","pay",
    "order","subscribe","unsubscribe","cancel","confirm","approve",
    "reject","accept","decline","vote","like","follow","unfollow",
    "comment","reply","share","publish","unpublish","enable","disable",
}

def is_state_changing(form_action, input_names, page_url):
    combined = (form_action + " " + " ".join(input_names) + " " + page_url).lower()
    return any(action in combined for action in STATE_CHANGE_ACTIONS)

def has_csrf_protection(form):
    """Check for various CSRF protection mechanisms."""
    inputs = form.get("inputs", [])

    # 1. Check for CSRF token hidden field
    for inp in inputs:
        name = inp.get("name","").lower()
        val  = inp.get("value","")
        if any(t in name for t in CSRF_TOKEN_NAMES):
            if val and len(val) > 8:  # Token has a value
                return True, "CSRF token field present"

    # 2. Check for double-submit cookie pattern (via input names)
    for inp in inputs:
        if inp.get("type") == "hidden" and len(inp.get("value","")) > 16:
            # Likely a CSRF token even if not named 'csrf'
            return True, "Hidden token field present"

    return False, None

def check_origin_validation(url, form, timeout=6):
    """Test if server validates Origin/Referer headers."""
    action = form.get("action") or url
    method = form.get("method","GET").upper()
    if method != "POST": return None

    inputs = form.get("inputs", [])
    data = {i["name"]: i.get("value","test") for i in inputs if i.get("name")}

    # Test with malicious Origin header
    evil_headers = HEADERS.copy()
    evil_headers["Origin"]  = "https://evil.com"
    evil_headers["Referer"] = "https://evil.com/csrf_attack.html"

    try:
        r_evil = requests.post(action, data=data,
                              headers=evil_headers, timeout=timeout,
                              verify=False, allow_redirects=False)

        # Test with legitimate Origin
        legit_headers = HEADERS.copy()
        parsed = urlparse(url)
        legit_headers["Origin"]  = f"{parsed.scheme}://{parsed.netloc}"
        legit_headers["Referer"] = url

        r_legit = requests.post(action, data=data,
                               headers=legit_headers, timeout=timeout,
                               verify=False, allow_redirects=False)

        # If both responses are identical → server not checking Origin
        if r_evil.status_code == r_legit.status_code and \
           abs(len(r_evil.text) - len(r_legit.text)) < 100:
            return "Server accepts requests from any Origin (no Origin validation)"

    except: pass
    return None

def analyze_cookies_samesite(response, url):
    """Check cookie SameSite attributes."""
    findings = []
    set_cookie_header = response.headers.get("Set-Cookie","")

    # Parse all Set-Cookie headers
    all_cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw, 'headers') else []
    if not all_cookies and set_cookie_header:
        all_cookies = [set_cookie_header]

    session_keywords = ["session","sess","sid","auth","token","login","user","account"]

    for cookie_str in all_cookies:
        cookie_name = cookie_str.split("=")[0].strip().lower()
        is_session_cookie = any(k in cookie_name for k in session_keywords)

        if not is_session_cookie and not any(c in cookie_str.lower() for c in ["httponly","secure"]):
            continue

        cookie_l = cookie_str.lower()
        issues = []

        if "samesite=none" in cookie_l:
            issues.append("SameSite=None allows cross-site requests")
        elif "samesite" not in cookie_l:
            issues.append("SameSite attribute missing — defaults to browser behavior")

        if "secure" not in cookie_l:
            issues.append("Secure flag missing — sent over HTTP")

        if "httponly" not in cookie_l:
            issues.append("HttpOnly flag missing — accessible via JavaScript (XSS risk)")

        if issues:
            original_name = cookie_str.split("=")[0].strip()
            findings.append({
                "vuln_type": "Insecure Cookie Configuration",
                "url": url, "parameter": original_name,
                "payload": "N/A",
                "severity": "Medium" if is_session_cookie else "Low",
                "description": f"Cookie '{original_name}' has security issues: {'; '.join(issues)}.",
                "recommendation": (
                    "Set: Set-Cookie: name=value; HttpOnly; Secure; SameSite=Strict. "
                    "For cross-site cookies: SameSite=Lax with explicit CSRF tokens."
                )
            })

    return findings

def run_csrf_scan(crawl_data, timeout=6):
    findings, seen_forms, seen_domains = [], set(), set()

    for page in crawl_data:
        url = page["url"]
        parsed = urlparse(url)
        domain = parsed.netloc

        # Check cookies once per domain
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            try:
                r = requests.get(url, headers=HEADERS, timeout=timeout, verify=False)
                findings.extend(analyze_cookies_samesite(r, url))
            except: pass

        for form in page.get("forms",[]):
            # Only analyze POST forms (GET forms not CSRF-able for state changes)
            if form.get("method","GET").upper() != "POST":
                continue

            action = form.get("action") or url
            inputs = form.get("inputs",[])
            input_names = [i.get("name","") for i in inputs]
            key = action

            if key in seen_forms: continue

            # Only flag forms that perform state-changing operations
            if not is_state_changing(action, input_names, url):
                continue

            has_protection, protection_type = has_csrf_protection(form)

            if not has_protection:
                # Additional check: test Origin validation
                origin_issue = check_origin_validation(url, form, timeout)

                severity = "High" if origin_issue else "Medium"
                description = (
                    f"CSRF vulnerability in POST form at '{action}'. "
                    f"No CSRF token found in form inputs. "
                )
                if origin_issue:
                    description += f"{origin_issue}. "
                description += (
                    f"Form performs state-changing operation. "
                    f"Attacker can craft a page that submits this form from any website."
                )

                findings.append({
                    "vuln_type": "Cross-Site Request Forgery (CSRF)",
                    "url": action, "parameter": "csrf_token",
                    "payload": "N/A", "severity": severity,
                    "description": description,
                    "recommendation": (
                        "1. Add synchronizer token: unique per-session CSRF token in all state-changing forms. "
                        "2. Validate Origin and Referer headers server-side. "
                        "3. Set SameSite=Strict on session cookies. "
                        "4. Use Double Submit Cookie pattern as defense-in-depth. "
                        "5. For APIs: require custom request headers (e.g., X-Requested-With)."
                    )
                })
                seen_forms.add(key)

    return findings
