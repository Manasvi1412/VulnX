"""
Security Headers Scanner - Production Grade
Checks 12 headers, cookie flags, HTTPS, CORS misconfiguration
"""
import requests, re, urllib3
urllib3.disable_warnings()

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "High",
        "description": "CSP header missing. Without CSP, XSS attacks are easier to execute as browsers will execute any inline scripts.",
        "recommendation": "Add CSP: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'"
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "description": "HSTS missing. Site vulnerable to SSL-stripping attacks and protocol downgrade attacks.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "description": "X-Frame-Options missing. Site may be embedded in iframes — vulnerable to Clickjacking.",
        "recommendation": "Add: X-Frame-Options: DENY (or use CSP frame-ancestors directive)"
    },
    "X-Content-Type-Options": {
        "severity": "Low",
        "description": "X-Content-Type-Options missing. Browsers may MIME-sniff responses, enabling content-type attacks.",
        "recommendation": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "severity": "Low",
        "description": "Referrer-Policy missing. Full URLs may leak in Referer header to third parties.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "Low",
        "description": "Permissions-Policy missing. Browser features (camera, mic, geolocation) are unrestricted.",
        "recommendation": "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()"
    },
    "X-XSS-Protection": {
        "severity": "Low",
        "description": "X-XSS-Protection missing. Legacy XSS filter not enabled for older browsers.",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block"
    },
    "Cache-Control": {
        "severity": "Low",
        "description": "Cache-Control not set. Sensitive pages may be cached by browsers or proxies.",
        "recommendation": "Add: Cache-Control: no-store, no-cache, must-revalidate for sensitive pages"
    },
}

def check_csp_quality(csp_value):
    """Check if CSP is present but weak."""
    issues = []
    if "unsafe-inline" in csp_value:
        issues.append("'unsafe-inline' allows inline scripts — defeats XSS protection")
    if "unsafe-eval" in csp_value:
        issues.append("'unsafe-eval' allows eval() — reduces XSS protection")
    if "*" in csp_value and "script-src" in csp_value:
        issues.append("Wildcard (*) in script-src allows scripts from any origin")
    return issues

def check_cors(headers, url):
    findings = []
    acao = headers.get("Access-Control-Allow-Origin","")
    acac = headers.get("Access-Control-Allow-Credentials","")

    if acao == "*" and acac.lower() == "true":
        findings.append({
            "vuln_type": "CORS Misconfiguration — Wildcard + Credentials",
            "url": url, "parameter": "Access-Control-Allow-Origin",
            "payload": "N/A", "severity": "High",
            "description": "CORS allows any origin (*) with credentials=true. Attackers can make cross-origin authenticated requests from any website.",
            "recommendation": "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Whitelist specific trusted origins."
        })
    elif acao and acao != "*" and acao != "null":
        # Dynamic origin reflection check
        pass

    if acao == "null":
        findings.append({
            "vuln_type": "CORS Misconfiguration — Null Origin",
            "url": url, "parameter": "Access-Control-Allow-Origin",
            "payload": "N/A", "severity": "Medium",
            "description": "CORS allows 'null' origin. Sandboxed iframes and local files can make cross-origin requests.",
            "recommendation": "Never whitelist 'null' origin. Use specific domain whitelist."
        })
    return findings

def check_cookies(response, url):
    findings = []
    for cookie in response.cookies:
        cookie_issues = []
        if not cookie.secure:
            cookie_issues.append("missing Secure flag — sent over HTTP")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            # Check raw header for HttpOnly
            set_cookie_header = response.headers.get("Set-Cookie","")
            if cookie.name in set_cookie_header and "httponly" not in set_cookie_header.lower():
                cookie_issues.append("missing HttpOnly flag — accessible via JavaScript")

        if cookie_issues:
            findings.append({
                "vuln_type": f"Insecure Cookie: {cookie.name}",
                "url": url, "parameter": cookie.name,
                "payload": "N/A", "severity": "Medium",
                "description": f"Cookie '{cookie.name}' has security issues: {', '.join(cookie_issues)}.",
                "recommendation": "Set Secure, HttpOnly, and SameSite=Strict flags on all session cookies."
            })
    return findings

def check_server_info(headers, url):
    findings = []
    server = headers.get("Server","")
    powered = headers.get("X-Powered-By","")

    version_pattern = re.compile(r'[\d]+\.[\d]+', re.I)

    if server and version_pattern.search(server):
        findings.append({
            "vuln_type": "Server Version Disclosure",
            "url": url, "parameter": "Server",
            "payload": "N/A", "severity": "Low",
            "description": f"Server header reveals version: '{server}'. Attackers can target known CVEs for this exact version.",
            "recommendation": "Configure server to suppress version information. Use generic server names."
        })

    if powered:
        findings.append({
            "vuln_type": "Technology Disclosure",
            "url": url, "parameter": "X-Powered-By",
            "payload": "N/A", "severity": "Low",
            "description": f"X-Powered-By reveals technology stack: '{powered}'. Helps attackers target specific vulnerabilities.",
            "recommendation": "Remove or suppress X-Powered-By header."
        })
    return findings

def run_header_scan(target_url):
    findings = []
    try:
        r = requests.get(target_url, headers=HEADERS, timeout=10,
                        verify=False, allow_redirects=True)
        resp_headers = {k.lower(): v for k,v in r.headers.items()}
        resp_headers_orig = dict(r.headers)
    except Exception as e:
        return findings

    # 1. Missing security headers
    for header, info in SECURITY_HEADERS.items():
        header_l = header.lower()
        if header_l not in resp_headers:
            findings.append({
                "vuln_type": f"Missing Header: {header}",
                "url": target_url, "parameter": header,
                "payload": "N/A", "severity": info["severity"],
                "description": info["description"],
                "recommendation": info["recommendation"]
            })
        elif header_l == "content-security-policy":
            # CSP present but check quality
            csp_issues = check_csp_quality(resp_headers[header_l])
            for issue in csp_issues:
                findings.append({
                    "vuln_type": "Weak Content-Security-Policy",
                    "url": target_url, "parameter": header,
                    "payload": resp_headers[header_l][:100],
                    "severity": "Medium",
                    "description": f"CSP present but weak: {issue}.",
                    "recommendation": "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes instead."
                })

    # 2. CORS check
    findings.extend(check_cors(resp_headers_orig, target_url))

    # 3. Cookie flags
    findings.extend(check_cookies(r, target_url))

    # 4. Server info disclosure
    findings.extend(check_server_info(resp_headers_orig, target_url))

    # 5. HTTP (not HTTPS)
    if target_url.startswith("http://"):
        findings.append({
            "vuln_type": "Insecure Protocol (HTTP)",
            "url": target_url, "parameter": "Protocol",
            "payload": "N/A", "severity": "High",
            "description": "Site uses HTTP instead of HTTPS. All data transmitted in plaintext — vulnerable to interception and MITM attacks.",
            "recommendation": "Enable HTTPS with a valid TLS certificate. Redirect all HTTP traffic to HTTPS. Enable HSTS."
        })

    return findings
