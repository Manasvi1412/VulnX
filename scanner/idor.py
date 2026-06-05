"""
IDOR Scanner - Production Grade
Techniques: Sequential ID probing, UUID testing, Hash ID testing,
Horizontal + Vertical privilege escalation detection,
Sensitive data pattern recognition in responses
"""
import requests, time, re, difflib, hashlib
from urllib.parse import urlparse, parse_qs

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "application/json, text/html, */*;q=0.8",
}

ID_PARAM_PATTERNS = re.compile(
    r'^(id|user_?id|uid|account_?id|order_?id|invoice_?id|'
    r'record_?id|profile_?id|doc_?id|document_?id|item_?id|'
    r'product_?id|customer_?id|member_?id|post_?id|ticket_?id|'
    r'session_?id|object_?id|resource_?id|ref_?id|entity_?id|'
    r'no|num|number|key|idx|index|seq|sequence)$',
    re.IGNORECASE
)

SENSITIVE_PATTERNS = [
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "email address"),
    (re.compile(r'"password"\s*:\s*"[^"]+"', re.I),                        "password field"),
    (re.compile(r'"token"\s*:\s*"[^"]+"', re.I),                           "token"),
    (re.compile(r'"secret"\s*:\s*"[^"]+"', re.I),                          "secret key"),
    (re.compile(r'"ssn"\s*:\s*"[^"]+"', re.I),                             "SSN"),
    (re.compile(r'"credit_?card"\s*:\s*"[^"]+"', re.I),                    "credit card"),
    (re.compile(r'"phone"\s*:\s*"[^"]+"', re.I),                           "phone number"),
    (re.compile(r'"api_?key"\s*:\s*"[^"]+"', re.I),                        "API key"),
    (re.compile(r'"private_?key"\s*:\s*"[^"]+"', re.I),                    "private key"),
    (re.compile(r'"balance"\s*:\s*[\d.]+', re.I),                          "account balance"),
    (re.compile(r'"role"\s*:\s*"(admin|root|superuser|staff|manager)"', re.I), "admin role"),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),                                 "SSN pattern"),
    (re.compile(r'\b4[0-9]{12}(?:[0-9]{3})?\b'),                           "Visa card number"),
]

def is_id_param(name):
    return bool(ID_PARAM_PATTERNS.match(name)) or \
           any(k in name.lower() for k in ["_id","id_","userid","accountid"])

def get_sensitive_data(text):
    for pattern, label in SENSITIVE_PATTERNS:
        if pattern.search(text):
            return label
    return None

def response_similarity(t1, t2):
    return difflib.SequenceMatcher(None, t1[:5000], t2[:5000]).ratio()

def req(url, params, timeout=8):
    try:
        r = requests.get(url, params=params, headers=HEADERS,
                        timeout=timeout, verify=False)
        return r
    except:
        return None

def generate_test_ids(original_id):
    """Generate IDs to test based on original."""
    tests = []
    try:
        n = int(original_id)
        # Sequential
        for delta in [-1, 1, -2, 2, -5, 5, -10, 10]:
            tid = n + delta
            if tid > 0:
                tests.append(str(tid))
        # Common admin IDs
        for admin_id in ["1","2","3","0","100","1000","9999"]:
            if admin_id != str(n):
                tests.append(admin_id)
    except ValueError:
        # String ID — try variations
        if len(original_id) == 32:  # MD5-like
            tests.append("0" * 32)
            tests.append("1" * 32)
        elif len(original_id) == 36 and original_id.count("-") == 4:  # UUID
            tests.append("00000000-0000-0000-0000-000000000001")
            tests.append("00000000-0000-0000-0000-000000000002")
    return tests[:8]  # Limit tests

def run_idor_scan(crawl_data, timeout=8):
    findings, seen = [], set()

    for page in crawl_data:
        parsed = urlparse(page["url"])
        qs = {k: v[0] for k,v in parse_qs(parsed.query).items()}

        id_params = {k: v for k,v in qs.items() if is_id_param(k)}
        if not id_params: continue

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        base_qs  = {k: v[0] for k,v in qs.items()}

        # Get baseline response
        r0 = req(base_url, base_qs, timeout)
        if not r0 or r0.status_code not in [200, 201]:
            continue
        if len(r0.text) < 50:
            continue

        orig_text   = r0.text
        orig_status = r0.status_code
        orig_sensitive = get_sensitive_data(orig_text)

        for param, orig_val in id_params.items():
            key = f"{base_url}:{param}"
            if key in seen: continue

            test_ids = generate_test_ids(orig_val)

            for test_id in test_ids:
                if test_id == orig_val: continue

                test_qs = base_qs.copy()
                test_qs[param] = test_id

                r = req(base_url, test_qs, timeout)
                if not r: continue

                # Skip error pages
                if r.status_code in [404, 403, 401, 500]:
                    time.sleep(0.05)
                    continue

                # Skip identical responses
                if r.text == orig_text:
                    time.sleep(0.05)
                    continue

                sim = response_similarity(orig_text, r.text)

                # Must have similar structure (same type of data, different values)
                if sim < 0.40 or sim > 0.99:
                    time.sleep(0.05)
                    continue

                # Check for sensitive data in the accessed resource
                sensitive = get_sensitive_data(r.text)
                sensitive_detail = f" Sensitive data exposed: {sensitive}." if sensitive else ""

                severity = "Critical" if sensitive else "High"

                findings.append({
                    "vuln_type": "Insecure Direct Object Reference (IDOR)",
                    "url": page["url"], "parameter": param,
                    "payload": test_id, "severity": severity,
                    "description": (
                        f"IDOR confirmed in param '{param}'. "
                        f"Changed ID {orig_val} → {test_id} returned valid data "
                        f"(similarity: {sim:.0%}).{sensitive_detail} "
                        f"Attacker can access other users' resources without authorization."
                    ),
                    "recommendation": (
                        "1. Implement server-side authorization check for every resource access. "
                        "2. Verify the requesting user owns the requested resource. "
                        "3. Use indirect references (random UUIDs) instead of sequential IDs. "
                        "4. Log and alert on unusual access patterns. "
                        "5. Apply rate limiting to prevent enumeration."
                    )
                })
                seen.add(key)
                break

            time.sleep(0.05)

    return findings
