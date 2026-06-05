import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import time

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36"
}

def normalize_url(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}{p.path}".rstrip("/")

def same_domain(url, base):
    return urlparse(url).netloc == urlparse(base).netloc

def extract_forms(soup, page_url):
    forms = []
    for form in soup.find_all("form"):
        action     = form.get("action", "")
        method     = form.get("method", "get").upper()
        action_url = urljoin(page_url, action) if action else page_url
        inputs     = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name  = inp.get("name", "")
            itype = inp.get("type", "text")
            val   = inp.get("value", "")
            if name:
                inputs.append({"name": name, "type": itype, "value": val})
        forms.append({"action": action_url, "method": method,
                      "inputs": inputs, "found_on": page_url})
    return forms

def extract_links(soup, page_url, base_url):
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if any(href.startswith(x) for x in ["#", "javascript:", "mailto:", "tel:"]):
            continue
        full = urljoin(page_url, href)
        if same_domain(full, base_url):
            links.add(normalize_url(full))
    return links

def extract_params(url):
    return list(parse_qs(urlparse(url).query).keys())

def fetch_page(url, timeout=8, session_headers=None):
    try:
        hdrs = {**HEADERS, **(session_headers or {})}
        r = requests.get(url, headers=hdrs, timeout=timeout,
                         allow_redirects=True, verify=False)
        ct = r.headers.get("Content-Type", "")
        if "text/html" in ct:
            return r.text, r.status_code
    except Exception:
        pass
    return None, None

def crawl(target_url, max_pages=40, max_depth=3, session_headers=None):
    results  = {"pages": [], "forms": [], "params": [],
                "total_urls": 0, "total_forms": 0, "total_params": 0}
    visited  = set()
    to_visit = [(normalize_url(target_url), 0)]
    base_url = target_url

    while to_visit and len(visited) < max_pages:
        url, depth = to_visit.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)

        html, status = fetch_page(url, session_headers=session_headers)
        if not html:
            continue

        soup       = BeautifulSoup(html, "html.parser")
        forms      = extract_forms(soup, url)
        links      = extract_links(soup, url, base_url)
        url_params = extract_params(url)

        results["pages"].append({
            "url":         url,
            "status":      status,
            "forms":       forms,
            "params":      url_params,
            "links_found": len(links),
            "depth":       depth
        })
        results["forms"].extend(forms)
        if url_params:
            results["params"].append({"url": url, "params": url_params})

        for link in links:
            if link not in visited:
                to_visit.append((link, depth + 1))

        time.sleep(0.2)

    results["total_urls"]   = len(results["pages"])
    results["total_forms"]  = len(results["forms"])
    results["total_params"] = len(results["params"])
    return results
