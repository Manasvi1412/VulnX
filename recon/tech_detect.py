import requests
from urllib.parse import urlparse

TECH_SIGNATURES = {
    "headers": {
        "X-Powered-By": {
            "PHP": "php",
            "ASP.NET": "asp.net",
            "Express": "nodejs"
        },
        "Server": {
            "Apache": "apache",
            "nginx": "nginx",
            "Microsoft-IIS": "iis",
            "LiteSpeed": "litespeed",
            "cloudflare": "cloudflare"
        },
        "X-Generator": {"WordPress": "wordpress"},
        "X-Drupal-Cache": {"Drupal": "drupal"},
        "X-Shopify-Stage": {"Shopify": "shopify"},
    },
    "body": {
        "wp-content": "WordPress",
        "wp-includes": "WordPress",
        "Joomla": "Joomla",
        "drupal.js": "Drupal",
        "React": "React",
        "ng-version": "Angular",
        "__vue": "Vue.js",
        "jquery": "jQuery",
        "bootstrap": "Bootstrap",
        "laravel": "Laravel",
        "django": "Django",
        "rails": "Ruby on Rails",
    },
    "cookies": {
        "PHPSESSID": "PHP",
        "JSESSIONID": "Java",
        "ASP.NET_SessionId": "ASP.NET",
        "csrftoken": "Django",
        "laravel_session": "Laravel"
    }
}

def detect_technologies(target_url):
    detected = []
    headers_info = {}
    try:
        r = requests.get(target_url, timeout=8, allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0 (compatible; VulnX/1.0)"})
        headers_info = dict(r.headers)
        body = r.text.lower()

        for header, tech_map in TECH_SIGNATURES["headers"].items():
            val = r.headers.get(header, "")
            for keyword, tech in tech_map.items():
                if keyword.lower() in val.lower():
                    detected.append({
                        "name": keyword,
                        "category": "Server / Framework",
                        "confidence": "High",
                        "source": f"Header: {header}"
                    })

        for pattern, tech in TECH_SIGNATURES["body"].items():
            if pattern.lower() in body:
                detected.append({
                    "name": tech,
                    "category": "Frontend / CMS",
                    "confidence": "Medium",
                    "source": "HTML body"
                })

        for cookie_name, tech in TECH_SIGNATURES["cookies"].items():
            if cookie_name in r.cookies:
                detected.append({
                    "name": tech,
                    "category": "Backend",
                    "confidence": "High",
                    "source": f"Cookie: {cookie_name}"
                })

        seen = set()
        unique = []
        for t in detected:
            if t["name"] not in seen:
                seen.add(t["name"])
                unique.append(t)
        detected = unique

    except Exception as e:
        pass

    return detected, headers_info
