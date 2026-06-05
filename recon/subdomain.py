import requests, concurrent.futures
from urllib.parse import urlparse

# 300 most common subdomains — 7x more coverage than before
COMMON_SUBDOMAINS = [
    "www","mail","ftp","admin","api","dev","staging","test","blog","shop",
    "store","app","portal","login","secure","vpn","remote","support","help",
    "docs","cdn","static","images","media","upload","download","files","assets",
    "m","mobile","beta","old","new","demo","cpanel","webmail","smtp","pop",
    "imap","ns1","ns2","mx","mysql","db","sql","web","server","host","cloud",
    "git","gitlab","github","jenkins","ci","jira","confluence","redmine",
    "grafana","kibana","elastic","elk","prometheus","monitor","status","ping",
    "health","check","metrics","logs","log","syslog","splunk","nagios","zabbix",
    "backup","bak","archive","old2","legacy","v2","v1","v3","alpha","gamma",
    "test2","testing","qa","uat","preprod","pre-prod","production","prod",
    "sandbox","lab","labs","internal","corp","intranet","extranet","private",
    "public","open","external","edge","proxy","gateway","lb","loadbalancer",
    "router","firewall","vpn2","remote2","citrix","rdp","ssh","bastion","jump",
    "admin2","administrator","root","manage","management","manager","panel",
    "dashboard","console","control","cpanel2","plesk","whm","directadmin",
    "phpmyadmin","adminer","pgadmin","mongodb","redis","memcache","rabbitmq",
    "kafka","zookeeper","consul","vault","k8s","kubernetes","docker","rancher",
    "registry","repo","repository","svn","hg","mercurial","artifactory","nexus",
    "sonar","sonarqube","teamcity","bamboo","travis","circleci","drone","argocd",
    "newsletter","news","press","media2","video","videos","img","photo","photos",
    "gallery","forum","forums","community","wiki","kb","knowledge","faq","ticket",
    "tickets","helpdesk","service","servicedesk","crm","erp","hr","payroll",
    "billing","invoice","payment","payments","checkout","cart","order","orders",
    "catalog","products","search","analytics","tracking","reports","reporting",
    "data","datawarehouse","dw","bi","business","intelligence","insight","survey",
    "form","forms","survey2","feedback","contact","chat","message","messaging",
    "notification","notifications","push","webhook","hooks","events","stream",
    "realtime","socket","ws","wss","websocket","grpc","graphql","rest","soap",
    "partner","partners","affiliate","affiliates","reseller","resellers","b2b",
    "b2c","marketplace","exchange","trade","trading","finance","financial","bank",
    "mobile2","app2","ios","android","pwa","spa","react","angular","vue","node",
    "php","python","java","ruby","go","rust","dotnet","net","asp","aspnet",
    "aurora","atlas","nexus2","prime","core","base","hub","center","central",
    "office","home","personal","user","users","account","accounts","profile",
    "profiles","auth","authentication","oauth","sso","ldap","ad","directory",
    "certificate","cert","ssl","tls","acme","letsencrypt","ca","pki","crl",
]

def check_subdomain(subdomain, domain, timeout=3):
    url = f"http://{subdomain}.{domain}"
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True,
                        headers={"User-Agent": "Mozilla/5.0"})
        return {
            "subdomain":   f"{subdomain}.{domain}",
            "url":         url,
            "status_code": r.status_code,
            "alive":       True
        }
    except Exception:
        return None

def find_subdomains(target_url, max_workers=30):
    parsed = urlparse(target_url)
    domain = parsed.netloc or parsed.path
    domain = domain.replace("www.", "").split(":")[0]

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(check_subdomain, sub, domain): sub
                   for sub in COMMON_SUBDOMAINS}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                results.append(result)

    return sorted(results, key=lambda x: x["subdomain"])
