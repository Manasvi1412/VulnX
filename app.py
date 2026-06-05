import os, sqlite3, threading, json
from flask import (Flask, render_template, request,
                   redirect, url_for, flash, jsonify, send_file)

import re as _re
app = Flask(__name__)
app.secret_key = "vulnx-secret-2024"

@app.template_filter('regex_split')
def regex_split_filter(value, pattern):
    return [s for s in _re.split(pattern, value) if s.strip()]

BASE_DIR = os.getcwd()
DB_PATH  = os.path.join(BASE_DIR, "database", "vulnx.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.join(BASE_DIR, "database"), exist_ok=True)
    c = get_db()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            total_vulns INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now')),
            session_cookie TEXT DEFAULT '',
            auth_header TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            vuln_type TEXT, url TEXT, parameter TEXT, payload TEXT,
            severity TEXT DEFAULT 'Low',
            description TEXT, recommendation TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS recon_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            result_type TEXT, value TEXT, extra TEXT
        );
        CREATE TABLE IF NOT EXISTS crawled_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            url TEXT, status_code INTEGER DEFAULT 0,
            forms_found INTEGER DEFAULT 0,
            params_found INTEGER DEFAULT 0,
            depth INTEGER DEFAULT 0,
            forms_json TEXT DEFAULT '[]',
            params_json TEXT DEFAULT '[]'
        );
    """)
    # Add auth columns to existing DBs that don't have them yet
    try:
        c.execute("ALTER TABLE scans ADD COLUMN session_cookie TEXT DEFAULT ''")
        c.execute("ALTER TABLE scans ADD COLUMN auth_header TEXT DEFAULT ''")
    except Exception:
        pass
    c.commit()
    c.close()

# ── Build session headers from stored auth info ───────────────────────────────
def get_session_headers(scan):
    """Convert stored cookie/auth fields into a headers dict for all scanners."""
    headers = {}
    cookie = (scan["session_cookie"] or "").strip()
    auth   = (scan["auth_header"]    or "").strip()
    if cookie:
        headers["Cookie"] = cookie
    if auth:
        # Accept both 'Bearer TOKEN' and raw token
        if auth.lower().startswith(("bearer ", "basic ", "token ")):
            headers["Authorization"] = auth
        else:
            headers["Authorization"] = f"Bearer {auth}"
    return headers

# ── background workers ────────────────────────────────────────────────────────
def run_recon(scan_id, target):
    from recon.subdomain   import find_subdomains
    from recon.portscan    import scan_ports
    from recon.tech_detect import detect_technologies
    c = get_db()
    c.execute("UPDATE scans SET status='running' WHERE id=?", (scan_id,)); c.commit()
    try:
        for sd in find_subdomains(target):
            c.execute("INSERT INTO recon_results (scan_id,result_type,value,extra) VALUES (?,?,?,?)",
                      (scan_id,"Subdomain",sd["subdomain"],f"HTTP {sd['status_code']}"))
        c.commit()
    except: pass
    try:
        ports,host,ip = scan_ports(target)
        for p in ports:
            c.execute("INSERT INTO recon_results (scan_id,result_type,value,extra) VALUES (?,?,?,?)",
                      (scan_id,"Open Port",f"{p['port']}/{p['service']}",f"Risk: {p['risk']} | {p['banner'][:60]}"))
        if ip:
            c.execute("INSERT INTO recon_results (scan_id,result_type,value,extra) VALUES (?,?,?,?)",
                      (scan_id,"IP Address",ip,f"Resolved from {host}"))
        c.commit()
    except: pass
    try:
        techs,headers = detect_technologies(target)
        for t in techs:
            c.execute("INSERT INTO recon_results (scan_id,result_type,value,extra) VALUES (?,?,?,?)",
                      (scan_id,"Technology",t["name"],f"{t['category']} | {t['confidence']}"))
        server = headers.get("Server","")
        if server:
            c.execute("INSERT INTO recon_results (scan_id,result_type,value,extra) VALUES (?,?,?,?)",
                      (scan_id,"Web Server",server,"From Server header"))
        c.commit()
    except: pass
    c.execute("UPDATE scans SET status='recon_done' WHERE id=?", (scan_id,)); c.commit(); c.close()

def run_crawl(scan_id, target, session_headers=None):
    from crawler.spider import crawl
    c = get_db()
    c.execute("UPDATE scans SET status='crawling' WHERE id=?", (scan_id,)); c.commit()
    try:
        results = crawl(target, max_pages=40, max_depth=3,
                        session_headers=session_headers)
        for page in results["pages"]:
            c.execute("""INSERT INTO crawled_urls
                (scan_id,url,status_code,forms_found,params_found,depth,forms_json,params_json)
                VALUES (?,?,?,?,?,?,?,?)""",
                (scan_id, page["url"], page["status"] or 0,
                 len(page["forms"]), len(page["params"]), page["depth"],
                 json.dumps(page["forms"]), json.dumps(page["params"])))
        c.commit()
        c.execute("UPDATE scans SET status='crawl_done' WHERE id=?", (scan_id,))
    except:
        c.execute("UPDATE scans SET status='crawl_error' WHERE id=?", (scan_id,))
    c.commit(); c.close()

def run_vuln_scan(scan_id, target, session_headers=None):
    from scanner.sqli          import run_sqli_scan
    from scanner.xss           import run_xss_scan
    from scanner.headers       import run_header_scan
    from scanner.ssrf          import run_ssrf_scan
    from scanner.lfi           import run_lfi_scan
    from scanner.idor          import run_idor_scan
    from scanner.open_redirect import run_redirect_scan
    from scanner.cmd_injection import run_cmd_scan
    from scanner.csrf          import run_csrf_scan
    from scanner.jwt_analyzer  import run_jwt_scan

    c = get_db()
    c.execute("UPDATE scans SET status='scanning' WHERE id=?", (scan_id,)); c.commit()

    rows = c.execute("SELECT url,forms_json,params_json FROM crawled_urls WHERE scan_id=?",
                     (scan_id,)).fetchall()
    crawl_data = []
    for row in rows:
        try:   forms  = json.loads(row["forms_json"]  or "[]")
        except: forms = []
        try:   params = json.loads(row["params_json"] or "[]")
        except: params = []
        crawl_data.append({"url": row["url"], "forms": forms, "params": params})

    sh = session_headers or {}
    all_findings = []

    # Pass session_headers to every scanner that supports it
    scanners = [
        ("Headers",       lambda: run_header_scan(target)),
        ("SQLi",          lambda: run_sqli_scan(crawl_data, sh)),
        ("XSS",           lambda: run_xss_scan(crawl_data, sh)),
        ("SSRF",          lambda: run_ssrf_scan(crawl_data, sh)),
        ("LFI",           lambda: run_lfi_scan(crawl_data, sh)),
        ("IDOR",          lambda: run_idor_scan(crawl_data, sh)),
        ("Open Redirect", lambda: run_redirect_scan(crawl_data, sh)),
        ("Cmd Injection", lambda: run_cmd_scan(crawl_data, sh)),
        ("CSRF",          lambda: run_csrf_scan(crawl_data, sh)),
        ("JWT",           lambda: run_jwt_scan(crawl_data, sh)),
    ]
    for name, scanner in scanners:
        try:
            results = scanner()
            all_findings.extend(results)
            print(f"[VulnX] {name}: {len(results)} findings")
        except Exception as e:
            print(f"[VulnX] {name} skipped: {e}")

    for f in all_findings:
        c.execute("""INSERT INTO vulnerabilities
            (scan_id,vuln_type,url,parameter,payload,severity,description,recommendation)
            VALUES (?,?,?,?,?,?,?,?)""",
            (scan_id, f.get("vuln_type","Unknown"), f.get("url",""),
             f.get("parameter",""), f.get("payload","N/A"),
             f.get("severity","Low"), f.get("description",""),
             f.get("recommendation","")))
    c.execute("UPDATE scans SET status='complete', total_vulns=? WHERE id=?",
              (len(all_findings), scan_id))
    c.commit(); c.close()

# ── routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    c = get_db()
    scans       = c.execute("SELECT * FROM scans ORDER BY created_at DESC LIMIT 10").fetchall()
    total_scans = c.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    total_vulns = c.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
    critical    = c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE severity='Critical'").fetchone()[0]
    c.close()
    return render_template("index.html", scans=scans, total_scans=total_scans,
                           total_vulns=total_vulns, critical=critical)

@app.route("/new-scan", methods=["POST"])
def new_scan():
    target         = request.form.get("target","").strip()
    session_cookie = request.form.get("session_cookie","").strip()
    auth_header    = request.form.get("auth_header","").strip()

    if not target:
        flash("Enter a target URL.", "danger")
        return redirect(url_for("index"))
    if not target.startswith("http"):
        target = "http://" + target

    c = get_db()
    scan_id = c.execute(
        "INSERT INTO scans (target,status,session_cookie,auth_header) VALUES (?,?,?,?)",
        (target, "pending", session_cookie, auth_header)
    ).lastrowid
    c.commit(); c.close()

    def pipeline(sid, tgt, cookie, auth):
        scan_row = {"session_cookie": cookie, "auth_header": auth}
        sh = get_session_headers(scan_row)
        run_recon(sid, tgt)
        run_crawl(sid, tgt, sh)
        run_vuln_scan(sid, tgt, sh)

    threading.Thread(target=pipeline,
                     args=(scan_id, target, session_cookie, auth_header),
                     daemon=True).start()
    flash(f"Scan started for {target}!", "success")
    return redirect(url_for("scan_detail", scan_id=scan_id))

@app.route("/scan-vulns/<int:scan_id>", methods=["POST"])
def scan_vulns_only(scan_id):
    c    = get_db()
    scan = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    c.close()
    if not scan:
        flash("Not found.", "danger"); return redirect(url_for("index"))
    sh = get_session_headers(dict(scan))
    threading.Thread(target=run_vuln_scan,
                     args=(scan_id, scan["target"], sh), daemon=True).start()
    flash("Vuln scan started!", "success")
    return redirect(url_for("scan_detail", scan_id=scan_id))

@app.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    c    = get_db()
    scan = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        flash("Not found.", "danger"); return redirect(url_for("index"))
    vulns = c.execute("""SELECT * FROM vulnerabilities WHERE scan_id=?
                         ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                         WHEN 'Medium' THEN 3 ELSE 4 END""", (scan_id,)).fetchall()
    recon = c.execute("SELECT * FROM recon_results WHERE scan_id=?", (scan_id,)).fetchall()
    urls  = c.execute("SELECT * FROM crawled_urls WHERE scan_id=? ORDER BY depth,url", (scan_id,)).fetchall()
    c.close()
    severity_counts = {"Critical":0,"High":0,"Medium":0,"Low":0}
    for v in vulns:
        if v["severity"] in severity_counts: severity_counts[v["severity"]] += 1
    recon_grouped = {}
    for r in recon: recon_grouped.setdefault(r["result_type"],[]).append(r)
    urls_parsed = []
    for u in urls:
        try:    forms = json.loads(u["forms_json"] or "[]")
        except: forms = []
        try:    params = json.loads(u["params_json"] or "[]")
        except: params = []
        urls_parsed.append({**dict(u), "forms": forms, "params": params})
    total_forms  = sum(u["forms_found"]  for u in urls)
    total_params = sum(u["params_found"] for u in urls)
    has_auth = bool((scan["session_cookie"] or "").strip() or
                    (scan["auth_header"]    or "").strip())
    return render_template("scan_detail.html",
        scan=scan, vulns=vulns, recon=recon,
        recon_grouped=recon_grouped, urls=urls_parsed,
        severity_counts=severity_counts,
        total_forms=total_forms, total_params=total_params,
        has_auth=has_auth)

@app.route("/api/scan-status/<int:scan_id>")
def scan_status(scan_id):
    c  = get_db()
    sc = c.execute("SELECT status FROM scans WHERE id=?", (scan_id,)).fetchone()
    rc = c.execute("SELECT COUNT(*) FROM recon_results   WHERE scan_id=?", (scan_id,)).fetchone()[0]
    uc = c.execute("SELECT COUNT(*) FROM crawled_urls    WHERE scan_id=?", (scan_id,)).fetchone()[0]
    vc = c.execute("SELECT COUNT(*) FROM vulnerabilities WHERE scan_id=?", (scan_id,)).fetchone()[0]
    c.close()
    return jsonify({"status": sc["status"] if sc else "not_found",
                    "recon_count": rc, "url_count": uc, "vuln_count": vc})

@app.route("/api/severity-stats")
def severity_stats():
    c    = get_db()
    rows = c.execute("SELECT severity, COUNT(*) as cnt FROM vulnerabilities GROUP BY severity").fetchall()
    c.close()
    counts = {"Critical":0,"High":0,"Medium":0,"Low":0}
    for r in rows:
        if r["severity"] in counts: counts[r["severity"]] = r["cnt"]
    return jsonify(counts)

@app.route("/report/<int:scan_id>")
def report_page(scan_id):
    c    = get_db()
    scan = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    if not scan:
        flash("Scan not found.", "danger"); return redirect(url_for("index"))
    vulns  = c.execute("""SELECT * FROM vulnerabilities WHERE scan_id=?
                          ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                          WHEN 'Medium' THEN 3 ELSE 4 END""", (scan_id,)).fetchall()
    recon  = c.execute("SELECT * FROM recon_results WHERE scan_id=?", (scan_id,)).fetchall()
    urls   = c.execute("SELECT * FROM crawled_urls  WHERE scan_id=?", (scan_id,)).fetchall()
    c.close()
    return render_template("report.html",
                           scan=dict(scan),
                           vulns=[dict(v) for v in vulns],
                           recon=[dict(r) for r in recon],
                           total_urls=len(urls),
                           total_forms=sum(u["forms_found"]  for u in urls),
                           total_params=sum(u["params_found"] for u in urls))

@app.route("/api/ai-analyze/<int:scan_id>")
def ai_analyze(scan_id):
    from ai_engine.gemini_analyzer import analyze_vulnerability, analyze_scan_summary
    c     = get_db()
    scan  = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    vulns = c.execute("SELECT * FROM vulnerabilities WHERE scan_id=?", (scan_id,)).fetchall()
    c.close()
    if not scan: return jsonify({"error":"not found"}), 404
    vuln_list = [dict(v) for v in vulns]
    results   = []
    for v in vuln_list:
        results.append({"id": v["id"], "analysis": analyze_vulnerability(v)})
    summary = analyze_scan_summary(scan["target"], vuln_list)
    return jsonify({"summary": summary, "analyses": results})

@app.route("/download-report/<int:scan_id>")
def download_report(scan_id):
    from reports.pdf_generator import generate_pdf
    from ai_engine.gemini_analyzer import analyze_vulnerability, analyze_scan_summary
    c     = get_db()
    scan  = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    vulns = c.execute("""SELECT * FROM vulnerabilities WHERE scan_id=?
                         ORDER BY CASE severity WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                         WHEN 'Medium' THEN 3 ELSE 4 END""", (scan_id,)).fetchall()
    recon = c.execute("SELECT * FROM recon_results WHERE scan_id=?", (scan_id,)).fetchall()
    urls  = c.execute("SELECT * FROM crawled_urls  WHERE scan_id=?", (scan_id,)).fetchall()
    c.close()
    if not scan:
        flash("Not found.", "danger"); return redirect(url_for("index"))
    vuln_list = [dict(v) for v in vulns]
    for v in vuln_list: v["ai_analysis"] = analyze_vulnerability(v)
    crawl_stats = {"pages": len(urls),
                   "forms": sum(u["forms_found"]  for u in urls),
                   "params": sum(u["params_found"] for u in urls), "depth": 3}
    out_dir  = os.path.join(BASE_DIR, "reports")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"vulnx_report_{scan_id}.pdf")
    ok, result = generate_pdf(dict(scan), vuln_list,
                              [dict(r) for r in recon],
                              crawl_stats,
                              analyze_scan_summary(scan["target"], vuln_list),
                              out_path)
    if ok:
        return send_file(result, as_attachment=True,
                         download_name=f"VulnX_Report_{scan_id}.pdf",
                         mimetype="application/pdf")
    flash(f"PDF error: {result}", "danger")
    return redirect(url_for("scan_detail", scan_id=scan_id))

@app.route("/delete-scan/<int:scan_id>", methods=["POST"])
def delete_scan(scan_id):
    c = get_db()
    for tbl in ["vulnerabilities","recon_results","crawled_urls"]:
        c.execute(f"DELETE FROM {tbl} WHERE scan_id=?", (scan_id,))
    c.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    c.commit(); c.close()
    flash("Deleted.", "info")
    return redirect(url_for("index"))

if __name__ == "__main__":
    init_db()
    print("\n✅  VulnX  →  http://localhost:5000\n")
    app.run(debug=True, port=5000)
