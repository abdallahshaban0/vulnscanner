"""
VulnScanner Web GUI — Flask Backend v1.1
==========================================
Run:  python app.py
Then: open http://localhost:5000
"""

import os, json, time, socket, tempfile
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response, stream_with_context, send_file

from modules.port_scanner    import run_port_scan
from modules.http_scanner    import check_http_vulnerabilities
from modules.dns_recon       import run_dns_recon
from modules.vuln_analysis   import analyse_port_vulnerabilities, calculate_risk_score, enrich_vulnerabilities, get_remediation_priority
from modules.report_generator import generate_html_report
from modules.knowledge_base  import enrich_with_knowledge
from modules.export_manager  import generate_pdf, generate_csv

app = Flask(__name__)
os.makedirs("reports", exist_ok=True)

latest_scan: dict = {}   # stores last scan for export endpoints


def sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


def parse_target(raw: str):
    raw = raw.strip()
    if not raw.startswith(("http://","https://")):
        raw = "https://" + raw
    from urllib.parse import urlparse
    p = urlparse(raw)
    domain = p.netloc or p.path.split("/")[0]
    return domain, raw


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    global latest_scan
    body       = request.get_json(force=True, silent=True) or {}
    target_raw = body.get("target","").strip()
    do_ports   = body.get("ports", True)
    do_http    = body.get("http",  True)
    do_dns     = body.get("dns",   True)

    if not target_raw:
        return jsonify({"error":"No target provided"}), 400

    domain, base_url = parse_target(target_raw)

    def generate():
        global latest_scan
        sd = {
            "target": domain, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "modules_run":[], "ports":[], "http":{}, "dns":{},
            "all_vulnerabilities":[], "risk_score":{}, "duration":"N/A",
        }
        t0 = time.time()
        all_v = []
        dns_d = {}

        yield sse({"step":"resolve","msg":f"Resolving {domain}..."})
        try:
            ip = socket.gethostbyname(domain)
            sd["resolved_ip"] = ip
            yield sse({"step":"resolve","msg":f"Resolved → {ip}","done":True})
        except socket.gaierror as e:
            yield sse({"step":"resolve","msg":f"Cannot resolve {domain}","done":True,"error":True})
            yield sse({"type":"complete","error":str(e)})
            return

        if do_http:
            sd["modules_run"].append("HTTP Scanner")
            yield sse({"step":"http","msg":"Scanning HTTP headers & SSL/TLS..."})
            hd = check_http_vulnerabilities(base_url, timeout=12)
            sd["http"] = hd
            hvs = hd.get("vulnerabilities",[])
            enrich_vulnerabilities(hvs)
            for v in hvs: enrich_with_knowledge(v)
            all_v.extend(hvs)
            yield sse({"step":"http","msg":f"HTTP done — {len(hvs)} findings","done":True})

        if do_dns:
            sd["modules_run"].append("DNS Recon")
            yield sse({"step":"dns","msg":"Enumerating DNS records & subdomains..."})
            dns_d = run_dns_recon(domain)
            sd["dns"] = dns_d
            dvs = dns_d.get("vulnerabilities",[])
            enrich_vulnerabilities(dvs)
            for v in dvs: enrich_with_knowledge(v)
            all_v.extend(dvs)
            yield sse({"step":"dns","msg":f"DNS done — {len(dns_d.get('subdomains',[]))} subdomains","done":True})

        if do_ports:
            sd["modules_run"].append("Port Scan")
            yield sse({"step":"ports","msg":"Scanning common TCP ports..."})
            ports = run_port_scan(ip, scan_type="common", threads=100, timeout=1.0)
            sd["ports"] = ports
            pvs = analyse_port_vulnerabilities(ports)
            enrich_vulnerabilities(pvs)
            for v in pvs: enrich_with_knowledge(v)
            all_v.extend(pvs)
            yield sse({"step":"ports","msg":f"Ports done — {len(ports)} open","done":True})

        yield sse({"step":"score","msg":"Calculating risk score..."})
        all_v    = get_remediation_priority(all_v)
        sd["all_vulnerabilities"] = all_v
        risk     = calculate_risk_score(all_v)
        sd["risk_score"] = risk
        sd["duration"]   = f"{round(time.time()-t0,1)}s"

        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = domain.replace(".","_")
        html_path = f"reports/scan_{safe}_{ts}.html"
        generate_html_report(sd, html_path)
        latest_scan = sd

        yield sse({"step":"score","msg":f"Score: {risk['score']}/100 ({risk['rating']})","done":True})
        yield sse({"type":"complete","data":{
            "target": domain, "ip": sd.get("resolved_ip",""),
            "timestamp": sd["timestamp"], "duration": sd["duration"],
            "risk": risk, "ports": sd["ports"], "http": sd["http"],
            "dns":{
                "records":    dns_d.get("dns_records",{}),
                "subdomains": dns_d.get("subdomains",[]),
                "whois":      dns_d.get("whois",{}),
                "zone_transfer": dns_d.get("zone_transfer",{}),
            },
            "vulnerabilities": all_v,
            "report": html_path,
        }})

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})


@app.route("/api/export/pdf", methods=["POST"])
def export_pdf():
    scan = latest_scan
    if not scan:
        return jsonify({"error":"No scan data. Run a scan first."}), 400
    for v in scan.get("all_vulnerabilities",[]): enrich_with_knowledge(v)
    tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False, dir="reports")
    tmp.close()
    generate_pdf(scan, tmp.name)
    target = scan.get("target","report").replace(".","_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return send_file(tmp.name, mimetype="application/pdf", as_attachment=True,
                     download_name=f"vulnscan_{target}_{ts}.pdf")


@app.route("/api/export/csv", methods=["POST"])
def export_csv():
    scan = latest_scan
    if not scan:
        return jsonify({"error":"No scan data. Run a scan first."}), 400
    for v in scan.get("all_vulnerabilities",[]): enrich_with_knowledge(v)
    csv_content = generate_csv(scan)
    target = scan.get("target","report").replace(".","_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(csv_content, mimetype="text/csv",
                    headers={"Content-Disposition":f"attachment; filename=vulnscan_{target}_{ts}.csv"})


@app.route("/reports/<path:filename>")
def serve_report(filename):
    from flask import send_from_directory
    return send_from_directory("reports", filename)


if __name__ == "__main__":
    print("\n" + "="*50)
    print("  VulnScanner Web GUI  |  http://localhost:5000")
    print("="*50 + "\n")
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
