"""
VulnScanner Web GUI — Flask Backend
=====================================
Run:  python app.py
Then: open http://localhost:5000 in your browser

The web server exposes:
  GET  /          → serves the GUI
  POST /api/scan  → runs the scanner and returns JSON results
  GET  /api/report/<id>  → returns saved HTML report
"""

import os
import json
import time
import socket
import threading
from datetime import datetime
from flask import Flask, render_template, request, jsonify, Response, stream_with_context

# Local scanner modules
from modules.port_scanner import run_port_scan
from modules.http_scanner import check_http_vulnerabilities
from modules.dns_recon import run_dns_recon
from modules.vuln_analysis import (
    analyse_port_vulnerabilities,
    calculate_risk_score,
    enrich_vulnerabilities,
    get_remediation_priority,
)
from modules.report_generator import generate_html_report

app = Flask(__name__)
os.makedirs("reports", exist_ok=True)


# ─── Helper ────────────────────────────────────────────────────────────────────

def sse_event(data: dict) -> str:
    """Format a dict as a Server-Sent Event."""
    return f"data: {json.dumps(data)}\n\n"


def clean_target(raw: str) -> tuple:
    """Return (domain, base_url) from raw input."""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    from urllib.parse import urlparse
    parsed = urlparse(raw)
    domain = parsed.netloc or parsed.path.split("/")[0]
    return domain, raw


# ─── Main scan endpoint (streaming SSE) ────────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def scan():
    body = request.get_json(force=True, silent=True) or {}
    target_raw = body.get("target", "").strip()
    run_ports = body.get("ports", True)
    run_http  = body.get("http",  True)
    run_dns   = body.get("dns",   True)

    if not target_raw:
        return jsonify({"error": "No target provided"}), 400

    domain, base_url = clean_target(target_raw)

    def generate():
        scan_data = {
            "target": domain,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "modules_run": [],
            "ports": [],
            "http": {},
            "dns": {},
            "all_vulnerabilities": [],
            "risk_score": {},
            "duration": "N/A",
        }
        start = time.time()
        all_vulns = []

        # ── Resolve ────────────────────────────────────────────────────────────
        yield sse_event({"step": "resolve", "msg": f"Resolving {domain}..."})
        try:
            ip = socket.gethostbyname(domain)
            scan_data["resolved_ip"] = ip
            yield sse_event({"step": "resolve", "msg": f"Resolved → {ip}", "done": True})
        except socket.gaierror as e:
            yield sse_event({"step": "resolve", "msg": f"Cannot resolve {domain}", "done": True, "error": True})
            yield sse_event({"type": "complete", "error": f"Cannot resolve {domain}: {e}"})
            return

        # ── HTTP ───────────────────────────────────────────────────────────────
        if run_http:
            scan_data["modules_run"].append("HTTP Scanner")
            yield sse_event({"step": "http", "msg": "Scanning HTTP security headers & SSL..."})
            http_data = check_http_vulnerabilities(base_url, timeout=12)
            scan_data["http"] = http_data
            http_vulns = http_data.get("vulnerabilities", [])
            enrich_vulnerabilities(http_vulns)
            all_vulns.extend(http_vulns)
            yield sse_event({
                "step": "http",
                "msg": f"HTTP scan complete — {len(http_vulns)} findings",
                "done": True,
            })

        # ── DNS ────────────────────────────────────────────────────────────────
        if run_dns:
            scan_data["modules_run"].append("DNS Recon")
            yield sse_event({"step": "dns", "msg": "Enumerating DNS records & subdomains..."})
            dns_data = run_dns_recon(domain)
            scan_data["dns"] = dns_data
            dns_vulns = dns_data.get("vulnerabilities", [])
            enrich_vulnerabilities(dns_vulns)
            all_vulns.extend(dns_vulns)
            yield sse_event({
                "step": "dns",
                "msg": f"DNS recon complete — {len(dns_data.get('subdomains', []))} subdomains, {len(dns_vulns)} findings",
                "done": True,
            })

        # ── Ports ──────────────────────────────────────────────────────────────
        if run_ports:
            scan_data["modules_run"].append("Port Scan")
            yield sse_event({"step": "ports", "msg": "Scanning common ports..."})
            ports = run_port_scan(ip, scan_type="common", threads=100, timeout=1.0)
            scan_data["ports"] = ports
            port_vulns = analyse_port_vulnerabilities(ports)
            enrich_vulnerabilities(port_vulns)
            all_vulns.extend(port_vulns)
            yield sse_event({
                "step": "ports",
                "msg": f"Port scan complete — {len(ports)} open ports, {len(port_vulns)} findings",
                "done": True,
            })

        # ── Score ──────────────────────────────────────────────────────────────
        yield sse_event({"step": "score", "msg": "Calculating risk score..."})
        all_vulns = get_remediation_priority(all_vulns)
        scan_data["all_vulnerabilities"] = all_vulns
        risk = calculate_risk_score(all_vulns)
        scan_data["risk_score"] = risk
        duration = round(time.time() - start, 1)
        scan_data["duration"] = f"{duration}s"
        yield sse_event({"step": "score", "msg": f"Risk score: {risk['score']}/100 ({risk['rating']})", "done": True})

        # ── Save report ────────────────────────────────────────────────────────
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe = domain.replace(".", "_")
        report_path = f"reports/scan_{safe}_{ts}.html"
        generate_html_report(scan_data, report_path)

        # ── Done ───────────────────────────────────────────────────────────────
        yield sse_event({
            "type": "complete",
            "data": {
                "target": domain,
                "ip": scan_data.get("resolved_ip", ""),
                "timestamp": scan_data["timestamp"],
                "duration": scan_data["duration"],
                "risk": risk,
                "ports": scan_data["ports"],
                "http": scan_data["http"],
                "dns": {
                    "records": dns_data.get("dns_records", {}) if run_dns else {},
                    "subdomains": dns_data.get("subdomains", []) if run_dns else [],
                    "whois": dns_data.get("whois", {}) if run_dns else {},
                    "zone_transfer": dns_data.get("zone_transfer", {}) if run_dns else {},
                },
                "vulnerabilities": all_vulns,
                "report": report_path,
            },
        })

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ─── Serve report file ─────────────────────────────────────────────────────────

@app.route("/reports/<path:filename>")
def serve_report(filename):
    from flask import send_from_directory
    return send_from_directory("reports", filename)


# ─── Main ──────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


if __name__ == "__main__":
    print("\n" + "="*55)
    print("  VulnScanner Web GUI")
    print("  Open your browser at: http://localhost:5000")
    print("="*55 + "\n")
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
