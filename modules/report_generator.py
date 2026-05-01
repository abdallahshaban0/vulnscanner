"""
Report Generator Module
=========================
Generates a professional, standalone HTML report and a JSON export
of all scan findings.
"""

import json
from datetime import datetime
from typing import Dict, List


def generate_html_report(scan_data: Dict, output_path: str) -> str:
    """Generate a self-contained HTML report."""

    target = scan_data.get("target", "Unknown")
    timestamp = scan_data.get("timestamp", datetime.now().isoformat())
    risk = scan_data.get("risk_score", {})
    all_vulns = scan_data.get("all_vulnerabilities", [])
    port_results = scan_data.get("ports", [])
    http_results = scan_data.get("http", {})
    dns_results = scan_data.get("dns", {})

    score = risk.get("score", 0)
    rating = risk.get("rating", "UNKNOWN")
    counts = risk.get("counts", {})

    score_color = {
        "CRITICAL": "#ef4444",
        "HIGH": "#f97316",
        "MEDIUM": "#eab308",
        "LOW": "#22c55e",
        "SECURE": "#10b981",
    }.get(rating, "#6b7280")

    def sev_badge(sev: str) -> str:
        colors = {
            "CRITICAL": "background:#7f1d1d;color:#fca5a5",
            "HIGH": "background:#7c2d12;color:#fdba74",
            "MEDIUM": "background:#713f12;color:#fde68a",
            "LOW": "background:#14532d;color:#86efac",
            "INFO": "background:#1e3a5f;color:#93c5fd",
        }
        style = colors.get(sev, "background:#374151;color:#d1d5db")
        return f'<span style="padding:2px 10px;border-radius:12px;font-size:11px;font-weight:700;{style}">{sev}</span>'

    def render_vuln_rows(vulns: List[Dict]) -> str:
        if not vulns:
            return '<tr><td colspan="4" style="text-align:center;color:#6b7280;padding:20px">No vulnerabilities found ✓</td></tr>'
        rows = ""
        for v in vulns:
            sev = v.get("severity", "INFO")
            vtype = v.get("type", "").replace("_", " ")
            detail = v.get("detail", "")
            owasp = v.get("owasp", "")
            port = v.get("port", "")
            port_str = f'<br><small style="color:#9ca3af">Port: {port}</small>' if port else ""
            rows += f"""
            <tr style="border-bottom:1px solid #1f2937">
              <td style="padding:12px 16px">{sev_badge(sev)}</td>
              <td style="padding:12px 16px;color:#e5e7eb;font-weight:600">{vtype}{port_str}</td>
              <td style="padding:12px 16px;color:#9ca3af;font-size:13px">{detail}</td>
              <td style="padding:12px 16px;color:#6b7280;font-size:12px">{owasp}</td>
            </tr>"""
        return rows

    def render_ports_table(ports: List[Dict]) -> str:
        if not ports:
            return '<p style="color:#6b7280;text-align:center">No open ports found.</p>'
        rows = ""
        for p in ports:
            risk_colors = {"HIGH": "#ef4444", "MEDIUM": "#f97316", "LOW": "#22c55e"}
            rc = risk_colors.get(p.get("risk", "LOW"), "#6b7280")
            banner = (p.get("banner") or "—")[:80]
            rows += f"""
            <tr style="border-bottom:1px solid #1f2937">
              <td style="padding:10px 16px;color:#60a5fa;font-weight:700">{p['port']}</td>
              <td style="padding:10px 16px;color:#34d399">{p.get('service','unknown')}</td>
              <td style="padding:10px 16px"><span style="color:{rc};font-weight:600">{p.get('risk','LOW')}</span></td>
              <td style="padding:10px 16px;color:#6b7280;font-size:12px;font-family:monospace">{banner}</td>
            </tr>"""
        return f"""
        <table style="width:100%;border-collapse:collapse">
          <thead>
            <tr style="background:#111827;color:#9ca3af;font-size:12px;text-transform:uppercase">
              <th style="padding:10px 16px;text-align:left">Port</th>
              <th style="padding:10px 16px;text-align:left">Service</th>
              <th style="padding:10px 16px;text-align:left">Risk</th>
              <th style="padding:10px 16px;text-align:left">Banner</th>
            </tr>
          </thead>
          <tbody>{rows}</tbody>
        </table>"""

    def render_dns_section(dns: Dict) -> str:
        if not dns:
            return '<p style="color:#6b7280">DNS data not available.</p>'
        ips = ", ".join(dns.get("ip_addresses", [])) or "—"
        subdomains = dns.get("subdomains", [])
        subs_html = ""
        for s in subdomains[:20]:
            subs_html += f'<li style="color:#34d399;font-size:13px">{s["subdomain"]} → {", ".join(s["ips"])}</li>'

        records_html = ""
        for rtype, values in dns.get("dns_records", {}).items():
            for v in values:
                records_html += f'<tr style="border-bottom:1px solid #1f2937"><td style="padding:8px 12px;color:#60a5fa;font-weight:600">{rtype}</td><td style="padding:8px 12px;color:#d1d5db;font-size:13px;font-family:monospace">{v[:120]}</td></tr>'

        zt = dns.get("zone_transfer", {})
        zt_status = f'<span style="color:#ef4444;font-weight:700">⚠ VULNERABLE — Zone transfer succeeded on {zt.get("nameserver","")}</span>' if zt.get("success") else '<span style="color:#22c55e">✓ Zone transfer blocked</span>'

        whois = dns.get("whois", {})
        whois_html = ""
        if whois:
            for k, v in whois.items():
                whois_html += f'<tr><td style="padding:6px 12px;color:#9ca3af;font-size:13px">{k}</td><td style="padding:6px 12px;color:#d1d5db;font-size:13px">{str(v)[:100]}</td></tr>'

        return f"""
        <p style="color:#9ca3af;margin:0 0 8px 0;font-size:13px">Resolved IPs: <strong style="color:#e5e7eb">{ips}</strong></p>
        <p style="color:#9ca3af;margin:0 0 16px 0;font-size:13px">Zone Transfer: {zt_status}</p>

        {'<h4 style="color:#9ca3af;margin:16px 0 8px 0;font-size:13px;text-transform:uppercase;letter-spacing:1px">DNS Records</h4><table style="width:100%;border-collapse:collapse"><tbody>' + records_html + '</tbody></table>' if records_html else ''}

        {'<h4 style="color:#9ca3af;margin:16px 0 8px 0;font-size:13px;text-transform:uppercase;letter-spacing:1px">Subdomains Found (' + str(len(subdomains)) + ')</h4><ul style="margin:0;padding-left:20px">' + subs_html + ('...' if len(subdomains) > 20 else '') + '</ul>' if subdomains else '<p style="color:#6b7280;font-size:13px">No subdomains discovered.</p>'}

        {'<h4 style="color:#9ca3af;margin:16px 0 8px 0;font-size:13px;text-transform:uppercase;letter-spacing:1px">WHOIS</h4><table style="width:100%;border-collapse:collapse"><tbody>' + whois_html + '</tbody></table>' if whois_html else ''}
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnScanner Report — {target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;500;600;700&display=swap');
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0a0e1a; color: #e5e7eb; font-family: 'Inter', sans-serif; line-height: 1.6; }}
  .header {{ background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%); border-bottom: 1px solid #1f2937; padding: 40px 60px; }}
  .header-top {{ display: flex; justify-content: space-between; align-items: flex-start; }}
  .logo {{ font-family: 'JetBrains Mono', monospace; font-size: 13px; color: #6b7280; letter-spacing: 2px; text-transform: uppercase; }}
  .logo span {{ color: #818cf8; }}
  .report-title {{ font-size: 28px; font-weight: 700; color: #f9fafb; margin: 12px 0 4px 0; }}
  .report-target {{ font-family: 'JetBrains Mono', monospace; font-size: 16px; color: #818cf8; }}
  .report-meta {{ font-size: 12px; color: #6b7280; margin-top: 8px; }}
  .score-badge {{ text-align: right; }}
  .score-circle {{ width: 90px; height: 90px; border-radius: 50%; display: flex; flex-direction: column; align-items: center; justify-content: center; border: 3px solid {score_color}; margin-left: auto; }}
  .score-num {{ font-size: 28px; font-weight: 700; color: {score_color}; line-height: 1; }}
  .score-label {{ font-size: 10px; color: #9ca3af; text-transform: uppercase; letter-spacing: 1px; }}
  .score-rating {{ margin-top: 6px; font-size: 13px; font-weight: 700; color: {score_color}; }}
  .stats-bar {{ display: flex; gap: 0; padding: 16px 60px; background: #0d1117; border-bottom: 1px solid #1f2937; }}
  .stat {{ flex: 1; text-align: center; padding: 12px; border-right: 1px solid #1f2937; }}
  .stat:last-child {{ border-right: none; }}
  .stat-num {{ font-size: 24px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }}
  .stat-label {{ font-size: 11px; color: #6b7280; text-transform: uppercase; letter-spacing: 1px; margin-top: 2px; }}
  .content {{ max-width: 1200px; margin: 0 auto; padding: 40px 60px; }}
  .section {{ margin-bottom: 40px; }}
  .section-title {{ font-size: 16px; font-weight: 600; color: #f9fafb; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #1f2937; display: flex; align-items: center; gap: 8px; }}
  .section-title .icon {{ font-size: 18px; }}
  .card {{ background: #111827; border: 1px solid #1f2937; border-radius: 8px; overflow: hidden; }}
  .vuln-table {{ width: 100%; border-collapse: collapse; }}
  .vuln-table thead tr {{ background: #0d1117; }}
  .vuln-table thead th {{ padding: 12px 16px; text-align: left; color: #6b7280; font-size: 11px; text-transform: uppercase; letter-spacing: 1px; font-weight: 600; }}
  .http-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .http-item {{ background: #111827; border: 1px solid #1f2937; border-radius: 6px; padding: 14px; }}
  .http-item-title {{ font-size: 12px; font-weight: 600; color: #6b7280; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px; }}
  .footer {{ border-top: 1px solid #1f2937; padding: 24px 60px; text-align: center; color: #374151; font-size: 12px; font-family: 'JetBrains Mono', monospace; }}
  .tag {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-family: 'JetBrains Mono', monospace; margin: 2px; }}
  .tag-info {{ background: #1e3a5f; color: #93c5fd; }}
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div>
      <div class="logo">[ <span>VULNSCANNER</span> ] // Automated Security Assessment</div>
      <div class="report-title">Vulnerability Assessment Report</div>
      <div class="report-target">{target}</div>
      <div class="report-meta">Generated: {timestamp} &nbsp;|&nbsp; Scan Duration: {scan_data.get('duration', 'N/A')} &nbsp;|&nbsp; Modules: {', '.join(scan_data.get('modules_run', []))}</div>
    </div>
    <div class="score-badge">
      <div class="score-circle">
        <div class="score-num">{score}</div>
        <div class="score-label">/ 100</div>
      </div>
      <div class="score-rating">{rating} RISK</div>
    </div>
  </div>
</div>

<div class="stats-bar">
  <div class="stat">
    <div class="stat-num" style="color:#ef4444">{counts.get('CRITICAL',0)}</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:#f97316">{counts.get('HIGH',0)}</div>
    <div class="stat-label">High</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:#eab308">{counts.get('MEDIUM',0)}</div>
    <div class="stat-label">Medium</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:#22c55e">{counts.get('LOW',0)}</div>
    <div class="stat-label">Low</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:#60a5fa">{len(port_results)}</div>
    <div class="stat-label">Open Ports</div>
  </div>
  <div class="stat">
    <div class="stat-num" style="color:#a78bfa">{len(dns_results.get('subdomains',[]))}</div>
    <div class="stat-label">Subdomains</div>
  </div>
</div>

<div class="content">

  <!-- Vulnerabilities -->
  <div class="section">
    <div class="section-title"><span class="icon">⚠</span> All Vulnerabilities ({len(all_vulns)} total)</div>
    <div class="card">
      <table class="vuln-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Vulnerability</th>
            <th>Detail</th>
            <th>OWASP / Framework</th>
          </tr>
        </thead>
        <tbody>
          {render_vuln_rows(all_vulns)}
        </tbody>
      </table>
    </div>
  </div>

  <!-- Open Ports -->
  <div class="section">
    <div class="section-title"><span class="icon">🔌</span> Open Ports ({len(port_results)})</div>
    <div class="card" style="padding:0">
      {render_ports_table(port_results)}
    </div>
  </div>

  <!-- HTTP Analysis -->
  {"" if not http_results.get("reachable") else f'''
  <div class="section">
    <div class="section-title"><span class="icon">🌐</span> HTTP/Web Analysis</div>
    <div class="http-grid">
      <div class="http-item">
        <div class="http-item-title">Server Information</div>
        {("".join(f'<div style="font-size:13px;color:#9ca3af;margin:2px 0"><span style="color:#60a5fa">{k}:</span> {v}</div>' for k,v in (http_results.get("server_info") or {}).items())) or '<span style="color:#6b7280;font-size:13px">No server headers disclosed ✓</span>'}
      </div>
      <div class="http-item">
        <div class="http-item-title">Response</div>
        <div style="font-size:13px;color:#34d399">Status: HTTP {http_results.get("status_code","—")}</div>
        <div style="font-size:13px;color:#9ca3af">Final URL: {http_results.get("final_url","—")[:60]}</div>
        {"<div style='font-size:13px;color:#f97316'>Redirects: " + " → ".join(str(r) for r in http_results.get("redirect_chain",[])) + "</div>" if http_results.get("redirect_chain") else ""}
      </div>
      <div class="http-item">
        <div class="http-item-title">Security Headers Missing ({len(http_results.get("missing_headers",[]))})</div>
        {"".join(f'<div style="font-size:13px;color:#f87171;margin:2px 0">✗ {h["header"]}</div>' for h in http_results.get("missing_headers",[])) or '<span style="color:#22c55e;font-size:13px">All headers present ✓</span>'}
      </div>
      <div class="http-item">
        <div class="http-item-title">Security Headers Present ({len(http_results.get("present_headers",[]))})</div>
        {"".join(f'<div style="font-size:13px;color:#34d399;margin:2px 0">✓ {h["header"]}</div>' for h in http_results.get("present_headers",[])) or '<span style="color:#6b7280;font-size:13px">None</span>'}
      </div>
      <div class="http-item">
        <div class="http-item-title">Cookie Analysis ({len(http_results.get("cookies",[]))} cookies)</div>
        {"".join(f'''<div style="font-size:12px;margin:4px 0;color:#9ca3af">
          <strong style="color:#e5e7eb">{c["name"]}</strong>
          {"".join(f' <span style="color:#f87171;font-size:11px">[{i}]</span>' for i in c.get("issues",[]))}
        </div>''' for c in http_results.get("cookies",[])) or '<span style="color:#6b7280;font-size:13px">No cookies detected</span>'}
      </div>
      <div class="http-item">
        <div class="http-item-title">Sensitive Files Exposed ({len(http_results.get("sensitive_files",[]))})</div>
        {"".join(f'<div style="font-size:12px;color:#f87171;margin:2px 0;font-family:monospace">{f["path"]} <span style="color:#6b7280">[{f["severity"]}]</span></div>' for f in http_results.get("sensitive_files",[])) or '<span style="color:#22c55e;font-size:13px">No sensitive files found ✓</span>'}
      </div>
    </div>
  </div>
  '''}

  <!-- DNS Recon -->
  {"" if not dns_results else f'''
  <div class="section">
    <div class="section-title"><span class="icon">🔍</span> DNS Reconnaissance</div>
    <div class="card" style="padding:20px">
      {render_dns_section(dns_results)}
    </div>
  </div>
  '''}

  <!-- SSL/TLS -->
  {"" if not http_results.get("ssl") else f'''
  <div class="section">
    <div class="section-title"><span class="icon">🔒</span> SSL/TLS Analysis</div>
    <div class="card" style="padding:20px">
      {("".join(f'<div style="font-size:13px;margin:4px 0;color:#9ca3af"><span style="color:#60a5fa;font-weight:600">{k.replace("_"," ").title()}:</span> {str(v)[:100]}</div>' for k,v in (http_results.get("ssl") or {}).items() if k != "issues"))}
      {("".join(f'<div style="color:#f87171;font-size:13px;margin:4px 0">⚠ {i}</div>' for i in (http_results.get("ssl") or {}).get("issues",[]))) or "<div style='color:#22c55e;font-size:13px;margin-top:8px'>✓ No SSL issues detected</div>"}
    </div>
  </div>
  '''}

  <!-- Disclaimer -->
  <div class="section">
    <div class="card" style="padding:20px;border-color:#1f2937;background:#0d1117">
      <div style="font-size:12px;color:#4b5563;line-height:1.8">
        <strong style="color:#6b7280">⚖ Legal Disclaimer:</strong> This report was generated by VulnScanner for authorised security assessment purposes only.
        Scanning systems without explicit written permission is illegal under the Computer Fraud and Abuse Act (CFAA), 
        Computer Misuse Act (CMA), and equivalent laws worldwide. This tool is intended for use in educational 
        environments, authorised penetration tests, and security research on systems you own or have permission to test.
        The authors accept no liability for misuse.
      </div>
    </div>
  </div>

</div>

<div class="footer">
  VulnScanner v1.0 &nbsp;|&nbsp; Automated Vulnerability Assessment Tool &nbsp;|&nbsp; For Authorised Use Only
</div>

</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    return output_path


def generate_json_report(scan_data: Dict, output_path: str) -> str:
    """Export scan results as JSON."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(scan_data, f, indent=2, default=str)
    return output_path
