#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║   ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗  ║
║   ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗ ║
║   ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗║
║   ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚█║
║    ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚║
║     ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ║
║                                                                          ║
║              Automated Vulnerability Scanner v1.0                        ║
║              Educational & Authorised Penetration Testing Only           ║
╚══════════════════════════════════════════════════════════════════════════╝

Usage:
    python scanner.py -t <target> [options]

Examples:
    python scanner.py -t example.com --full
    python scanner.py -t 192.168.1.1 --ports --port-range 1-1024
    python scanner.py -t example.com --http --dns --report html
"""

import argparse
import socket
import sys
import time
import os
from datetime import datetime
from typing import Dict, List

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS = True
except ImportError:
    COLORS = False
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""

# Local module imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from modules.port_scanner import run_port_scan, COMMON_SERVICES
from modules.http_scanner import check_http_vulnerabilities
from modules.dns_recon import run_dns_recon
from modules.vuln_analysis import analyse_port_vulnerabilities, calculate_risk_score, enrich_vulnerabilities, get_remediation_priority
from modules.report_generator import generate_html_report, generate_json_report


# ─────────────────────────────────────────────
# Output helpers
# ─────────────────────────────────────────────

def banner():
    print(f"""
{Fore.CYAN}{Style.BRIGHT}
╔══════════════════════════════════════════════════════════╗
║  ██╗   ██╗██╗   ██╗██╗     ███╗  ██╗███████╗ ██████╗   ║
║  ██║   ██║██║   ██║██║     ████╗ ██║██╔════╝██╔════╝   ║
║  ██║   ██║██║   ██║██║     ██╔██╗██║███████╗██║         ║
║  ╚██╗ ██╔╝██║   ██║██║     ██║╚████║╚════██║██║         ║
║   ╚████╔╝ ╚██████╔╝███████╗██║ ╚███║███████║╚██████╗   ║
║    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚══╝╚══════╝ ╚═════╝  ║
║                                                          ║
║      Automated Vulnerability Scanner  v1.0               ║
║      For Authorised Penetration Testing Only             ║
╚══════════════════════════════════════════════════════════╝
{Style.RESET_ALL}""")


def section(title: str):
    print(f"\n{Fore.CYAN}{Style.BRIGHT}{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}{Style.RESET_ALL}")


def info(msg: str):
    print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")


def success(msg: str):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def warning(msg: str):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")


def error(msg: str):
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")


def severity_color(sev: str) -> str:
    colors = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.RED,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.GREEN,
        "INFO": Fore.BLUE,
    }
    return colors.get(sev, "")


def print_vuln(v: Dict):
    sev = v.get("severity", "INFO")
    color = severity_color(sev)
    vtype = v.get("type", "").replace("_", " ")
    detail = v.get("detail", "")
    port = f" (port {v['port']})" if v.get("port") else ""
    print(f"  {color}[{sev}]{Style.RESET_ALL} {vtype}{port}")
    print(f"         {Fore.WHITE}{Style.DIM}{detail[:120]}{Style.RESET_ALL}")


# ─────────────────────────────────────────────
# Main scan orchestrator
# ─────────────────────────────────────────────

def run_scan(args) -> Dict:
    start_time = time.time()
    target = args.target.strip()
    scan_data = {
        "target": target,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "modules_run": [],
        "ports": [],
        "http": {},
        "dns": {},
        "all_vulnerabilities": [],
        "risk_score": {},
        "duration": "N/A",
    }

    # ── Resolve target ────────────────────────────────────────
    section("🔍 Target Resolution")
    try:
        ip = socket.gethostbyname(target)
        scan_data["resolved_ip"] = ip
        success(f"Target:  {Fore.CYAN}{target}{Style.RESET_ALL}")
        success(f"IP:      {Fore.CYAN}{ip}{Style.RESET_ALL}")
        success(f"Date:    {scan_data['timestamp']}")
    except socket.gaierror:
        error(f"Cannot resolve {target} — check the hostname.")
        return scan_data

    # ── Port Scan ─────────────────────────────────────────────
    if args.ports or args.full:
        scan_data["modules_run"].append("Port Scan")
        section(f"🔌 Port Scanning ({args.scan_type.upper()})")
        info(f"Scanning {_count_ports(args)} ports with {args.threads} threads...")

        ports = run_port_scan(
            host=ip,
            port_range=args.port_range,
            scan_type=args.scan_type,
            threads=args.threads,
            timeout=args.timeout,
        )
        scan_data["ports"] = ports

        if ports:
            success(f"Found {len(ports)} open port(s):")
            print(f"\n  {'PORT':<8} {'SERVICE':<15} {'RISK':<8} {'BANNER'}")
            print(f"  {'─'*60}")
            for p in ports:
                rc = {"HIGH": Fore.RED, "MEDIUM": Fore.YELLOW, "LOW": Fore.GREEN}.get(p["risk"], "")
                banner_preview = (p.get("banner") or "")[:50]
                print(f"  {Fore.CYAN}{p['port']:<8}{Style.RESET_ALL}"
                      f"{p['service']:<15}"
                      f"{rc}{p['risk']:<8}{Style.RESET_ALL}"
                      f"{Fore.WHITE}{Style.DIM}{banner_preview}{Style.RESET_ALL}")
        else:
            info("No open ports found in the scanned range.")

        # Port-based vulnerability analysis
        port_vulns = analyse_port_vulnerabilities(ports)
        scan_data["all_vulnerabilities"].extend(port_vulns)
        if port_vulns:
            warning(f"Found {len(port_vulns)} port-based vulnerability/risk(s):")
            for v in port_vulns:
                print_vuln(v)

    # ── HTTP Scan ─────────────────────────────────────────────
    if args.http or args.full:
        scan_data["modules_run"].append("HTTP Scanner")
        # Build URLs to test
        urls = []
        if args.url:
            urls = [args.url]
        else:
            urls = [f"https://{target}", f"http://{target}"]

        for url in urls:
            section(f"🌐 HTTP Vulnerability Scan — {url}")
            info(f"Scanning web application at {url} ...")
            http_data = check_http_vulnerabilities(url, timeout=args.timeout * 5)

            if not http_data.get("reachable"):
                warning(f"Could not reach {url} — skipping.")
                continue

            scan_data["http"] = http_data
            success(f"HTTP {http_data['status_code']} — Site is reachable")

            http_vulns = http_data.get("vulnerabilities", [])
            enrich_vulnerabilities(http_vulns)

            if http_vulns:
                warning(f"{len(http_vulns)} web vulnerability/finding(s):")
                for v in sorted(http_vulns, key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4}.get(x.get("severity","INFO"),4)):
                    print_vuln(v)
            else:
                success("No HTTP vulnerabilities detected!")

            scan_data["all_vulnerabilities"].extend(http_vulns)

            # Sensitive files
            sensitive = http_data.get("sensitive_files", [])
            if sensitive:
                warning(f"\n  ⚠  {len(sensitive)} sensitive file(s) exposed:")
                for f in sensitive:
                    color = Fore.RED if f["severity"] in ("CRITICAL","HIGH") else Fore.YELLOW
                    print(f"  {color}  → {f['url']} [{f['severity']}]{Style.RESET_ALL}")

            break  # Use first reachable URL

    # ── DNS Recon ─────────────────────────────────────────────
    if args.dns or args.full:
        scan_data["modules_run"].append("DNS Recon")
        # Strip scheme for DNS
        domain = target.replace("https://","").replace("http://","").split("/")[0]
        section(f"🔍 DNS Reconnaissance — {domain}")
        info("Enumerating DNS records, subdomains, and checking email security ...")

        dns_data = run_dns_recon(domain)
        scan_data["dns"] = dns_data

        ips = dns_data.get("ip_addresses", [])
        if ips:
            success(f"Resolved IPs: {', '.join(ips)}")

        records = dns_data.get("dns_records", {})
        if records:
            success(f"DNS records found: {', '.join(records.keys())}")

        subdomains = dns_data.get("subdomains", [])
        if subdomains:
            warning(f"Subdomains discovered ({len(subdomains)}):")
            for sub in subdomains[:15]:
                print(f"  {Fore.CYAN}  → {sub['subdomain']}{Style.RESET_ALL} {Fore.WHITE}{Style.DIM}({', '.join(sub['ips'])}){Style.RESET_ALL}")
            if len(subdomains) > 15:
                info(f"  ... and {len(subdomains)-15} more (see report)")

        dns_vulns = dns_data.get("vulnerabilities", [])
        enrich_vulnerabilities(dns_vulns)
        scan_data["all_vulnerabilities"].extend(dns_vulns)

        if dns_vulns:
            warning(f"\n  {len(dns_vulns)} DNS finding(s):")
            for v in dns_vulns:
                print_vuln(v)

    # ── Risk Scoring ──────────────────────────────────────────
    section("📊 Risk Assessment")
    all_vulns = get_remediation_priority(scan_data["all_vulnerabilities"])
    scan_data["all_vulnerabilities"] = all_vulns
    risk = calculate_risk_score(all_vulns)
    scan_data["risk_score"] = risk

    score = risk["score"]
    rating = risk["rating"]
    counts = risk["counts"]

    color_map = {"CRITICAL": Fore.RED+Style.BRIGHT, "HIGH": Fore.RED, "MEDIUM": Fore.YELLOW, "LOW": Fore.GREEN, "SECURE": Fore.GREEN+Style.BRIGHT}
    rc = color_map.get(rating, "")
    print(f"\n  Risk Score:  {rc}{score}/100  [{rating}]{Style.RESET_ALL}")
    print(f"\n  Critical: {Fore.RED}{counts.get('CRITICAL',0)}{Style.RESET_ALL}  "
          f"High: {Fore.RED}{counts.get('HIGH',0)}{Style.RESET_ALL}  "
          f"Medium: {Fore.YELLOW}{counts.get('MEDIUM',0)}{Style.RESET_ALL}  "
          f"Low: {Fore.GREEN}{counts.get('LOW',0)}{Style.RESET_ALL}")

    # Top 5 priority remediations
    critical_high = [v for v in all_vulns if v.get("severity") in ("CRITICAL","HIGH")]
    if critical_high:
        print(f"\n  {Fore.RED}{Style.BRIGHT}Top Priority Remediations:{Style.RESET_ALL}")
        for i, v in enumerate(critical_high[:5], 1):
            vtype = v.get("type","").replace("_"," ")
            rec = v.get("recommendation","See full report for remediation advice.")
            print(f"  {i}. {Fore.RED}{vtype}{Style.RESET_ALL}")
            print(f"     {Fore.WHITE}{Style.DIM}↳ {rec[:100]}{Style.RESET_ALL}")

    # ── Duration ──────────────────────────────────────────────
    duration = round(time.time() - start_time, 2)
    scan_data["duration"] = f"{duration}s"

    return scan_data


def _count_ports(args) -> str:
    if args.scan_type == "full":
        return "65535"
    elif args.scan_type == "top1000":
        return "~1000"
    elif args.scan_type == "custom" and args.port_range:
        return args.port_range
    else:
        return f"{len(COMMON_SERVICES)} (common)"


# ─────────────────────────────────────────────
# Report output
# ─────────────────────────────────────────────

def save_reports(scan_data: Dict, args):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_safe = scan_data["target"].replace(".", "_").replace("/", "_").replace(":", "_")
    base = f"reports/scan_{target_safe}_{timestamp}"
    os.makedirs("reports", exist_ok=True)

    section("💾 Saving Reports")

    if args.report in ("html", "all"):
        path = f"{base}.html"
        generate_html_report(scan_data, path)
        success(f"HTML report: {Fore.CYAN}{path}{Style.RESET_ALL}")

    if args.report in ("json", "all"):
        path = f"{base}.json"
        generate_json_report(scan_data, path)
        success(f"JSON report: {Fore.CYAN}{path}{Style.RESET_ALL}")

    if args.report == "html":
        return base + ".html"
    return base


# ─────────────────────────────────────────────
# Argument parser
# ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vulnscanner",
        description="Automated Vulnerability Scanner — For Authorised Use Only",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Full scan with HTML report:
    python scanner.py -t example.com --full --report html

  Port scan only (top 1000 ports):
    python scanner.py -t 192.168.1.1 --ports --scan-type top1000

  HTTP + DNS scan:
    python scanner.py -t example.com --http --dns

  Custom port range:
    python scanner.py -t 10.0.0.1 --ports --scan-type custom --port-range 80,443,8080,8443

  Fast scan with JSON output:
    python scanner.py -t example.com --full --threads 200 --report json

Scan Types:
  common    — ~50 well-known ports (fastest)
  top1000   — NMAP top 1000 ports
  custom    — specify --port-range
  full      — all 65535 ports (slowest)
        """,
    )

    parser.add_argument("-t", "--target", required=True, help="Target hostname or IP address")
    parser.add_argument("-u", "--url", help="Specific URL for HTTP scanning (e.g. https://example.com)")

    # Scan modules
    modules = parser.add_argument_group("Scan Modules")
    modules.add_argument("--full", action="store_true", help="Run all scan modules")
    modules.add_argument("--ports", action="store_true", help="Run port scanner")
    modules.add_argument("--http", action="store_true", help="Run HTTP vulnerability scanner")
    modules.add_argument("--dns", action="store_true", help="Run DNS reconnaissance")

    # Port scan options
    port_opts = parser.add_argument_group("Port Scan Options")
    port_opts.add_argument("--scan-type", default="common",
                           choices=["common", "top1000", "full", "custom"],
                           help="Port scan type (default: common)")
    port_opts.add_argument("--port-range", default=None,
                           help="Custom port range: '1-1024' or '80,443,8080'")
    port_opts.add_argument("--threads", type=int, default=100,
                           help="Number of scanning threads (default: 100)")
    port_opts.add_argument("--timeout", type=float, default=1.0,
                           help="Socket timeout in seconds (default: 1.0)")

    # Output options
    output = parser.add_argument_group("Output Options")
    output.add_argument("--report", default="html",
                        choices=["html", "json", "all", "none"],
                        help="Report format (default: html)")
    output.add_argument("--output-dir", default="reports",
                        help="Report output directory (default: reports/)")
    output.add_argument("-q", "--quiet", action="store_true",
                        help="Suppress banner and verbose output")

    return parser


# ─────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.quiet:
        banner()

    # Default to full scan if no module selected
    if not any([args.ports, args.http, args.dns, args.full]):
        warning("No scan module specified — running full scan by default.")
        args.full = True

    # Legal acknowledgement reminder
    print(f"\n{Fore.YELLOW}[⚠] LEGAL NOTICE: Only scan systems you own or have explicit written")
    print(f"    authorisation to test. Unauthorised scanning is illegal.{Style.RESET_ALL}\n")

    try:
        scan_data = run_scan(args)

        if args.report != "none":
            save_reports(scan_data, args)

        total = len(scan_data.get("all_vulnerabilities", []))
        risk = scan_data.get("risk_score", {})

        print(f"\n{Fore.CYAN}{Style.BRIGHT}{'═'*60}")
        print(f"  SCAN COMPLETE — {total} findings — Risk: {risk.get('rating','N/A')} ({risk.get('score',0)}/100)")
        print(f"{'═'*60}{Style.RESET_ALL}\n")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        error(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
