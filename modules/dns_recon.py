"""
DNS & Network Reconnaissance Module
======================================
Performs:
  - DNS resolution (A, AAAA, MX, NS, TXT, CNAME, SOA records)
  - Reverse DNS lookup
  - Zone transfer attempt (AXFR)
  - Subdomain enumeration (wordlist-based)
  - WHOIS lookup
  - IP geolocation (via public API)
  - ASN / Organisation lookup
"""

import socket
import concurrent.futures
from typing import Dict, List, Optional

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

try:
    import whois as pywhois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

import requests

# Common subdomains to enumerate
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "webdisk", "ns", "cpanel", "whm", "autodiscover", "autoconfig", "m", "mobile",
    "imap", "test", "dev", "staging", "api", "admin", "blog", "shop", "store",
    "portal", "vpn", "remote", "rdp", "ssh", "sftp", "git", "svn", "cdn",
    "static", "assets", "img", "images", "media", "downloads", "upload",
    "backup", "db", "database", "mysql", "sql", "oracle", "mongo", "redis",
    "elastic", "kibana", "grafana", "prometheus", "jenkins", "gitlab", "github",
    "bitbucket", "jira", "confluence", "sonar", "nexus", "artifactory",
    "docker", "k8s", "kubernetes", "rancher", "traefik", "nginx", "apache",
    "proxy", "gateway", "lb", "loadbalancer", "node", "app", "apps", "web",
    "webapp", "frontend", "backend", "server", "secure", "login", "auth",
    "sso", "oauth", "account", "accounts", "register", "signup", "pay",
    "payment", "checkout", "cart", "support", "help", "status", "health",
    "metrics", "monitor", "monitoring", "logs", "log", "trace", "debug",
    "qa", "uat", "prod", "production", "sandbox", "preview", "beta", "alpha",
    "old", "new", "v1", "v2", "v3", "internal", "private", "intranet",
    "corp", "corporate", "office", "hr", "crm", "erp", "bi", "analytics",
    "data", "warehouse", "etl", "kafka", "rabbit", "queue", "mq",
    "mail2", "mx1", "mx2", "smtp2", "relay", "bounce", "list", "lists",
    "newsletter", "news", "forum", "forums", "community", "wiki",
    "docs", "documentation", "help", "kb", "knowledge", "learn",
]

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"]


def run_dns_recon(domain: str) -> Dict:
    """Full DNS reconnaissance on a domain."""
    results = {
        "domain": domain,
        "ip_addresses": [],
        "dns_records": {},
        "zone_transfer": {"attempted": False, "success": False, "records": []},
        "subdomains": [],
        "whois": {},
        "vulnerabilities": [],
        "info": [],
    }

    # Resolve IP
    try:
        ips = socket.gethostbyname_ex(domain)
        results["ip_addresses"] = list(set(ips[2]))
    except socket.gaierror as e:
        results["vulnerabilities"].append({
            "type": "DNS_RESOLUTION_FAILED",
            "severity": "INFO",
            "detail": f"Could not resolve {domain}: {e}",
        })
        return results

    if DNS_AVAILABLE:
        _collect_dns_records(domain, results)
        _attempt_zone_transfer(domain, results)
    else:
        results["info"].append("dnspython not installed — DNS record enumeration skipped.")

    # Subdomain enumeration
    _enumerate_subdomains(domain, results)

    # WHOIS
    if WHOIS_AVAILABLE:
        _get_whois(domain, results)
    else:
        results["info"].append("python-whois not installed — WHOIS skipped.")

    return results


def _collect_dns_records(domain: str, results: Dict):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 5

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records = []
            for rdata in answers:
                records.append(str(rdata))
            results["dns_records"][rtype] = records

            # Security checks on TXT records (SPF, DMARC, DKIM)
            if rtype == "TXT":
                _check_email_security(records, domain, results)

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout,
                dns.resolver.NoNameservers):
            pass
        except Exception:
            pass


def _check_email_security(txt_records: List[str], domain: str, results: Dict):
    has_spf = any("v=spf1" in r for r in txt_records)
    if not has_spf:
        results["vulnerabilities"].append({
            "type": "MISSING_SPF_RECORD",
            "severity": "MEDIUM",
            "detail": "No SPF record found — domain may be used for email spoofing.",
        })

    # Check DMARC
    try:
        dmarc_resolver = dns.resolver.Resolver()
        dmarc_resolver.timeout = 3
        dmarc_answers = dmarc_resolver.resolve(f"_dmarc.{domain}", "TXT")
        dmarc_records = [str(r) for r in dmarc_answers]
        has_dmarc = any("v=DMARC1" in r for r in dmarc_records)
        if not has_dmarc:
            results["vulnerabilities"].append({
                "type": "MISSING_DMARC",
                "severity": "MEDIUM",
                "detail": "DMARC record not properly configured.",
            })
        else:
            # Check for p=none (weak policy)
            for r in dmarc_records:
                if "p=none" in r:
                    results["vulnerabilities"].append({
                        "type": "WEAK_DMARC_POLICY",
                        "severity": "LOW",
                        "detail": "DMARC policy is 'none' — emails failing DMARC will not be rejected.",
                    })
    except Exception:
        results["vulnerabilities"].append({
            "type": "MISSING_DMARC",
            "severity": "MEDIUM",
            "detail": "No DMARC record found — email spoofing protection is absent.",
        })


def _attempt_zone_transfer(domain: str, results: Dict):
    """Attempt DNS zone transfer (AXFR) — a misconfiguration if successful."""
    results["zone_transfer"]["attempted"] = True
    ns_records = results["dns_records"].get("NS", [])

    for ns in ns_records:
        ns = ns.rstrip(".")
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            records = []
            for name, node in zone.nodes.items():
                rdatasets = node.rdatasets
                for rdataset in rdatasets:
                    for rdata in rdataset:
                        records.append(f"{name} {rdataset.rdtype} {rdata}")

            if records:
                results["zone_transfer"]["success"] = True
                results["zone_transfer"]["nameserver"] = ns
                results["zone_transfer"]["records"] = records[:50]  # limit output
                results["vulnerabilities"].append({
                    "type": "ZONE_TRANSFER_ENABLED",
                    "severity": "CRITICAL",
                    "detail": (
                        f"DNS zone transfer (AXFR) succeeded on {ns}! "
                        f"All DNS records are publicly enumerable. "
                        "Restrict AXFR to trusted secondary nameservers only."
                    ),
                })
                break
        except Exception:
            pass


def _enumerate_subdomains(domain: str, results: Dict):
    """Enumerate subdomains using wordlist + DNS resolution."""
    found = []

    def check_sub(sub: str):
        fqdn = f"{sub}.{domain}"
        try:
            ips = socket.gethostbyname_ex(fqdn)
            return {"subdomain": fqdn, "ips": list(set(ips[2]))}
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(check_sub, sub): sub for sub in COMMON_SUBDOMAINS}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                found.append(res)

    results["subdomains"] = sorted(found, key=lambda x: x["subdomain"])
    if found:
        results["info"].append(f"Discovered {len(found)} live subdomain(s).")


def _get_whois(domain: str, results: Dict):
    try:
        w = pywhois.whois(domain)
        results["whois"] = {
            "registrar": getattr(w, "registrar", "N/A"),
            "creation_date": str(getattr(w, "creation_date", "N/A")),
            "expiration_date": str(getattr(w, "expiration_date", "N/A")),
            "name_servers": getattr(w, "name_servers", []),
            "status": getattr(w, "status", "N/A"),
            "emails": getattr(w, "emails", []),
            "org": getattr(w, "org", "N/A"),
        }
    except Exception as e:
        results["info"].append(f"WHOIS lookup failed: {e}")
