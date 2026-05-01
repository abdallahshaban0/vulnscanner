"""
Vulnerability Analysis Module
================================
Analyses scan results and maps findings to:
  - Known CVEs for common service versions
  - OWASP Top 10 categories
  - CWE references
  - CVSS-like severity scoring
  - Remediation recommendations
"""

from typing import Dict, List

# Known vulnerable service versions mapped to CVEs
# Format: {service: {version_keyword: [CVE list]}}
KNOWN_VULNERABLE_VERSIONS = {
    "Apache": {
        "2.4.49": ["CVE-2021-41773 (Path Traversal / RCE - CVSS 9.8)", "CVE-2021-42013"],
        "2.4.50": ["CVE-2021-42013 (Path Traversal / RCE - CVSS 9.8)"],
        "2.2":    ["CVE-2017-7679 (Buffer Overflow)", "CVE-2017-9798 (Optionsbleed)"],
        "2.0":    ["CVE-2006-20001 (DoS)", "Multiple critical vulnerabilities - EOL"],
    },
    "nginx": {
        "1.14": ["CVE-2019-9511 (HTTP/2 DoS)", "CVE-2019-9513"],
        "1.12": ["CVE-2017-7529 (Off-by-One - Info Disclosure)"],
        "1.10": ["Multiple vulnerabilities - EOL version"],
        "1.6":  ["Multiple vulnerabilities - EOL version"],
    },
    "OpenSSH": {
        "7.4": ["CVE-2017-15906 (File creation)", "CVE-2018-15473 (Username Enumeration)"],
        "7.2": ["CVE-2016-6515 (DoS)", "CVE-2016-10009"],
        "6":   ["CVE-2016-0777 (Info Disclosure)", "CVE-2015-5600"],
        "5":   ["CVE-2010-4478 (Auth Bypass - CRITICAL)", "Multiple critical CVEs"],
    },
    "vsftpd": {
        "2.3.4": ["CVE-2011-2523 (Backdoor RCE - CVSS 10.0) - Famous backdoor!"],
        "2.0":   ["CVE-2011-0762 (DoS)"],
    },
    "ProFTPD": {
        "1.3.5": ["CVE-2015-3306 (Unauthenticated File Copy - CVSS 10.0)"],
        "1.3.3": ["CVE-2010-4221 (Stack Overflow - CVSS 10.0)"],
    },
    "IIS": {
        "6.0": ["CVE-2017-7269 (Buffer Overflow RCE - CVSS 10.0)", "EOL - No more patches"],
        "5.0": ["Multiple critical CVEs - EOL"],
        "5.1": ["CVE-2003-0109", "EOL - No more patches"],
    },
    "PHP": {
        "5.": ["Multiple critical CVEs - EOL since Dec 2018"],
        "7.0": ["Multiple critical CVEs - EOL since Jan 2019"],
        "7.1": ["Multiple critical CVEs - EOL since Dec 2019"],
        "7.2": ["Multiple critical CVEs - EOL since Nov 2020"],
    },
    "MySQL": {
        "5.0": ["CVE-2016-6662 (RCE - CVSS 9.8) - EOL"],
        "5.1": ["Multiple CVEs - EOL"],
        "5.5": ["CVE-2016-6662", "EOL since Dec 2018"],
    },
    "Tomcat": {
        "9.0.0": ["CVE-2019-0232 (CGI RCE on Windows - CVSS 8.1)"],
        "8.5.": ["CVE-2020-1938 (GhostCat - File Read - CVSS 9.8)"],
        "8.0":  ["CVE-2020-1938 (GhostCat)", "EOL"],
        "7.":   ["CVE-2017-12617 (JSP Upload RCE)", "EOL"],
        "6.":   ["Multiple critical CVEs - EOL"],
    },
    "WordPress": {
        "wp-login": ["Exposed admin login - brute-force risk"],
        "xmlrpc":   ["XML-RPC enabled - brute-force amplification risk (CVE-2015-3146)"],
    },
    "Elasticsearch": {
        "": ["CVE-2014-3120 (Unauthenticated RCE via MVEL)", "CVE-2015-1427 (Groovy RCE)"],
    },
    "MongoDB": {
        "": ["Default config allows unauthenticated access on port 27017"],
    },
    "Redis": {
        "": ["Default config has no auth - CVE-2015-4335 (Eval RCE)"],
    },
}

# OWASP Top 10 2021 mapping
OWASP_MAPPING = {
    "MISSING_SECURITY_HEADER": "A05:2021 - Security Misconfiguration",
    "SERVER_VERSION_DISCLOSURE": "A05:2021 - Security Misconfiguration",
    "INSECURE_COOKIE": "A02:2021 - Cryptographic Failures",
    "NO_HTTPS": "A02:2021 - Cryptographic Failures",
    "WEAK_TLS_PROTOCOL": "A02:2021 - Cryptographic Failures",
    "WEAK_CIPHER": "A02:2021 - Cryptographic Failures",
    "INVALID_SSL_CERT": "A02:2021 - Cryptographic Failures",
    "SENSITIVE_FILE_EXPOSED": "A05:2021 - Security Misconfiguration",
    "DANGEROUS_HTTP_METHOD": "A05:2021 - Security Misconfiguration",
    "ZONE_TRANSFER_ENABLED": "A05:2021 - Security Misconfiguration",
    "MISSING_SPF_RECORD": "A05:2021 - Security Misconfiguration",
    "MISSING_DMARC": "A05:2021 - Security Misconfiguration",
    "WEAK_DMARC_POLICY": "A05:2021 - Security Misconfiguration",
    "HIGH_RISK_PORT_OPEN": "A05:2021 - Security Misconfiguration",
    "TELNET_EXPOSED": "A02:2021 - Cryptographic Failures",
    "FTP_EXPOSED": "A02:2021 - Cryptographic Failures",
    "VULNERABLE_SERVICE_VERSION": "A06:2021 - Vulnerable and Outdated Components",
    "NO_HTTPS_REDIRECT": "A02:2021 - Cryptographic Failures",
    "CONNECTION_FAILED": "INFO",
    "TIMEOUT": "INFO",
}

# CWE references
CWE_MAPPING = {
    "MISSING_SECURITY_HEADER": "CWE-693: Protection Mechanism Failure",
    "INSECURE_COOKIE": "CWE-614: Sensitive Cookie Without Secure Attribute",
    "NO_HTTPS": "CWE-319: Cleartext Transmission of Sensitive Information",
    "WEAK_TLS_PROTOCOL": "CWE-326: Inadequate Encryption Strength",
    "WEAK_CIPHER": "CWE-326: Inadequate Encryption Strength",
    "SENSITIVE_FILE_EXPOSED": "CWE-538: File and Directory Information Exposure",
    "ZONE_TRANSFER_ENABLED": "CWE-264: Permissions, Privileges, and Access Controls",
    "SERVER_VERSION_DISCLOSURE": "CWE-200: Exposure of Sensitive Information",
    "VULNERABLE_SERVICE_VERSION": "CWE-1104: Use of Unmaintained Third Party Components",
}


def analyse_port_vulnerabilities(open_ports: List[Dict]) -> List[Dict]:
    """Analyse open ports for known vulnerabilities and misconfigurations."""
    vulns = []

    for port_info in open_ports:
        port = port_info["port"]
        service = port_info.get("service", "unknown")
        banner = port_info.get("banner", "") or ""

        # High-risk port checks
        if port == 23:
            vulns.append({
                "type": "TELNET_EXPOSED",
                "severity": "CRITICAL",
                "port": port,
                "detail": (
                    "Telnet (port 23) is open. Telnet transmits all data including "
                    "credentials in CLEARTEXT. Replace with SSH immediately."
                ),
                "owasp": OWASP_MAPPING["TELNET_EXPOSED"],
                "cwe": "CWE-319",
                "recommendation": "Disable Telnet. Use SSH (port 22) with key-based auth.",
            })

        elif port == 21:
            vulns.append({
                "type": "FTP_EXPOSED",
                "severity": "HIGH",
                "port": port,
                "detail": (
                    "FTP (port 21) is open. FTP transmits credentials in cleartext. "
                    "Check if anonymous login is enabled."
                ),
                "owasp": OWASP_MAPPING["FTP_EXPOSED"],
                "cwe": "CWE-319",
                "recommendation": "Replace FTP with SFTP or FTPS. Disable anonymous FTP.",
            })

        elif port == 445:
            vulns.append({
                "type": "SMB_EXPOSED",
                "severity": "HIGH",
                "port": port,
                "detail": (
                    "SMB (port 445) is exposed. If unpatched, may be vulnerable to "
                    "EternalBlue (MS17-010 / CVE-2017-0144) used by WannaCry ransomware."
                ),
                "owasp": "A06:2021 - Vulnerable and Outdated Components",
                "cwe": "CWE-119",
                "recommendation": "Apply MS17-010 patch. Block SMB at perimeter. Disable SMBv1.",
            })

        elif port == 3389:
            vulns.append({
                "type": "RDP_EXPOSED",
                "severity": "HIGH",
                "port": port,
                "detail": (
                    "RDP (port 3389) is publicly exposed. May be vulnerable to BlueKeep "
                    "(CVE-2019-0708) or DejaBlue. High brute-force risk."
                ),
                "owasp": "A05:2021 - Security Misconfiguration",
                "cwe": "CWE-284",
                "recommendation": "Restrict RDP to VPN/trusted IPs. Enable NLA. Apply all patches.",
            })

        elif port == 5900:
            vulns.append({
                "type": "VNC_EXPOSED",
                "severity": "HIGH",
                "port": port,
                "detail": "VNC (port 5900) is exposed. Often has weak/no authentication.",
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "cwe": "CWE-287",
                "recommendation": "Restrict VNC to localhost or VPN only. Use strong password.",
            })

        elif port in (6379,):
            vulns.append({
                "type": "REDIS_EXPOSED",
                "severity": "CRITICAL",
                "port": port,
                "detail": (
                    "Redis (port 6379) is publicly exposed. Default Redis has no "
                    "authentication. Allows unauthenticated data access and potential RCE."
                ),
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "cwe": "CWE-306",
                "recommendation": "Bind Redis to 127.0.0.1. Enable requirepass. Use firewalls.",
            })

        elif port in (27017, 27018):
            vulns.append({
                "type": "MONGODB_EXPOSED",
                "severity": "CRITICAL",
                "port": port,
                "detail": (
                    "MongoDB is publicly accessible. Default MongoDB config has no auth. "
                    "Billions of records have been leaked via exposed MongoDB instances."
                ),
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "cwe": "CWE-306",
                "recommendation": "Enable MongoDB authentication. Bind to 127.0.0.1. Use firewalls.",
            })

        elif port == 9200:
            vulns.append({
                "type": "ELASTICSEARCH_EXPOSED",
                "severity": "CRITICAL",
                "port": port,
                "detail": (
                    "Elasticsearch is publicly accessible. Allows unauthenticated data read/write. "
                    "Responsible for numerous large-scale data breaches."
                ),
                "owasp": "A07:2021 - Identification and Authentication Failures",
                "cwe": "CWE-306",
                "recommendation": "Enable X-Pack security. Bind to localhost. Use firewalls.",
            })

        elif port in (1433,):
            vulns.append({
                "type": "MSSQL_EXPOSED",
                "severity": "HIGH",
                "port": port,
                "detail": "MSSQL Server is publicly exposed. High risk of brute-force attacks.",
                "owasp": "A05:2021 - Security Misconfiguration",
                "cwe": "CWE-284",
                "recommendation": "Restrict MSSQL to trusted IPs. Disable SA account. Use Windows Auth.",
            })

        elif port == 3306:
            vulns.append({
                "type": "MYSQL_EXPOSED",
                "severity": "HIGH",
                "port": port,
                "detail": "MySQL is publicly exposed. High risk of brute-force and data theft.",
                "owasp": "A05:2021 - Security Misconfiguration",
                "cwe": "CWE-284",
                "recommendation": "Bind MySQL to localhost. Use firewall rules. Disable remote root login.",
            })

        # Banner-based version detection
        if banner:
            version_vulns = _check_banner_vulnerabilities(banner, port)
            vulns.extend(version_vulns)

    return vulns


def _check_banner_vulnerabilities(banner: str, port: int) -> List[Dict]:
    """Check service banners against known vulnerable versions."""
    vulns = []
    banner_lower = banner.lower()

    for service, versions in KNOWN_VULNERABLE_VERSIONS.items():
        if service.lower() in banner_lower:
            for version_key, cves in versions.items():
                if version_key and version_key in banner:
                    for cve in cves:
                        vulns.append({
                            "type": "VULNERABLE_SERVICE_VERSION",
                            "severity": "CRITICAL" if "10.0" in cve or "RCE" in cve else "HIGH",
                            "port": port,
                            "detail": f"Vulnerable version detected in banner: {service} {version_key} — {cve}",
                            "owasp": OWASP_MAPPING["VULNERABLE_SERVICE_VERSION"],
                            "cwe": CWE_MAPPING.get("VULNERABLE_SERVICE_VERSION", ""),
                            "banner": banner[:200],
                            "recommendation": f"Update {service} to the latest stable version immediately.",
                        })
    return vulns


def calculate_risk_score(all_vulnerabilities: List[Dict]) -> Dict:
    """Calculate an overall risk score from 0-100."""
    weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}
    
    score = 0
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    
    for vuln in all_vulnerabilities:
        sev = vuln.get("severity", "INFO")
        counts[sev] = counts.get(sev, 0) + 1
        score += weights.get(sev, 0)
    
    score = min(score, 100)
    
    if score >= 75:
        rating = "CRITICAL"
        color = "🔴"
    elif score >= 50:
        rating = "HIGH"
        color = "🟠"
    elif score >= 25:
        rating = "MEDIUM"
        color = "🟡"
    elif score > 0:
        rating = "LOW"
        color = "🟢"
    else:
        rating = "SECURE"
        color = "✅"
    
    return {
        "score": score,
        "rating": rating,
        "color": color,
        "counts": counts,
    }


def enrich_vulnerabilities(vulns: List[Dict]) -> List[Dict]:
    """Add OWASP and CWE mappings to vulnerabilities that don't have them."""
    for v in vulns:
        vtype = v.get("type", "")
        if "owasp" not in v:
            v["owasp"] = OWASP_MAPPING.get(vtype, "Unknown")
        if "cwe" not in v:
            v["cwe"] = CWE_MAPPING.get(vtype, "")
    return vulns


def get_remediation_priority(vulns: List[Dict]) -> List[Dict]:
    """Sort vulnerabilities by priority for remediation."""
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return sorted(vulns, key=lambda v: order.get(v.get("severity", "INFO"), 4))
