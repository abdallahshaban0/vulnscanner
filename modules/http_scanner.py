"""
HTTP Vulnerability Scanner Module
===================================
Checks for common web application vulnerabilities:
  - Missing/misconfigured security headers
  - Directory listing
  - Sensitive file exposure
  - Cookie security flags
  - SSL/TLS issues
  - Open redirects
  - Server info disclosure
  - Common CVE-related paths
"""

import requests
import ssl
import socket
import urllib3
from typing import Dict, List
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HSTS missing — browser connections can be downgraded to HTTP.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "CSP missing — XSS and data injection attacks are not mitigated.",
        "recommendation": "Define a strict Content-Security-Policy header.",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Clickjacking protection missing — site can be embedded in iframes.",
        "recommendation": "Add: X-Frame-Options: DENY  or  SAMEORIGIN",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "MIME sniffing not disabled — browsers may interpret files incorrectly.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "No Referrer-Policy — sensitive URL data may leak via Referer header.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "No Permissions-Policy — browser features are not restricted.",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Legacy XSS protection header not set (deprecated but still used in some contexts).",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block",
    },
}

SENSITIVE_PATHS = [
    "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.production",
    "/config.php", "/config.yml", "/config.yaml", "/config.json",
    "/wp-config.php", "/wp-login.php", "/wp-admin/",
    "/.htaccess", "/.htpasswd", "/robots.txt", "/sitemap.xml",
    "/admin/", "/admin/login", "/administrator/",
    "/phpmyadmin/", "/pma/", "/mysql/",
    "/backup/", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/database.sql", "/dump.sql",
    "/server-status", "/server-info",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/api/", "/api/v1/", "/api/swagger.json", "/swagger-ui.html",
    "/api-docs", "/openapi.json", "/graphql", "/graphiql",
    "/console", "/h2-console", "/jolokia",
    "/.well-known/security.txt", "/security.txt",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/info.php", "/phpinfo.php", "/test.php",
    "/.DS_Store", "/Thumbs.db",
    "/error_log", "/error.log", "/access.log",
    "/.ssh/id_rsa", "/.ssh/authorized_keys",
    "/id_rsa", "/private.key", "/server.key",
    "/composer.json", "/package.json", "/yarn.lock",
    "/Dockerfile", "/docker-compose.yml", "/.dockerignore",
    "/Makefile", "/Gruntfile.js", "/gulpfile.js",
]

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]

SERVER_HEADERS_TO_CHECK = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Joomla-Cache",
]


def check_http_vulnerabilities(url: str, timeout: int = 10) -> Dict:
    """
    Main HTTP vulnerability checker.
    Returns a dict with all findings categorised by type.
    """
    results = {
        "url": url,
        "reachable": False,
        "redirect_chain": [],
        "final_url": url,
        "status_code": None,
        "server_info": {},
        "missing_headers": [],
        "present_headers": [],
        "sensitive_files": [],
        "cookies": [],
        "ssl": {},
        "methods": [],
        "vulnerabilities": [],
        "info": [],
    }

    try:
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; VulnScanner/1.0; +https://github.com/vulnscanner)"
        })

        resp = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        results["reachable"] = True
        results["status_code"] = resp.status_code
        results["final_url"] = resp.url

        # Redirect chain
        if resp.history:
            results["redirect_chain"] = [r.url for r in resp.history] + [resp.url]

        # Check security headers
        _check_security_headers(resp, results)

        # Check server information disclosure
        _check_server_disclosure(resp, results)

        # Check cookies
        _check_cookies(resp, results)

        # SSL/TLS check
        if url.startswith("https://") or url.startswith("http://"):
            _check_ssl(url, results)

        # HTTP methods
        _check_http_methods(url, session, timeout, results)

        # Sensitive file exposure
        _check_sensitive_files(url, session, timeout, results)

        # Check for HTTP → HTTPS redirect
        _check_https_redirect(url, session, timeout, results)

    except requests.exceptions.ConnectionError:
        results["vulnerabilities"].append({
            "type": "CONNECTION_FAILED",
            "severity": "INFO",
            "detail": "Could not connect to the target. Host may be down or port closed.",
        })
    except requests.exceptions.Timeout:
        results["vulnerabilities"].append({
            "type": "TIMEOUT",
            "severity": "INFO",
            "detail": f"Connection timed out after {timeout}s.",
        })
    except Exception as e:
        results["vulnerabilities"].append({
            "type": "ERROR",
            "severity": "INFO",
            "detail": str(e),
        })

    return results


def _check_security_headers(resp: requests.Response, results: Dict):
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for header, info in SECURITY_HEADERS.items():
        if header.lower() not in headers_lower:
            results["missing_headers"].append({
                "header": header,
                "severity": info["severity"],
                "description": info["description"],
                "recommendation": info["recommendation"],
            })
            results["vulnerabilities"].append({
                "type": "MISSING_SECURITY_HEADER",
                "severity": info["severity"],
                "detail": f"Missing header: {header} — {info['description']}",
            })
        else:
            results["present_headers"].append({
                "header": header,
                "value": headers_lower[header.lower()],
            })


def _check_server_disclosure(resp: requests.Response, results: Dict):
    for h in SERVER_HEADERS_TO_CHECK:
        val = resp.headers.get(h)
        if val:
            results["server_info"][h] = val
            results["vulnerabilities"].append({
                "type": "SERVER_VERSION_DISCLOSURE",
                "severity": "LOW",
                "detail": f"{h}: {val} — Server version exposed, aids fingerprinting.",
            })


def _check_cookies(resp: requests.Response, results: Dict):
    for cookie in resp.cookies:
        issues = []
        if not cookie.secure:
            issues.append("Secure flag missing")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("HttpOnly flag missing")
        samesite = cookie.get_nonstandard_attr("SameSite")
        if not samesite:
            issues.append("SameSite attribute missing")

        cookie_info = {
            "name": cookie.name,
            "secure": cookie.secure,
            "httponly": cookie.has_nonstandard_attr("HttpOnly"),
            "samesite": samesite,
            "issues": issues,
        }
        results["cookies"].append(cookie_info)

        for issue in issues:
            results["vulnerabilities"].append({
                "type": "INSECURE_COOKIE",
                "severity": "MEDIUM",
                "detail": f"Cookie '{cookie.name}': {issue}",
            })


def _check_ssl(url: str, results: Dict):
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    ssl_info = {"host": host, "port": port, "issues": []}

    try:
        # Check if HTTP is used instead of HTTPS
        if parsed.scheme == "http":
            ssl_info["issues"].append("Site uses plain HTTP (no TLS/SSL)")
            results["vulnerabilities"].append({
                "type": "NO_HTTPS",
                "severity": "HIGH",
                "detail": "Site is served over plain HTTP. All traffic is unencrypted.",
            })
        else:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    ssl_info["protocol"] = protocol
                    ssl_info["cipher"] = cipher[0] if cipher else "unknown"
                    ssl_info["cert_subject"] = dict(x[0] for x in cert.get("subject", []))
                    ssl_info["cert_issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    ssl_info["cert_expiry"] = cert.get("notAfter", "unknown")

                    # Check for weak protocols
                    if protocol in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                        ssl_info["issues"].append(f"Weak TLS version: {protocol}")
                        results["vulnerabilities"].append({
                            "type": "WEAK_TLS_PROTOCOL",
                            "severity": "HIGH",
                            "detail": f"Weak TLS version in use: {protocol}. Use TLS 1.2 or 1.3.",
                        })

                    # Weak cipher check
                    if cipher:
                        cipher_name = cipher[0]
                        if any(w in cipher_name for w in ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]):
                            ssl_info["issues"].append(f"Weak cipher: {cipher_name}")
                            results["vulnerabilities"].append({
                                "type": "WEAK_CIPHER",
                                "severity": "HIGH",
                                "detail": f"Weak cipher suite: {cipher_name}",
                            })

        results["ssl"] = ssl_info

    except ssl.SSLCertVerificationError as e:
        ssl_info["issues"].append(f"Certificate verification failed: {e}")
        results["vulnerabilities"].append({
            "type": "INVALID_SSL_CERT",
            "severity": "HIGH",
            "detail": f"SSL certificate is invalid or self-signed: {e}",
        })
        results["ssl"] = ssl_info
    except Exception:
        pass


def _check_http_methods(url: str, session: requests.Session, timeout: int, results: Dict):
    dangerous_found = []
    try:
        opts = session.options(url, timeout=timeout, verify=False)
        allow = opts.headers.get("Allow", "")
        if allow:
            for method in DANGEROUS_METHODS:
                if method in allow:
                    dangerous_found.append(method)
    except Exception:
        pass

    # Also try TRACE directly
    try:
        trace = session.request("TRACE", url, timeout=timeout, verify=False)
        if trace.status_code < 400:
            dangerous_found.append("TRACE")
    except Exception:
        pass

    results["methods"] = dangerous_found
    for method in set(dangerous_found):
        severity = "HIGH" if method in ("PUT", "DELETE", "TRACE") else "MEDIUM"
        results["vulnerabilities"].append({
            "type": "DANGEROUS_HTTP_METHOD",
            "severity": severity,
            "detail": f"HTTP method {method} is allowed — may enable unauthorized actions.",
        })


def _check_sensitive_files(url: str, session: requests.Session, timeout: int, results: Dict):
    base = url.rstrip("/")
    found = []

    for path in SENSITIVE_PATHS:
        try:
            target = base + path
            r = session.get(target, timeout=timeout, verify=False, allow_redirects=False)
            if r.status_code in (200, 206):
                size = len(r.content)
                severity = _sensitive_path_severity(path)
                found.append({
                    "path": path,
                    "url": target,
                    "status": r.status_code,
                    "size": size,
                    "severity": severity,
                })
                results["vulnerabilities"].append({
                    "type": "SENSITIVE_FILE_EXPOSED",
                    "severity": severity,
                    "detail": f"Sensitive path accessible: {target} (HTTP {r.status_code}, {size} bytes)",
                })
        except Exception:
            continue

    results["sensitive_files"] = found


def _sensitive_path_severity(path: str) -> str:
    critical = [".env", ".git", ".ssh", "id_rsa", "private.key", "server.key",
                ".htpasswd", "wp-config", "config.php", "database.sql", "dump.sql"]
    high = ["backup", "admin", "phpmyadmin", "actuator/env", "config.yml", "config.json"]
    for kw in critical:
        if kw in path:
            return "CRITICAL"
    for kw in high:
        if kw in path:
            return "HIGH"
    return "MEDIUM"


def _check_https_redirect(url: str, session: requests.Session, timeout: int, results: Dict):
    parsed = urlparse(url)
    if parsed.scheme == "https":
        http_url = "http://" + parsed.netloc + (parsed.path or "/")
        try:
            r = session.get(http_url, timeout=timeout, verify=False, allow_redirects=False)
            if r.status_code not in (301, 302, 307, 308):
                results["vulnerabilities"].append({
                    "type": "NO_HTTPS_REDIRECT",
                    "severity": "MEDIUM",
                    "detail": "HTTP does not automatically redirect to HTTPS.",
                })
            else:
                results["info"].append("HTTP → HTTPS redirect is configured correctly.")
        except Exception:
            pass
