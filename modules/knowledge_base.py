"""
Vulnerability Knowledge Base
==============================
Every vulnerability type gets a human-readable summary, technical explanation,
impact assessment, and step-by-step remediation guide.
"""

VULN_KNOWLEDGE = {
    # ── HTTP Headers ──────────────────────────────────────────────────────────
    "MISSING_SECURITY_HEADER": {
        "summary": "A critical HTTP security header is absent from server responses.",
        "impact": "Without proper security headers, browsers cannot enforce key protections, leaving users exposed to cross-site scripting, clickjacking, protocol downgrade attacks, and data leakage.",
        "fix_steps": [
            "Identify which specific header is missing (HSTS, CSP, X-Frame-Options, etc.).",
            "Add the header to your web server configuration or application middleware.",
            "For Nginx: add inside server {} block in nginx.conf.",
            "For Apache: add inside <VirtualHost> in httpd.conf or .htaccess.",
            "For Node/Express: use the 'helmet' npm package (app.use(helmet())).",
            "For Django: set SECURE_* settings in settings.py.",
            "Test with securityheaders.com after deployment.",
        ],
        "references": ["OWASP Secure Headers Project", "MDN HTTP Security Headers"],
        "owasp": "A05:2021 - Security Misconfiguration",
    },

    "MISSING_HSTS": {
        "summary": "HTTP Strict Transport Security (HSTS) is not configured.",
        "impact": "Browsers may allow HTTP connections, enabling SSL-stripping attacks where an attacker can downgrade your HTTPS site to plain HTTP and intercept all traffic.",
        "fix_steps": [
            "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "Nginx: add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;",
            "Apache: Header always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'",
            "Ensure your entire site and all subdomains serve valid HTTPS before enabling includeSubDomains.",
            "Consider submitting to the HSTS preload list at hstspreload.org for maximum protection.",
        ],
        "references": ["RFC 6797", "OWASP HSTS Cheat Sheet"],
        "owasp": "A02:2021 - Cryptographic Failures",
    },

    "MISSING_CSP": {
        "summary": "Content Security Policy (CSP) header is not set.",
        "impact": "Without CSP, attackers who inject malicious scripts (XSS) face no browser-enforced restrictions. Malicious code can steal session cookies, capture keystrokes, or redirect users.",
        "fix_steps": [
            "Start with a strict baseline: Content-Security-Policy: default-src 'self'",
            "Gradually add allowed sources: script-src 'self' https://cdn.example.com",
            "Use report-uri or report-to to collect policy violation logs during testing.",
            "Use Content-Security-Policy-Report-Only first to test without breaking your site.",
            "Avoid 'unsafe-inline' and 'unsafe-eval' — use nonces or hashes instead.",
            "Test with Google CSP Evaluator at csp-evaluator.withgoogle.com.",
        ],
        "references": ["MDN CSP Reference", "OWASP CSP Cheat Sheet"],
        "owasp": "A05:2021 - Security Misconfiguration",
    },

    # ── SSL/TLS ───────────────────────────────────────────────────────────────
    "NO_HTTPS": {
        "summary": "The site is served over plain HTTP with no encryption.",
        "impact": "All data transmitted between users and the server is visible to anyone on the network — passwords, session tokens, personal data, and payment information are completely exposed.",
        "fix_steps": [
            "Obtain a free TLS certificate from Let's Encrypt (certbot.eff.org).",
            "Install and configure the certificate on your web server.",
            "Configure HTTP (port 80) to permanently redirect to HTTPS (301 redirect).",
            "Update all internal links and resources to use HTTPS URLs.",
            "Enable HSTS after verifying HTTPS works correctly.",
            "Test with SSL Labs at ssllabs.com/ssltest/.",
        ],
        "references": ["Let's Encrypt Documentation", "OWASP Transport Layer Security Cheat Sheet"],
        "owasp": "A02:2021 - Cryptographic Failures",
    },

    "WEAK_TLS_PROTOCOL": {
        "summary": "An outdated and insecure TLS protocol version is in use.",
        "impact": "TLS 1.0 and 1.1 have known vulnerabilities (POODLE, BEAST, CRIME). Attackers can exploit these to decrypt encrypted communications or forge certificates.",
        "fix_steps": [
            "Disable TLS 1.0 and TLS 1.1 on your server — only allow TLS 1.2 and TLS 1.3.",
            "Nginx: ssl_protocols TLSv1.2 TLSv1.3;",
            "Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3",
            "IIS: Disable via Windows Registry or IIS Crypto tool.",
            "Update cipher suite list to exclude RC4, 3DES, DES, EXPORT, and NULL ciphers.",
            "Run SSL Labs test to confirm TLS 1.0/1.1 are disabled.",
        ],
        "references": ["NIST SP 800-52 Rev 2", "OWASP TLS Cheat Sheet"],
        "owasp": "A02:2021 - Cryptographic Failures",
    },

    "WEAK_CIPHER": {
        "summary": "The server supports weak or broken cipher suites.",
        "impact": "Weak ciphers (RC4, DES, 3DES, EXPORT) can be broken by attackers in real time or offline, allowing decryption of captured traffic and session hijacking.",
        "fix_steps": [
            "Disable all RC4, DES, 3DES, NULL, EXPORT, and ANON cipher suites.",
            "Nginx recommended: ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:...",
            "Use Mozilla's SSL Config Generator at ssl-config.mozilla.org for your server version.",
            "Enable Perfect Forward Secrecy (PFS) by prioritising ECDHE and DHE key exchanges.",
            "Regularly update your server and OpenSSL to get new cipher suite recommendations.",
        ],
        "references": ["Mozilla SSL Configuration Generator", "OWASP Cryptographic Failures"],
        "owasp": "A02:2021 - Cryptographic Failures",
    },

    "INVALID_SSL_CERT": {
        "summary": "The SSL/TLS certificate is invalid, expired, or self-signed.",
        "impact": "Users see browser security warnings and may ignore them. Self-signed certs cannot be validated — attackers can perform man-in-the-middle attacks undetected.",
        "fix_steps": [
            "Obtain a valid certificate from a trusted CA (Let's Encrypt is free).",
            "Ensure the certificate covers all domain names (including www. subdomain).",
            "Set up automatic renewal using certbot renew --pre-hook and --post-hook.",
            "Monitor expiry with tools like certificate transparency logs or UptimeRobot.",
            "Never use self-signed certificates in production environments.",
        ],
        "references": ["Let's Encrypt", "SSL Labs Certificate Checker"],
        "owasp": "A02:2021 - Cryptographic Failures",
    },

    # ── Sensitive Files ───────────────────────────────────────────────────────
    "SENSITIVE_FILE_EXPOSED": {
        "summary": "A sensitive configuration or data file is publicly accessible.",
        "impact": "Exposed files like .env, .git/config, wp-config.php, or database dumps can reveal database credentials, API keys, secret tokens, and internal architecture — enabling full system compromise.",
        "fix_steps": [
            "Immediately restrict access to the exposed file at the web server level.",
            "Nginx: deny access with: location ~ /\\.env { deny all; return 404; }",
            "Apache: add to .htaccess: <Files .env> Order allow,deny Deny from all </Files>",
            "Move sensitive config files above the web root (outside public_html/).",
            "Rotate ALL credentials and secrets that may have been exposed immediately.",
            "Audit your .gitignore to prevent future commits of sensitive files.",
            "Use environment variables or secret managers (AWS Secrets Manager, Vault) instead of config files.",
        ],
        "references": ["OWASP Sensitive Data Exposure", "CWE-538"],
        "owasp": "A05:2021 - Security Misconfiguration",
    },

    # ── Cookies ───────────────────────────────────────────────────────────────
    "INSECURE_COOKIE": {
        "summary": "Session cookies are missing security attributes.",
        "impact": "Without Secure flag: cookies sent over HTTP can be intercepted. Without HttpOnly: JavaScript can read cookies, enabling XSS-based session theft. Without SameSite: Cross-Site Request Forgery (CSRF) attacks become trivial.",
        "fix_steps": [
            "Add Secure flag: cookie only transmitted over HTTPS connections.",
            "Add HttpOnly flag: prevents JavaScript from accessing the cookie.",
            "Add SameSite=Strict or SameSite=Lax to prevent CSRF.",
            "PHP: session_set_cookie_params(['secure'=>true,'httponly'=>true,'samesite'=>'Lax']);",
            "Django: SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax'",
            "Node/Express: res.cookie('session', val, {secure:true, httpOnly:true, sameSite:'lax'})",
            "Avoid storing sensitive data directly in cookies — use server-side sessions.",
        ],
        "references": ["OWASP Session Management Cheat Sheet", "RFC 6265"],
        "owasp": "A02:2021 - Cryptographic Failures",
    },

    # ── Dangerous Methods ─────────────────────────────────────────────────────
    "DANGEROUS_HTTP_METHOD": {
        "summary": "Dangerous HTTP methods (PUT, DELETE, TRACE) are enabled on the server.",
        "impact": "PUT allows uploading arbitrary files (including web shells). DELETE allows removing files. TRACE enables Cross-Site Tracing (XST) attacks that can steal authentication headers.",
        "fix_steps": [
            "Disable TRACE globally — it has no legitimate use in production.",
            "Nginx: add_header 'X-Content-Type-Options' 'nosniff'; and limit_except GET POST { deny all; }",
            "Apache: <LimitExcept GET POST> Require all denied </LimitExcept>",
            "Only enable PUT/DELETE if your API specifically requires them, and protect with authentication.",
            "Use a WAF (Web Application Firewall) to block dangerous methods at the perimeter.",
        ],
        "references": ["OWASP HTTP Methods Test", "CWE-16"],
        "owasp": "A05:2021 - Security Misconfiguration",
    },

    # ── Server Disclosure ─────────────────────────────────────────────────────
    "SERVER_VERSION_DISCLOSURE": {
        "summary": "The server reveals its software name and version in response headers.",
        "impact": "Attackers use version information to identify known CVEs for your exact server version and launch targeted exploits without any guesswork.",
        "fix_steps": [
            "Nginx: add 'server_tokens off;' in the http {} block of nginx.conf.",
            "Apache: set 'ServerTokens Prod' and 'ServerSignature Off' in httpd.conf.",
            "PHP: set 'expose_php = Off' in php.ini and remove X-Powered-By header.",
            "Node/Express: app.disable('x-powered-by') or use helmet().",
            "Remove or customise X-Generator, X-Drupal-Cache, X-Joomla headers.",
            "Apply a reverse proxy (nginx, Cloudflare) to strip/replace server headers.",
        ],
        "references": ["CWE-200", "OWASP Information Exposure"],
        "owasp": "A05:2021 - Security Misconfiguration",
    },

    # ── DNS Issues ────────────────────────────────────────────────────────────
    "ZONE_TRANSFER_ENABLED": {
        "summary": "DNS zone transfer (AXFR) is publicly accessible — all DNS records exposed.",
        "impact": "Any attacker can retrieve your complete DNS zone file, mapping every server, subdomain, internal host, and IP address in your infrastructure. This is critical reconnaissance intelligence.",
        "fix_steps": [
            "Restrict AXFR transfers to only trusted secondary nameserver IPs.",
            "BIND: add 'allow-transfer { secondary-ns-ip; };' to each zone in named.conf.",
            "PowerDNS: set allow-axfr-ips in pdns.conf.",
            "Test the fix: 'dig axfr yourdomain.com @ns1.yourdomain.com' should be refused.",
            "Audit which of your subdomains were exposed and assess their risk.",
            "Consider moving to a managed DNS provider (Cloudflare, Route53) with built-in zone transfer controls.",
        ],
        "references": ["RFC 5936", "CWE-264"],
        "owasp": "A05:2021 - Security Misconfiguration",
    },

    "MISSING_SPF_RECORD": {
        "summary": "No SPF DNS record found — domain is vulnerable to email spoofing.",
        "impact": "Attackers can send emails that appear to come from your domain. This enables phishing, fraud, and reputational damage as your domain is used in spam/scam campaigns.",
        "fix_steps": [
            "Add a TXT record at your domain's DNS: v=spf1 include:_spf.yourprovider.com ~all",
            "Replace 'include:...' with your actual mail server's SPF include.",
            "Use 'mx' if your MX records send mail: v=spf1 mx ~all",
            "Use '-all' (fail) instead of '~all' (softfail) for stricter enforcement.",
            "Test with: dig TXT yourdomain.com | grep spf",
            "Validate with MXToolbox SPF checker at mxtoolbox.com/spf.aspx.",
        ],
        "references": ["RFC 7208", "DMARC.org SPF Guide"],
        "owasp": "A05:2021 - Security Misconfiguration",
    },

    "MISSING_DMARC": {
        "summary": "No DMARC record found — no policy to handle email authentication failures.",
        "impact": "Without DMARC, emails failing SPF/DKIM checks are delivered anyway. Your domain can be spoofed in phishing campaigns with no enforcement mechanism.",
        "fix_steps": [
            "Add TXT record at _dmarc.yourdomain.com:",
            "Start with monitoring mode: v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com",
            "After reviewing reports (2-4 weeks), move to: p=quarantine then p=reject.",
            "Final strict policy: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com; adkim=s; aspf=s",
            "Use a DMARC reporting service (Postmark, Valimail) to analyse reports.",
            "Ensure SPF and DKIM are both set up correctly before enforcing DMARC.",
        ],
        "references": ["RFC 7489", "DMARC.org"],
        "owasp": "A05:2021 - Security Misconfiguration",
    },

    "WEAK_DMARC_POLICY": {
        "summary": "DMARC policy is set to 'none' — monitoring only, no enforcement.",
        "impact": "p=none only logs failures but does not block or quarantine spoofed emails. Attackers can still send emails impersonating your domain with no consequence.",
        "fix_steps": [
            "Review your DMARC aggregate reports (rua) to understand current failures.",
            "Move from p=none to p=quarantine (suspicious emails go to spam).",
            "After confirming legitimate email is not affected, move to p=reject.",
            "Update record: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com",
            "Ensure all legitimate mail sources have valid SPF and DKIM alignment.",
        ],
        "references": ["DMARC.org Policy Guide"],
        "owasp": "A05:2021 - Security Misconfiguration",
    },

    # ── Port-level ────────────────────────────────────────────────────────────
    "TELNET_EXPOSED": {
        "summary": "Telnet (port 23) is running — an unencrypted remote access protocol.",
        "impact": "Telnet transmits everything in cleartext including usernames, passwords, and all commands. Any attacker on the same network can capture full sessions with a packet sniffer.",
        "fix_steps": [
            "Immediately disable Telnet on the target system.",
            "Install and enable OpenSSH for secure remote access.",
            "Configure SSH with key-based authentication (disable password auth).",
            "Linux: systemctl disable telnet && systemctl enable sshd",
            "Restrict SSH access to specific IP addresses using firewall rules.",
            "Add SSH to /etc/hosts.allow and block all others in /etc/hosts.deny.",
        ],
        "references": ["CWE-319", "NIST SP 800-115"],
        "owasp": "A02:2021 - Cryptographic Failures",
    },

    "FTP_EXPOSED": {
        "summary": "FTP (port 21) is open — credentials transmitted in plaintext.",
        "impact": "FTP sends usernames and passwords unencrypted. Passive sniffing on the same network segment captures credentials immediately. Anonymous FTP may expose all files without any authentication.",
        "fix_steps": [
            "Replace FTP with SFTP (SSH File Transfer Protocol) — uses port 22.",
            "If FTP must be kept, upgrade to FTPS (FTP over TLS) — enforce explicit TLS.",
            "Disable anonymous FTP login entirely.",
            "vsftpd: set anonymous_enable=NO in /etc/vsftpd.conf.",
            "Restrict FTP access to specific IP ranges via firewall.",
            "Audit all FTP user accounts and remove unused ones.",
        ],
        "references": ["CWE-319", "OWASP File Upload Cheat Sheet"],
        "owasp": "A02:2021 - Cryptographic Failures",
    },

    "SMB_EXPOSED": {
        "summary": "SMB (port 445) is publicly accessible — high risk of exploitation.",
        "impact": "Unpatched SMB is vulnerable to EternalBlue (CVE-2017-0144) used by WannaCry and NotPetya ransomware. Even patched SMB should not be exposed to the internet.",
        "fix_steps": [
            "Apply MS17-010 patch immediately if not already done.",
            "Block ports 445 and 139 at the perimeter firewall — never expose to the internet.",
            "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
            "Enable SMB signing to prevent relay attacks.",
            "Use VPN for any legitimate remote file sharing needs.",
            "Run 'nmap -p 445 --script smb-vuln-ms17-010 <target>' to verify EternalBlue status.",
        ],
        "references": ["MS17-010", "CVE-2017-0144", "CISA Alert AA20-133A"],
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
    },

    "RDP_EXPOSED": {
        "summary": "RDP (port 3389) is publicly exposed to the internet.",
        "impact": "Public RDP is one of the most attacked services online. Risks include BlueKeep RCE (CVE-2019-0708), brute-force credential attacks, and ransomware deployment via compromised accounts.",
        "fix_steps": [
            "Immediately restrict RDP access to known IP addresses via firewall.",
            "Place RDP behind a VPN — require VPN connection before RDP is accessible.",
            "Enable Network Level Authentication (NLA) to require credentials before session starts.",
            "Apply all Windows updates including BlueKeep patch (CVE-2019-0708).",
            "Enable Account Lockout Policy to stop brute-force attacks.",
            "Use a bastion host or jump server for administrative access.",
            "Monitor RDP login attempts in Windows Event Log (Event IDs 4624, 4625).",
        ],
        "references": ["CVE-2019-0708 BlueKeep", "CISA RDP Security Guide"],
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },

    "REDIS_EXPOSED": {
        "summary": "Redis is publicly accessible with no authentication.",
        "impact": "Unauthenticated Redis allows any attacker to read and overwrite all cached data, execute arbitrary commands via Lua scripting, write SSH authorized_keys to gain shell access, and achieve full server compromise.",
        "fix_steps": [
            "Bind Redis to localhost only: bind 127.0.0.1 in redis.conf.",
            "Set a strong password: requirepass yourStrongPasswordHere",
            "Block port 6379 at the firewall — never expose to the internet.",
            "Rename or disable dangerous commands: rename-command FLUSHALL ''",
            "Run Redis as a non-privileged system user.",
            "Enable Redis ACLs (Redis 6+) for fine-grained access control.",
        ],
        "references": ["Redis Security Documentation", "CVE-2015-4335"],
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },

    "MONGODB_EXPOSED": {
        "summary": "MongoDB is publicly accessible without authentication.",
        "impact": "Unauthenticated MongoDB gives complete read/write/delete access to all databases. This vulnerability has caused billions of records to be exposed in publicised breaches affecting healthcare, government, and enterprise.",
        "fix_steps": [
            "Enable authentication: security.authorization: enabled in mongod.conf.",
            "Bind to localhost: net.bindIp: 127.0.0.1",
            "Create admin user: db.createUser({user:'admin', pwd:'<password>', roles:['root']})",
            "Block port 27017/27018 at the firewall immediately.",
            "Audit all existing databases for unauthorised data access.",
            "Use MongoDB Atlas or a managed service with built-in security controls.",
        ],
        "references": ["MongoDB Security Checklist", "OWASP NoSQL Injection"],
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },

    "ELASTICSEARCH_EXPOSED": {
        "summary": "Elasticsearch is publicly accessible without authentication.",
        "impact": "Open Elasticsearch exposes all indexed data for read and write access. Attackers can exfiltrate all data, delete indices, or inject malicious documents. Responsible for many of the largest data breaches in history.",
        "fix_steps": [
            "Enable X-Pack security (built into Elasticsearch 8+): xpack.security.enabled: true",
            "Bind to localhost: network.host: 127.0.0.1",
            "Block port 9200 and 9300 at the firewall immediately.",
            "Create user accounts with role-based access control (RBAC).",
            "Enable TLS for node-to-node and client communication.",
            "Use Kibana's Security app to audit access and set up alerting.",
        ],
        "references": ["Elastic Security Guide", "CWE-306"],
        "owasp": "A07:2021 - Identification and Authentication Failures",
    },

    "VULNERABLE_SERVICE_VERSION": {
        "summary": "A service with a known Critical or High CVE was detected in the banner.",
        "impact": "Running software with publicly known vulnerabilities provides attackers with ready-made exploit code. Many CVEs in this category allow unauthenticated remote code execution.",
        "fix_steps": [
            "Update the affected software to the latest stable version immediately.",
            "Check the CVE details at nvd.nist.gov for specific patch information.",
            "If an update is not immediately possible, apply vendor-provided mitigations.",
            "Disable or restrict access to the service until it can be patched.",
            "Subscribe to security advisories for all software you run.",
            "Implement a vulnerability management process for regular patching cycles.",
        ],
        "references": ["NVD CVE Database", "CISA Known Exploited Vulnerabilities"],
        "owasp": "A06:2021 - Vulnerable and Outdated Components",
    },

    "NO_HTTPS_REDIRECT": {
        "summary": "HTTP traffic is not automatically redirected to HTTPS.",
        "impact": "Users who visit the plain HTTP version of the site have their traffic transmitted unencrypted, even if HTTPS is available. Session cookies and credentials can be intercepted.",
        "fix_steps": [
            "Configure a permanent 301 redirect from HTTP to HTTPS.",
            "Nginx: return 301 https://$host$request_uri; in the port 80 server block.",
            "Apache: RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
            "Cloudflare: enable 'Always Use HTTPS' in SSL/TLS settings.",
            "After redirect is in place, enable HSTS to lock in HTTPS for browsers.",
        ],
        "references": ["OWASP Transport Layer Security Cheat Sheet"],
        "owasp": "A02:2021 - Cryptographic Failures",
    },

    "MSSQL_EXPOSED": {
        "summary": "Microsoft SQL Server is publicly exposed on the internet.",
        "impact": "Internet-facing MSSQL is a major attack target for brute-force, credential stuffing, and SQL injection attacks. The SA account, if enabled, can lead to full OS compromise via xp_cmdshell.",
        "fix_steps": [
            "Block port 1433 at the perimeter firewall — never expose to the internet.",
            "Restrict access to specific application server IPs only.",
            "Disable the SA account or change its password to a very strong value.",
            "Disable xp_cmdshell: EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;",
            "Use Windows Authentication instead of SQL Authentication where possible.",
            "Enable SQL Server Audit to log all login attempts.",
        ],
        "references": ["CIS Microsoft SQL Server Benchmark", "OWASP Database Security"],
        "owasp": "A05:2021 - Security Misconfiguration",
    },

    "MYSQL_EXPOSED": {
        "summary": "MySQL database server is publicly accessible.",
        "impact": "Public MySQL exposure enables credential brute-forcing, exploitation of MySQL vulnerabilities, and potential remote code execution through file read/write operations (LOAD DATA INFILE, SELECT INTO OUTFILE).",
        "fix_steps": [
            "Bind MySQL to localhost: bind-address = 127.0.0.1 in my.cnf.",
            "Block port 3306 at the firewall — only allow application server IPs.",
            "Remove or restrict the root@'%' account: DELETE FROM mysql.user WHERE User='root' AND Host='%';",
            "Run mysql_secure_installation to remove test databases and anonymous users.",
            "Create application-specific database users with minimal privileges.",
            "Enable MySQL general log temporarily to audit current access.",
        ],
        "references": ["MySQL Security Best Practices", "CIS MySQL Benchmark"],
        "owasp": "A05:2021 - Security Misconfiguration",
    },

    # ── Defaults ──────────────────────────────────────────────────────────────
    "DEFAULT": {
        "summary": "A security vulnerability or misconfiguration was detected.",
        "impact": "This finding may expose systems or data to unauthorized access, data leakage, or exploitation by malicious actors.",
        "fix_steps": [
            "Review the specific finding details above.",
            "Consult the relevant vendor documentation for security hardening guides.",
            "Apply the principle of least privilege to all services and accounts.",
            "Test changes in a staging environment before applying to production.",
            "Rescan after remediation to confirm the issue is resolved.",
        ],
        "references": ["OWASP Top 10 2021", "CIS Benchmarks"],
        "owasp": "A05:2021 - Security Misconfiguration",
    },
}


def enrich_with_knowledge(vuln: dict) -> dict:
    """Add summary, impact, fix steps, and references to a vulnerability dict."""
    vtype = vuln.get("type", "DEFAULT")
    kb = VULN_KNOWLEDGE.get(vtype) or VULN_KNOWLEDGE.get("DEFAULT")

    # Don't overwrite if already set
    if "summary" not in vuln:
        vuln["summary"] = kb.get("summary", "")
    if "impact" not in vuln:
        vuln["impact"] = kb.get("impact", "")
    if "fix_steps" not in vuln:
        vuln["fix_steps"] = kb.get("fix_steps", [])
    if "references" not in vuln:
        vuln["references"] = kb.get("references", [])
    if "owasp" not in vuln or not vuln["owasp"]:
        vuln["owasp"] = kb.get("owasp", "")
    if "recommendation" not in vuln and kb.get("fix_steps"):
        vuln["recommendation"] = kb["fix_steps"][0]

    return vuln
