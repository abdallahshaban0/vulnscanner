<div align="center">

# 🔍 VulnScanner

### Automated Vulnerability Scanner for Ethical Hacking & Penetration Testing

[![CI](https://github.com/abdallahshaban0/vulnscanner/actions/workflows/ci.yml/badge.svg)](https://github.com/abdallahshaban0/vulnscanner/actions)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?logo=docker)](Dockerfile)
[![Security](https://img.shields.io/badge/For-Authorised%20Testing%20Only-red)](https://github.com/abdallahshaban0/vulnscanner)

> A professional multi-module vulnerability scanner built in pure Python.
> Port scanning · HTTP security auditing · DNS reconnaissance · CVE matching · Risk scoring · HTML reports.

</div>

---

## Quick Start

```bash
# Clone
git clone https://github.com/abdallahshaban0/vulnscanner.git
cd vulnscanner

# One-command install (Linux / macOS)
bash install.sh

# Or manually
pip install -r requirements.txt

# Run your first scan
python scanner.py -t example.com --full --report html
```

> **Windows:** Use `vulnscanner.bat` instead of `./vulnscanner.sh`
> **Docker:** `docker build -t vulnscanner . && docker run --rm vulnscanner -t example.com --full`

---

## Table of Contents

- [Features](#features)
- [Project Structure](#project-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Scan Examples](#scan-examples)
- [How It Works](#how-it-works)
- [Vulnerability Checks](#vulnerability-checks)
- [Risk Scoring](#risk-scoring)
- [Legal Notice](#legal-notice)
- [Credits](#credits)

---

## Features

| Module | What it checks |
|---|---|
| **Port Scanner** | TCP ports 1-65535, banner grabbing, service detection, risk classification |
| **HTTP Scanner** | Security headers, sensitive files, cookies, SSL/TLS, HTTP methods, redirects |
| **DNS Recon** | All DNS records, zone transfer (AXFR), subdomain enumeration, SPF/DMARC, WHOIS |
| **CVE Matching** | Banner-based version detection against known vulnerable software |
| **Risk Scoring** | Weighted 0-100 score with CRITICAL / HIGH / MEDIUM / LOW rating |
| **Reports** | Standalone HTML report + JSON export, no server needed |

---

## Project Structure

```
vulnscanner/
|
+-- scanner.py                  <- Main CLI entry point
|
+-- modules/
|   +-- port_scanner.py         <- Multi-threaded TCP port scanner
|   +-- http_scanner.py         <- Web vulnerability checks (50+ checks)
|   +-- dns_recon.py            <- DNS records, AXFR, subdomain enum, WHOIS
|   +-- vuln_analysis.py        <- CVE matching, OWASP mapping, scoring
|   +-- report_generator.py     <- HTML + JSON report generation
|
+-- reports/                    <- Scan output directory (auto-created)
|
+-- .github/
|   +-- workflows/ci.yml        <- GitHub Actions CI (multi-Python, Docker)
|   +-- ISSUE_TEMPLATE/         <- Bug report & feature request templates
|
+-- Dockerfile                  <- Run via Docker (no install needed)
+-- install.sh                  <- One-command Linux/macOS installer
+-- vulnscanner.sh              <- Shell launcher
+-- vulnscanner.bat             <- Windows launcher
+-- setup.py                    <- pip install support
+-- pyproject.toml              <- Modern Python packaging
+-- requirements.txt
+-- LICENSE
```

---

## Installation

### Option 1 — One-command installer (Linux / macOS)

```bash
git clone https://github.com/abdallahshaban0/vulnscanner.git
cd vulnscanner
bash install.sh
source .venv/bin/activate
python scanner.py --help
```

### Option 2 — Manual (all platforms)

```bash
git clone https://github.com/abdallahshaban0/vulnscanner.git
cd vulnscanner
pip install -r requirements.txt
python scanner.py --help
```

### Option 3 — Docker (zero install)

```bash
docker build -t vulnscanner .
docker run --rm -v $(pwd)/reports:/app/reports vulnscanner -t example.com --full --report html
```

### Requirements

- Python 3.8 or higher
- pip
- No root / sudo required

---

## Usage

```
python scanner.py -t <target> [modules] [options]
```

### Scan Modules

| Flag | Description |
|---|---|
| `--full` | Run all modules (recommended) |
| `--ports` | Port scanner only |
| `--http` | HTTP vulnerability scanner only |
| `--dns` | DNS reconnaissance only |

### Port Scan Options

| Flag | Default | Description |
|---|---|---|
| `--scan-type` | `common` | `common` / `top1000` / `full` / `custom` |
| `--port-range` | — | `1-1024` or `80,443,8080` |
| `--threads` | `100` | Concurrent threads |
| `--timeout` | `1.0` | Socket timeout in seconds |

### Output Options

| Flag | Default | Description |
|---|---|---|
| `--report` | `html` | `html` / `json` / `all` / `none` |
| `-u`, `--url` | auto | Override target URL |
| `-q`, `--quiet` | off | Suppress banner |

---

## Scan Examples

```bash
# Full scan — all modules — HTML report
python scanner.py -t example.com --full --report html

# Deep port scan — top 1000 ports
python scanner.py -t 192.168.1.1 --ports --scan-type top1000

# Web app security audit only
python scanner.py -t example.com --http --report html

# DNS recon only
python scanner.py -t example.com --dns --report json

# Lab / CTF machine (faster)
python scanner.py -t 192.168.56.101 --full --threads 200 --timeout 2

# Custom port list
python scanner.py -t 10.0.0.5 --ports --scan-type custom --port-range 22,80,443,3306,5432,6379

# Both HTML and JSON output
python scanner.py -t example.com --full --report all

# Docker run with report extraction
docker run --rm -v $(pwd)/reports:/app/reports vulnscanner -t example.com --full
```

---

## How It Works

### Port Scanner

- Uses Python built-in `socket.connect_ex()` — no external tools required
- Multi-threaded via `concurrent.futures.ThreadPoolExecutor`
- Attempts banner grabbing on every open port
- Risk classification: HIGH (Telnet, SMB, RDP) / MEDIUM (SSH, MySQL) / LOW (HTTP)

### HTTP Scanner

Sends crafted requests and analyses:

1. Security headers — 7 critical headers checked
2. Sensitive files — 50+ paths (.env, .git, /phpmyadmin, Swagger, etc.)
3. Cookie flags — Secure, HttpOnly, SameSite
4. SSL/TLS — protocol version, cipher suite, certificate validity
5. HTTP methods — PUT, DELETE, TRACE, CONNECT
6. HTTPS redirect enforcement

### DNS Recon

- Queries A, AAAA, MX, NS, TXT, CNAME, SOA records
- Attempts zone transfer (AXFR) on every nameserver
- Enumerates 200+ common subdomains in parallel
- Validates SPF + DMARC email security records
- Performs full WHOIS lookup

### CVE Matching

Banner text matched against known vulnerable versions:

| Banner | CVE | CVSS |
|---|---|---|
| Apache/2.4.49 | CVE-2021-41773 Path Traversal/RCE | 9.8 |
| vsftpd 2.3.4 | CVE-2011-2523 Backdoor RCE | 10.0 |
| ProFTPD 1.3.5 | CVE-2015-3306 File Copy RCE | 10.0 |
| Tomcat/8.5 | CVE-2020-1938 GhostCat | 9.8 |
| IIS/6.0 | CVE-2017-7269 Buffer Overflow RCE | 10.0 |

---

## Vulnerability Checks

### Port-level risks

| Port | Finding | Severity |
|---|---|---|
| 23 | Telnet cleartext protocol | CRITICAL |
| 6379 | Redis unauthenticated access | CRITICAL |
| 27017 | MongoDB unauthenticated access | CRITICAL |
| 9200 | Elasticsearch unauthenticated | CRITICAL |
| 445 | SMB / EternalBlue risk | HIGH |
| 3389 | RDP / BlueKeep risk | HIGH |
| 21 | FTP cleartext credentials | HIGH |
| 5900 | VNC exposed | HIGH |
| 3306 | MySQL publicly exposed | HIGH |

### HTTP security headers

| Header | Missing = Severity |
|---|---|
| Strict-Transport-Security | HIGH |
| Content-Security-Policy | HIGH |
| X-Frame-Options | MEDIUM |
| X-Content-Type-Options | MEDIUM |
| Referrer-Policy | LOW |
| Permissions-Policy | LOW |

### DNS checks

| Check | Severity |
|---|---|
| Zone transfer (AXFR) succeeds | CRITICAL |
| No SPF record | MEDIUM |
| No DMARC record | MEDIUM |
| DMARC p=none (weak policy) | LOW |

---

## Risk Scoring

| Score | Rating | Action |
|---|---|---|
| 0 | SECURE | No findings |
| 1-24 | LOW | Minor hardening recommended |
| 25-49 | MEDIUM | Remediation recommended |
| 50-74 | HIGH | Urgent remediation needed |
| 75-100 | CRITICAL | Immediate action required |

Weights: CRITICAL=25 pts, HIGH=10 pts, MEDIUM=5 pts, LOW=2 pts (capped at 100)

---

## Legal Notice

**This tool is for authorised security testing and educational use ONLY.**

You are permitted to scan systems you own, intentionally vulnerable labs (Metasploitable, DVWA, TryHackMe, HackTheBox, VulnHub), and systems with explicit written penetration testing authorisation.

Scanning without permission violates the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act (CMA), EU Directive 2013/40/EU, and equivalent laws worldwide.

**The author accepts no liability for misuse of this tool.**

---

## Credits

<div align="center">

**Developed by [abdallahshaban0](https://github.com/abdallahshaban0)**

*Ethical Hacking & Penetration Testing Course Project*

Built with Python · Designed for Security Education · Open Source under MIT License

</div>
