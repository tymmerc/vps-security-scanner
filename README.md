# VPS Security Scanner & Pentest Bot

Automated security scanning and offensive penetration testing for self-hosted VPS.

## Features

### Passive Scanner (`scan.sh`)
Runs daily via systemd timer. Checks:
- **Secrets** - gitleaks scan across all git repos
- **Dependencies** - npm audit + pip-audit on all projects
- **VPS Hardening** - SSH config, firewall, open ports, fail2ban
- **Nginx/TLS** - security headers, certificate expiry, TLS config
- **Docker** - privileged containers, root users, host networking
- **Permissions** - .env files, private keys, world-writable files

### Pentest Bot (`pentest.sh`)
On-demand offensive security testing:
- **Port Scan** - nmap full TCP + UDP with vuln scripts
- **Nuclei** - 8000+ CVE/misconfig templates on all domains + exposed ports
- **TLS Audit** - testssl.sh deep cipher/protocol analysis
- **Headers** - security header verification per route
- **Dir Brute-force** - ffuf with SecLists wordlists + sensitive file probing
- **Nikto** - web server misconfiguration scanner
- **Brute-force** - hydra SSH + HTTP basic auth credential testing

## Usage

```bash
# Passive scan (runs daily at 4am automatically)
./scan.sh

# Pentest modes
pentest --full        # All modules (~15-30 min)
pentest --quick       # Ports + nuclei + TLS + headers (~5 min)
pentest --web         # Web-focused (nuclei + TLS + headers + dirbrute + nikto)
pentest --network     # Network-focused (ports + brute-force)
pentest --bruteforce  # Credential testing only
```

## Reports

HTML reports auto-generated after each scan:
- Passive: `reports/latest/report.html`
- Pentest: `reports/latest-pentest/report.html`

30 most recent reports are kept, older ones are auto-purged.

## Tools

| Tool | Version | Purpose |
|------|---------|---------|
| gitleaks | 8.21.2 | Secret detection |
| trivy | 0.69.3 | Vulnerability scanning |
| lynis | 3.0.9 | System hardening audit |
| pip-audit | 2.10.0 | Python dependency audit |
| nuclei | 3.3.7 | Template-based vuln scanner |
| nmap | 7.94 | Port scanning & fingerprinting |
| testssl.sh | latest | TLS/SSL audit |
| nikto | latest | Web server scanner |
| ffuf | 2.1.0 | Directory brute-forcing |
| hydra | latest | Credential brute-forcing |

## Setup

Designed for Ubuntu 24.04 VPS. Install dependencies:

```bash
# The scan scripts handle tool installation, but you can also run:
apt install nmap nikto hydra
# nuclei, gitleaks, trivy, ffuf are installed as standalone binaries
```

Systemd timer for daily passive scans:
```bash
systemctl enable --now vps-security-scan.timer
```

## License

MIT
