# Cybersecurity Blue Team Projects

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Focus](https://img.shields.io/badge/Focus-Blue%20Team%20%2F%20SOC-1f6feb)
![Projects](https://img.shields.io/badge/Projects-5%20Completed-2ea44f)
![Roadmap](https://img.shields.io/badge/Roadmap-8%20Planned-8957e5)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-d93025)

A portfolio of hands-on, from-scratch security tools built for **SOC operations, threat detection, log analysis, threat intelligence, vulnerability management and incident response**. Every project is a working tool with its own documentation, not a tutorial copy.

---

## Project Directory

| # | Project | What it does | Tech stack | Status |
|---|---------|--------------|------------|--------|
| 01 | [Password Strength Analyzer](01-Password-Strength-Analyzer/) | Real-time password analysis with breach exposure check | Python, PyQt5, HIBP API | Completed |
| 02 | [Sentinel Threat Intelligence](02-File-Hash-Checker/) | Multi-source file hash reputation analysis | Python, PyQt5, VirusTotal, OTX, MalwareBazaar | Completed |
| 03 | [LogSentinel Analyzer](03-Log-Parser/) | Real-time universal log parser and brute-force detector | Python, PyQt5, PyQtGraph, Watchdog | Completed |
| 04 | [PhishGuard Analyzer](04-Phishing-URL-Analyzer/) | Enterprise URL intelligence with WHOIS, SSL, DNS and tech stack detection | Python, PyQt5, VirusTotal API | Completed |
| 05 | [VulnSentinel](05-Vulnerability-Scanner/) | Attack surface scanner with web dashboard, threat intel (CISA KEV, Shodan InternetDB) and MITRE ATT&CK mapping | Python, Flask, Shodan InternetDB, CISA KEV | Completed |

---

## Blue Team Skills Demonstrated

| Domain | Covered by |
|--------|-----------|
| Credential security | 01 |
| Threat intelligence and IOC enrichment | 02, 04, 05 |
| Log analysis and detection of brute-force activity | 03 |
| Phishing and malicious URL analysis | 04 |
| Vulnerability and exposure management | 05 |
| Threat-informed defense (MITRE ATT&CK) | 05 |
| Secure coding (input validation, output escaping, no hardcoded secrets) | All |

---

## Roadmap

Planned projects that extend the portfolio across the full SOC workflow.

| # | Project | Focus | Status |
|---|---------|-------|--------|
| 06 | Detection Engineering Lab | Sigma-style rule engine, rule testing, ATT&CK coverage map | Planned |
| 07 | Windows Event and Sysmon Threat Hunter | EVTX parsing, hunting for persistence, credential access, lateral movement | Planned |
| 08 | Network Traffic Analyzer | PCAP analysis, beaconing, DNS tunneling and port-scan detection | Planned |
| 09 | Incident Response Triage Toolkit | Volatile artifact collection, timeline building, IOC extraction | Planned |
| 10 | Phishing Email Analyzer | Header and authentication (SPF, DKIM, DMARC) analysis, attachment triage | Planned |
| 11 | Mini SIEM | Log ingestion, correlation rules, alerting and dashboard | Planned |
| 12 | SOAR Playbook Automation | Automated enrichment and response workflows for common alerts | Planned |
| 13 | Windows Hardening Auditor | CIS-style configuration audit with remediation guidance | Planned |

---

## Repository Structure

```text
Cybersecurity-BlueTeam-Projects/
  01-Password-Strength-Analyzer/
  02-File-Hash-Checker/
  03-Log-Parser/
  04-Phishing-URL-Analyzer/
  05-Vulnerability-Scanner/
  README.md
```

## Getting Started

Each project is self-contained with its own `README.md`, dependencies and usage guide.

```powershell
git clone https://github.com/DharunS360/Cybersecurity-BlueTeam-Projects.git
cd Cybersecurity-BlueTeam-Projects\<project-folder>
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

API keys (VirusTotal, AbuseIPDB and others) are read from environment variables. No secrets are stored in this repository.

## Responsible Use

These tools are built for defensive and educational purposes. Scan, test or analyze only systems and data you own or are explicitly authorized to assess.

## Author

**Dharun S**: aspiring Blue Team / SOC Analyst

- GitHub: [DharunS360](https://github.com/DharunS360)
- LinkedIn: add your profile link here

## License

Released under the MIT License unless a project folder states otherwise.