# Cybersecurity Blue Team Projects

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6?logo=windows&logoColor=white)
![Focus](https://img.shields.io/badge/Focus-Blue%20Team%20%2F%20SOC-1f6feb)
![Projects](https://img.shields.io/badge/Projects-9%20Completed-2ea043)
![Roadmap](https://img.shields.io/badge/Roadmap-4%20Planned-8957e5)
![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK%20Mapped-red)
![License](https://img.shields.io/badge/License-MIT-green)

A portfolio of hands-on, from-scratch security tools built for **SOC operations, endpoint threat hunting, threat detection, log analysis, threat intelligence, network detection, vulnerability management and incident response**. Every project is a working tool with its own documentation, not a tutorial copy.

## Project Directory

| # | Project | What it does | Tech stack | Status |
|---|---|---|---|---|
| 01 | [Password Strength Analyzer](01-Password-Strength-Analyzer) | Real-time password analysis with breach exposure check | Python, PyQt5, HIBP API | Completed |
| 02 | [Sentinel Threat Intelligence](02-File-Hash-Checker) | Multi-source file hash reputation analysis | Python, PyQt5, VirusTotal, OTX, MalwareBazaar | Completed |
| 03 | [LogSentinel Analyzer](03-Log-Parser) | Real-time universal log parser and brute-force detector | Python, PyQt5, PyQtGraph, Watchdog | Completed |
| 04 | [PhishGuard Analyzer](04-Phishing-URL-Analyzer) | Enterprise URL intelligence with WHOIS, SSL, DNS and tech stack detection | Python, PyQt5, VirusTotal API | Completed |
| 05 | [VulnSentinel](05-Vulnerability-Scanner) | Attack surface scanner with web dashboard, threat intel (CISA KEV, Shodan InternetDB) and MITRE ATT&CK mapping | Python, Flask, Shodan InternetDB, CISA KEV | Completed |
| 07 | [SysmonHunter](07-Windows-Sysmon-Threat-Hunter) | Windows Event and Sysmon threat hunting: EVTX, XML and live ingestion, 104 ATT&CK-mapped rule definitions, stateful correlation, local web UI and HTML/JSON/CSV reports | Python, Flask, python-evtx, defusedxml, wevtutil | Completed |
| 08 | [Network Traffic Analyzer](08-Network-Traffic-Analyzer) | Real-time network detection console: flow tracking, process attribution, TLS SNI/JA3, GeoIP/ASN, threat intel and 16 MITRE ATT&CK-mapped detections | Python, PyQt5, Scapy, psutil, PyQtGraph | Completed |
| 09 | [Incident Response Triage Toolkit](09-Incident-Response-Triage-Toolkit) | Live Windows IR triage console: process, network, persistence and event-log collection, MITRE ATT&CK-mapped detections, timeline, IOC extraction, process tree, baseline diff and case export | Python, PyQt5, psutil, PowerShell/CIM, VirusTotal | Completed |
| 10 | [PhishScope](10-Phishing-Email-Analyzer) | Phishing e-mail triage: live SPF/DKIM/DMARC, routing, URL and attachment analysis, IOCs and MITRE mapping | Python, PyQt5, dnspython, dkimpy, VirusTotal | Completed |

## Blue Team Skills Demonstrated

| Domain | Covered by |
|---|---|
| Credential security | 01 |
| Threat intelligence and IOC enrichment | 02, 04, 05, 08, 09, 10 |
| Log analysis and detection of brute-force activity | 03, 07 |
| Windows endpoint telemetry hunting (Sysmon, Security, PowerShell logs) | 07 |
| Phishing and malicious URL analysis | 04, 10 |
| E-mail security (SPF, DKIM, DMARC) and attachment triage | 10 |
| Vulnerability and exposure management | 05 |
| Threat-informed defense (MITRE ATT&CK) | 05, 07, 08, 09 |
| Network traffic analysis and detection (C2 beaconing, DNS tunneling, scans, ARP spoofing) | 08 |
| Incident response, live triage and forensic artifact collection | 09 |
| Persistence and malware hunting (registry, services, tasks, WMI) | 07, 09 |
| Detection engineering (rule logic, correlation, allowlisting, baselining, unit tests) | 07, 09 |
| Secure coding (input validation, output escaping, CSRF protection, no hardcoded secrets) | All |

## Roadmap

Planned projects that extend the portfolio across the full SOC workflow.

| # | Project | Focus | Status |
|---|---|---|---|
| 06 | Detection Engineering Lab | Sigma-style rule engine, rule testing, ATT&CK coverage map | Planned |
| 11 | Mini SIEM | Log ingestion, correlation rules, alerting and dashboard | Planned |
| 12 | SOAR Playbook Automation | Automated enrichment and response workflows for common alerts | Planned |
| 13 | Windows Hardening Auditor | CIS-style configuration audit with remediation guidance | Planned |

## Repository Structure

```
Cybersecurity-BlueTeam-Projects/
  .github/workflows/                  CI pipelines
  01-Password-Strength-Analyzer/
  02-File-Hash-Checker/
  03-Log-Parser/
  04-Phishing-URL-Analyzer/
  05-Vulnerability-Scanner/
  07-Windows-Sysmon-Threat-Hunter/
  08-Network-Traffic-Analyzer/
  09-Incident-Response-Triage-Toolkit/
  10-Phishing-Email-Analyzer/
  LICENSE
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

Requirements by project:
- **Project 07** needs Python 3.11+, runs a local web UI on `127.0.0.1` and does not need Administrator rights. Protected live channels (for example Security) may need an authorised account or an exported EVTX file.
- **Project 08** additionally requires [Npcap](https://npcap.com) and an Administrator terminal for live capture.
- **Project 09** also benefits from an Administrator terminal (Security event log, Prefetch and Defender state).

## Responsible Use

These tools are built for defensive and educational purposes. Scan, test or analyze only systems and data you own or are explicitly authorized to assess.

## Author

**Dharun S**: aspiring Blue Team / SOC Analyst

- GitHub: [DharunS360](https://github.com/DharunS360)
- LinkedIn: https://www.linkedin.com/in/YOUR-LINKEDIN-HANDLE

## License

Released under the MIT License unless a project folder states otherwise.