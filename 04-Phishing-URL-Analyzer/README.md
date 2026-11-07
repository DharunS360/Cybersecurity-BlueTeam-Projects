# ?? PhishGuard - Enterprise URL Intelligence

An advanced Python-based tool built with PyQt5 for Blue Team and SOC analysts. It performs comprehensive threat intelligence on URLs, combining multiple security sources to detect phishing, malware, and suspicious domains.

## Features
- **Multi-Source Intelligence:**
  - ?? **VirusTotal:** Real-time URL reputation check.
  - ?? **URLScan.io:** Historical scans and public visibility.
  - ?? **WHOIS:** Domain age and registrar details.
  - ?? **DNS & IP:** A, MX, NS records and resolved IP.
  - ?? **SSL Certificate:** Issuer and validity details.
  - ??? **Security Headers:** Checks for CSP, HSTS, X-Frame-Options.
- **Technology Stack Detection:** Identifies WordPress, React, Nginx, Cloudflare, and more (Wappalyzer-style logic).
- **Heuristic Risk Scoring:** Detects typosquatting, suspicious TLDs (.xyz, .tk), and phishing keywords.
- **Interactive Dashboard:** Live web preview and clickable buttons to view full reports on external platforms.
- **Modern GUI:** Dark-themed, fully responsive PyQt5 dashboard.

## Setup
1. Install dependencies:
   pip install -r requirements.txt
2. Ensure config.json contains your VirusTotal API key.
3. Run the tool:
   python phishing_analyzer.py
4. Paste a URL and click Analyze URL.

## Tech Stack
- Python 3.x
- PyQt5 & PyQtWebEngine (GUI & Live Preview)
- Requests (API Integration)
- python-whois & dnspython (Domain Intelligence)
