# PhishScope - Phishing Email Analyzer (Project 10)

Blue-team phishing triage workstation. Drop in a `.eml` and get a risk verdict, authentication results
computed from **live DNS**, IP / domain / URL / file reputation from **real threat-intel sources**, and
analyst-ready IOCs with MITRE ATT&CK mapping.

## Features
| Area | What it does |
|------|--------------|
| SPF | Full RFC 7208 evaluation of the delivering IP (include/a/mx/ip4/ip6/redirect, 10-lookup limit) |
| DKIM | Real cryptographic verification (dkimpy) + selector key lookup, key strength, alignment |
| DMARC | Policy discovery (org-domain fallback), SPF/DKIM alignment (relaxed/strict) |
| Routing | Received-chain parsing, hop delays, origin IP, GeoIP / ASN / proxy flags, Spamhaus ZEN + SpamCop |
| Sender | Display-name spoofing, brand impersonation, Reply-To / Return-Path mismatch, RDAP domain age |
| URLs | Text-vs-href mismatch, punycode, lookalikes, shorteners, redirectors, OpenPhish feed, Spamhaus DBL, VirusTotal |
| Attachments | Hashes, magic-byte vs extension, double extension, macros (OLE + OOXML), remote template injection, PDF JS/Launch, HTML smuggling, encrypted archives, VirusTotal |
| Output | Risk score, MITRE ATT&CK map, defanged IOC list, JSON / HTML report / IOC CSV |

## Run
```
run.bat                      # GUI (creates venv on first run)
run.bat sample.eml           # GUI, auto-analyze
python main.py sample.eml --cli --html report.html --json out.json --ioc iocs.csv
```
Optional: Settings -> VirusTotal API key (free key works). Everything else needs no key.

## Safety
Attachments are parsed as bytes only - nothing is executed or rendered. HTML bodies are never rendered; links are shown defanged.

## Data sources
DNS (SPF/DKIM/DMARC/DNSBL), RDAP (rdap.org), ip-api.com, OpenPhish community feed, Spamhaus DBL/ZEN, SpamCop, VirusTotal v3.
