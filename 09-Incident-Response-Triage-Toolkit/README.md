# 09 - Incident Response Triage Toolkit

Live Windows incident-response triage console for blue teams. It collects **real volatile and persistent artifacts from the running host**
(no sample data), scores them against detection rules mapped to **MITRE ATT&CK**, builds a unified **timeline**, extracts **IOCs**,
and exports a forensically-sound **case folder** (JSON, CSV, HTML report, IOC feed, chain of custody, SHA-256 manifest).

## What it collects
| Area | Source |
|---|---|
| Processes | psutil: path, cmdline, parent chain, user, start time, SHA-256, Authenticode signature |
| Network | live TCP/UDP table mapped to process, DNS-cache hostname enrichment, public/private scoping |
| Persistence | Run/RunOnce, Winlogon, AppInit, IFEO, cmd AutoRun, Startup folders, Services, Scheduled Tasks, WMI subscriptions |
| Event logs | Security (4624/4625/4688/4697/4698/4720/4728/4732/4756/1102), System (7045/104), PowerShell 4104, Defender |
| Files / execution | recent executables & scripts in user-writable dirs, Prefetch, Recent LNKs |
| System state | local users/admins, sessions, DNS cache, ARP, SMB shares, hosts file, RDP, firewall, Defender status + exclusions |

## Detections (examples)
Process masquerading & look-alike names, Office/WMI/IIS spawning shells, encoded PowerShell, LOLBin abuse (certutil, mshta, regsvr32, rundll32, bitsadmin, wmic),
credential-dumping & shadow-copy deletion, offensive/dual-use tools, unsigned or tampered binaries, user-directory persistence, WMI/IFEO/Winlogon abuse,
brute force and success-after-failure, log clearing, new services/tasks/accounts, Defender/firewall tampering, double-extension droppers.

## Run
```powershell
pip install -r requirements.txt
python main.py            # GUI  (right-click terminal -> Run as administrator for full coverage)
python main.py --cli      # headless, exports to .\cases\<HOST>_<timestamp>\
```
Optional: set `VT_API_KEY` (or paste it in the GUI) to enrich hash / IP / domain IOCs with VirusTotal.

## Case folder
`report.html`, `case_data.json`, `csv\*.csv`, `iocs.csv`, `blocklist_iocs.txt`, `chain_of_custody.txt`, `SHA256SUMS.txt`

## Notes
Read-only collection. Run only on systems you are authorised to examine. Without Administrator rights the Security log,
Prefetch and Defender exclusions are unavailable (the tool reports this).
