# Detection reference

All thresholds are constants or literals in `core/analyzer.py`. Every alert is de-duplicated with a 300 second
per-key cooldown and can be suppressed through the allowlist (`data/allowlist.txt`).

| Detection | Logic | Known false positives | Tuning |
|---|---|---|---|
| Known Malicious IP | Remote (non-private) IP found in Feodo or ET compromised-IP lists on new flow | Stale list entries, shared hosting | Allowlist the IP; refresh feeds |
| Malicious Domain | DNS query name or TLS SNI equals or is a subdomain of a URLhaus host | Compromised legitimate sites | Allowlist the domain/IP |
| Malicious JA3 | ClientHello JA3 MD5 present in SSLBL list | Shared fingerprints with legitimate clients | Check SNI and process before escalating |
| Port Scan | In 10 s, one source sends SYN-only to 20+ distinct (host, port) pairs, 15+ distinct ports, 3 or fewer hosts | Vulnerability scanners, some P2P apps | Allowlist the scanner source |
| Network Sweep | In 10 s, one source sends SYNs to 20+ internal hosts on 3 or fewer ports | Network inventory tools | Allowlist the source |
| SYN Flood | 300+ SYNs to one destination within 5 s | Load tests | Raise the threshold in `_scan` |
| Beaconing | 8+ new connections to the same external host/port, mean interval 5-3600 s, coefficient of variation 0.20 or less (DNS: 0.10) | Updaters, telemetry, chat/keep-alive, NTP-like services | Verify process and destination reputation; allowlist |
| DNS Tunneling | Name 70+ chars, or subdomain 25+ chars with entropy 3.7+, or TXT/NULL query with 20+ char subdomain, or 40+ unique subdomains of one parent in 60 s | CDN and anti-virus lookups with long hashed names (common suffixes are excluded) | Extend `DNS_SAFE` |
| Possible DGA | Second-level label 12+ chars, entropy 3.3+, and (digits 25%+ or vowels 20% or less), no hyphen | Auto-generated cloud hostnames | Allowlist the domain |
| NXDOMAIN Storm | 15+ NXDOMAIN answers to one client in 60 s | Misconfigured search suffixes, ad-blockers | Check resolver config |
| ARP Spoofing | A known IP-to-MAC binding changes | DHCP re-lease, NIC failover, VMs | Verify gateway MAC out of band |
| Rogue DHCP | DHCP offers (server to port 68) from more than one source IP | Intentional redundant DHCP servers | Allowlist the second server |
| ICMP Tunneling | 5+ ICMP echo packets with 128+ byte payload between a host pair within 60 s | Large-payload ping tests | Allowlist the pair |
| Cleartext Credentials | HTTP Basic header, HTTP POST body with `password=`/`passwd=`/`pwd=`/`pass=`, FTP/POP3 `PASS`, IMAP `LOGIN` | Legacy internal apps | Move the service to TLS |
| Large Upload | One external flow with 50 MB or more sent and at least 10x more sent than received | Backups, cloud sync, video calls | Allowlist the destination |
| Risky Outbound Port | Outbound SYN to Telnet, SMB, RDP, VNC, MSSQL, MySQL, WinRM, IRC, Tor (9001), 4444, 31337 | Admin work over VPN | Allowlist the destination |

## Severity and risk score

Alert severity maps to points (Critical 100, High 70, Medium 40, Low 15). A remote host's risk score is the highest
severity seen for it, and the score is shown in the Flows, Destinations and Processes tabs. The "High-risk hosts"
counter counts hosts with a score of 70 or more.

## Notes on MITRE ATT&CK mapping

Mappings indicate the technique a behaviour is **consistent with**, not proof of that technique. Analysts should
validate each alert against context (process, destination reputation, user activity).