# Changelog

## 2.0.0
- Flow tracking with per-flow bytes, packets, duration and TCP state
- Process attribution (name + PID) via psutil
- TLS ClientHello parsing: SNI and JA3 fingerprints
- GeoIP / ASN / reverse-DNS enrichment (optional online lookups)
- Threat intel: Feodo, Emerging Threats, URLhaus and SSLBL JA3 feeds with per-feed status and local cache
- New detections: malicious domain/JA3, DGA, NXDOMAIN storm, ARP spoofing, rogue DHCP, SYN flood, ICMP tunneling,
  cleartext credentials, large upload, risky outbound ports
- Alert triage: explanation + response advice, allowlist, per-host risk score, IOC lookup
- Evidence and export: PCAP save, HTML/JSON/CSV reports, SIEM-ready JSONL logs
- Unit tests and GitHub Actions CI

## 1.0.0
- Live packet capture and PCAP analysis
- Port scan, beaconing and DNS tunneling detection with MITRE ATT&CK mapping
- Dashboard, top talkers and DNS views