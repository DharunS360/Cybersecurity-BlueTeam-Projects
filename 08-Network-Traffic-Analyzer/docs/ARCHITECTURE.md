# Architecture

## Design goals
- **Separation of concerns:** capture, parsing, analysis and presentation are independent modules.
- **Testability:** the parser emits a plain `Rec` dataclass, so the detection engine can be unit-tested with
  synthetic records and no capture driver.
- **Resilience:** every external dependency (threat feeds, GeoIP, process mapping) fails soft. A feed outage never
  stops capture.
- **SIEM-friendliness:** all events are also written as JSON Lines.

## Modules

| Module | Responsibility |
|---|---|
| `main.py` | PyQt5 console: capture controls, tables, charts, alert triage, report export. Contains no detection logic. |
| `core/parser.py` | Converts a Scapy packet into a `Rec` (addresses, L4 protocol, ports, flags, truncated payload, DNS/ARP fields). |
| `core/records.py` | `Rec` dataclass shared between parser, analyzer and tests. |
| `core/tls.py` | Parses a TLS ClientHello and returns SNI, TLS version and the JA3 fingerprint (GREASE values excluded). |
| `core/analyzer.py` | Flow table, per-host risk, all detections, alert cooldown/allowlist, JSONL logging, GUI snapshot. |
| `core/intel.py` | Downloads and caches IP, domain and JA3 indicators; IOC lookup. |
| `core/enrich.py` | Background GeoIP/ASN/reverse-DNS lookups and psutil-based socket-to-process mapping. |

## Data flow

1. **Capture:** Scapy `AsyncSniffer` (live, through Npcap) or `PcapReader` (offline) delivers packets.
2. **Parse:** `parser.parse()` produces a `Rec`; unparseable packets are dropped silently.
3. **Ingest:** `Analyzer.ingest()` (guarded by a lock) updates counters, the 20,000-packet ring buffer and the flow table.
4. **Flow tracking:** flows are keyed by a direction-independent 5-tuple. The local endpoint is determined from the
   host's own addresses (live) or private-address heuristics (PCAP).
5. **Detection:** per-record checks run (threat-intel match, scans, beaconing, DNS analytics, TLS, cleartext, ARP,
   DHCP, ICMP, exfiltration). Alerts pass through a 300 s per-key cooldown and the allowlist.
6. **Enrichment:** new external IPs are queued for GeoIP/ASN lookup in a background thread; the process mapper refreshes
   the OS socket table every second and flows look themselves up by local port.
7. **Presentation:** the GUI polls `Analyzer.snapshot()` once per second and renders only the visible tab.
8. **Persistence:** closed flows, DNS responses, TLS hellos and alerts are appended to `logs/*.jsonl`.

## Threading model

| Thread | Work |
|---|---|
| GUI thread | Rendering, user actions, 1 Hz refresh timer |
| Sniffer thread | Calls `Analyzer.process()` per packet |
| PCAP worker (QThread) | Reads an offline capture into the analyzer |
| Intel updater | Downloads feeds at start or on demand |
| Enricher | GeoIP/rDNS lookups from a queue |
| Process mapper | Polls `psutil.net_connections()` |

Shared analyzer state is protected by a re-entrant lock.

## Extending

- **New detection:** add a method in `Analyzer`, call it from `_ingest`, call `_raise(...)` with severity, kind and
  MITRE technique, add response text to `ADVICE`, and add a test in `tests/test_analyzer.py`.
- **New intel feed:** add an entry to `FEEDS` in `core/intel.py` with its type (`ip`, `domain` or `ja3`).