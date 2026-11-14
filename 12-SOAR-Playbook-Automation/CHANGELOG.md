# Changelog

All notable changes to Project 12 - SOAR Playbook Automation.

## [0.1.1] - Phase 1.1
### Fixed
- 8.8.8.8 (Google DNS) was shown as Low Risk because one VirusTotal engine flagged it. AbuseIPDB whitelist and
  OTX false-positive validation are now honoured: such indicators become **Known Benign**.
- VirusTotal overwhelming consensus (20+ engines, or 40%+ of engines) is now +75 and Malicious on its own, instead of
  depending on noisy community-pulse points.
- Feodo Tracker C2 addresses with status `offline` score +60 instead of +80 (the address may have been reassigned).
### Added
- `CONFLICT` note when a benign mark contradicts a strong detection.
- EICAR test files are labelled "harmless by design".
- `Store.close()`; unit tests no longer leak database connections.
- Unit tests: 71 -> 76.

## [0.1.0] - Phase 1
### Added
- Ingestion for `.eml`, `.json`, `.jsonl`, `.csv`, logs and stdin with field-path tracking.
- Defang-aware, validated IOC extraction with a transparency log of excluded indicators.
- Nine live sources: VirusTotal, AbuseIPDB, OTX, URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker, CISA KEV, FIRST EPSS.
- Parallel enrichment with per-provider rate limiting, SQLite caching and typed failure handling.
- Explainable scoring; failures never reported as clean.
- Hash-chained, tamper-evident audit log with `verify-audit`.
- CLI: `analyze`, `doctor`, `cases`, `show`, `verify-audit`.
- 71 unit tests and a GitHub Actions workflow (Ubuntu and Windows, Python 3.11 and 3.12).