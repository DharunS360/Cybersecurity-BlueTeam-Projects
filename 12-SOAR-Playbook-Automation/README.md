# 12 - SOAR Playbook Automation

### Phase 1: Threat-Intelligence Enrichment & Verdict Engine

![Python](https://img.shields.io/badge/Python-3.11%2B-blue) ![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6) ![Sources](https://img.shields.io/badge/Live%20Sources-9-orange) ![Tests](https://img.shields.io/badge/Unit%20Tests-76-brightgreen) ![Data](https://img.shields.io/badge/Data-Live%20only%2C%20no%20dummy-red) ![Status](https://img.shields.io/badge/Status-Phase%201%20Complete-yellow)

A SOAR (Security Orchestration, Automation and Response) core that takes a **real alert artefact**
(a phishing `.eml`, a Wazuh or Sysmon JSON alert, a CSV, any log file), extracts every indicator of
compromise (IOC), enriches each one against **nine live threat-intelligence sources in parallel**, and returns an
**explainable verdict** with evidence, verification links and a **tamper-evident audit trail**.

> **No demo data. No dummy data. No hard-coded verdicts.** Every score is calculated from what live sources
> returned at query time. Unit tests use mocked HTTP responses only, so the logic can be verified offline;
> the product itself never fabricates data.

---

## Table of Contents

1. [What problem it solves](#1-what-problem-it-solves)
2. [Why you can trust the result](#2-why-you-can-trust-the-result)
3. [Technology stack](#3-technology-stack)
4. [Architecture and data flow](#4-architecture-and-data-flow)
5. [Project structure (file by file)](#5-project-structure-file-by-file)
6. [Threat-intelligence sources](#6-threat-intelligence-sources)
7. [How each stage works](#7-how-each-stage-works)
8. [Scoring model](#8-scoring-model)
9. [Audit log (tamper-evident)](#9-audit-log-tamper-evident)
10. [Installation](#10-installation)
11. [Configuration](#11-configuration)
12. [Usage and command reference](#12-usage-and-command-reference)
13. [Example output (real run, trimmed)](#13-example-output-real-run-trimmed)
14. [JSON report format](#14-json-report-format)
15. [Testing](#15-testing)
16. [Design decisions](#16-design-decisions)
17. [Troubleshooting](#17-troubleshooting)
18. [Known limitations](#18-known-limitations)
19. [Roadmap](#19-roadmap)
20. [Responsible use](#20-responsible-use)

---

## 1. What problem it solves

A SOC analyst receives an alert and must answer one question quickly: **"Is this indicator malicious?"**
Doing it by hand means opening VirusTotal, AbuseIPDB, OTX, URLhaus and more in separate tabs, copying results
into a ticket, and hoping nothing was missed. This project automates that step of the workflow:

| Manual analyst step | What this tool does |
|---|---|
| Read the alert and pick out IPs, URLs, hashes | Extracts and validates every IOC automatically, including defanged ones (`hxxp`, `[.]`) |
| Open 5-9 intelligence sites | Queries 9 sources in parallel with rate limiting and caching |
| Judge conflicting answers | Combines them into one explainable score |
| Write down why | Stores evidence, links and a hash-chained audit trail |

---

## 2. Why you can trust the result

| Principle | How it is enforced in code |
|---|---|
| **Evidence, not opinion** | Every finding stores the source, the reason, key evidence fields and a link so the analyst can verify it. |
| **Explainable score** | `score = sum of points from sources that answered (cap 100)`. Each point is printed as `+N Source: reason`. |
| **Failure is never "clean"** | A timeout, rejected key, rate limit or parse error becomes `ERR` or `RATE`. If no source answered, the verdict is **Unknown**. |
| **Coverage is visible** | Output shows `(6/6 sources answered)` and lists sources that failed or were skipped because no key is set. |
| **"Not Flagged" is honest** | The tool never says "Clean". One clean answer is labelled low confidence. |
| **Benign knowledge is used** | AbuseIPDB whitelist and OTX false-positive validation can override weak noise (e.g. `8.8.8.8` becomes **Known Benign**). |
| **Conflicts are surfaced** | If a benign mark contradicts a strong detection, the result says `CONFLICT ... review manually` instead of hiding it. |
| **No silent drops** | Private IPs, allowlisted domains and over-limit IOCs are listed in a transparency log with the reason. |
| **Tamper-evident audit** | Every action is chained with SHA-256. `verify-audit` detects edited or deleted rows. |
| **Passive only** | Lookups only. Nothing is ever submitted to VirusTotal or any scanner, so no sample or URL is leaked. |

---

## 3. Technology stack

| Component | Technology | Why it was chosen |
|---|---|---|
| Language | **Python 3.11+** | Same baseline as the rest of this portfolio; runs on Python 3.14 as well (tested on Windows). |
| HTTP client | **requests** (the only third-party dependency) | Mature, reliable; connection pooling plus `urllib3` retry for 502/503/504. |
| Concurrency | `concurrent.futures.ThreadPoolExecutor` (8 workers) | Enrichment is network-bound; threads give parallel lookups with no extra dependency. |
| Storage | **SQLite** (`sqlite3`, WAL mode) | Zero setup, single file, transactional; holds cache, cases and audit log. |
| Integrity | `hashlib` SHA-256 hash chain | Makes the audit log tamper-evident without external services. |
| Validation | `ipaddress`, `urllib.parse`, `re` | Standard-library validation of every IP, URL and domain. |
| Email parsing | `email` (policy.default) | Parses headers, bodies and attachments of `.eml` files without extra packages. |
| CLI | `argparse` + ANSI colours | No dependency; colours work in Windows 10/11 terminals. |
| Tests | `unittest` | Same style as the other projects; no pytest needed. |
| CI | GitHub Actions | Ubuntu and Windows, Python 3.11 and 3.12. |

**Dependency file:** `requirements.txt` contains a single line, `requests>=2.31`. A small dependency surface
means fewer installation problems and a smaller supply-chain risk.

---

## 4. Architecture and data flow

```
 INPUT                    EXTRACT              ENRICH (parallel)                  DECIDE            RECORD
+--------------+      +-------------+      +------------------------+      +----------------+   +-----------------+
| .eml         |      |  ioc.py     |      |  engine.py             |      | scoring.py     |   | store.py        |
| .json/.jsonl | ---> |  Collector  | ---> |  ThreadPool x 8        | ---> | explainable    |-->| SQLite          |
| .csv         |      |  refang     |      |  cache -> rate limit   |      | score + label  |   |  cases          |
| .log/.txt    |      |  validate   |      |  -> provider.lookup()  |      | benign override|   |  cache          |
| stdin / --ioc|      |  dedupe     |      |                        |      | conflict notes |   |  audit_log      |
+--------------+      +-------------+      +-----------+------------+      +----------------+   |  (hash chain)   |
   ingest.py            transparency log               |                                          +-----------------+
                        (skipped IOCs)      +----------+-----------+
                                            | providers/*          |
                                            | VirusTotal AbuseIPDB |
                                            | OTX URLhaus          |
                                            | MalwareBazaar        |
                                            | ThreatFox  Feodo     |
                                            | CISA KEV  EPSS       |
                                            +----------------------+
```

**Step by step for one `analyze` command:**

1. `cli.py` reads the input and calls `ingest.load_alert()`.
2. `ingest.py` picks a parser by file type and feeds every string to `ioc.Collector.scan()`.
3. `ioc.py` un-defangs, extracts, validates and de-duplicates indicators, recording where each was seen.
4. `engine.analyze()` creates a case ID and writes the first audit entry (`case.created`).
5. For every (indicator, provider) pair that applies, a task is queued on the thread pool.
6. `engine.query()` runs each task: skip if no key, return cache hit if fresh, otherwise call `provider.lookup()`.
7. Errors are converted into explicit findings (`ERR`, `RATE`); they are never cached and never treated as clean.
8. Every query writes an `enrich.query` audit entry (provider, indicator, status, points, cached, milliseconds).
9. `scoring.aggregate()` turns the findings into a score, a label and notes for each indicator.
10. The overall case verdict is the worst indicator; `case.verdict` is written to the audit log; the case is saved.
11. `cli.py` prints the report and optionally writes JSON. Exit code `2` means Malicious.

---

## 5. Project structure (file by file)

```
12-SOAR-Playbook-Automation/
|-- README.md                  this document
|-- CHANGELOG.md               version history
|-- requirements.txt           runtime dependency (requests)
|-- .env.example               template for API keys (copy to .env)
|-- .gitignore                 keeps .env, data/ and caches out of Git
|-- soar/                      the application package (about 1,650 lines)
|   |-- __main__.py            enables:  python -m soar
|   |-- __init__.py            version string
|   |-- cli.py                 commands, ANSI rendering, exit codes
|   |-- config.py              Settings, .env loader (never overrides real env vars)
|   |-- models.py              IOC, Finding, IOCVerdict, Alert, CaseResult, enums
|   |-- ioc.py                 defang-aware IOC extraction, validation, allowlist
|   |-- ingest.py              parsers for .eml, .json/.jsonl, .csv, text
|   |-- http.py                HttpClient, RateLimiter, ProviderError (typed failures)
|   |-- engine.py              pipeline orchestration, parallelism, caching, audit hooks
|   |-- scoring.py             explainable scoring, benign override, conflict notes
|   |-- store.py               SQLite: cache, cases, hash-chained audit log
|   `-- providers/
|       |-- base.py            Provider and FeedProvider base classes
|       |-- virustotal.py      VirusTotal v3 (IP, domain, URL, hash)
|       |-- abuseipdb.py       AbuseIPDB v2 (IP)
|       |-- otx.py             AlienVault OTX (IP, domain, URL, hash)
|       |-- abusech.py         URLhaus, MalwareBazaar, ThreatFox
|       `-- feeds.py           Feodo Tracker, CISA KEV, FIRST EPSS
|-- tests/                     76 unit tests (about 660 lines)
|   |-- helpers.py             test doubles: FakeHttp, FakeResp (tests only)
|   |-- test_ioc.py            15 tests  - extraction and validation
|   |-- test_providers.py      28 tests  - every provider parser and HTTP error mapping
|   |-- test_scoring.py        10 tests  - bands, benign override, conflicts
|   |-- test_engine.py          9 tests  - pipeline, cache, error containment
|   |-- test_ingest.py          9 tests  - eml, json, jsonl, csv, logs
|   `-- test_store.py           5 tests  - audit chain, tamper detection, cache TTL
`-- data/                      created at runtime (git-ignored)
    |-- soar.db                SQLite database
    |-- feeds/                 cached Feodo and CISA KEV feeds
    `-- allowlist.txt          optional: your own trusted domains
```

---

## 6. Threat-intelligence sources

| # | Source | Indicator types | API key | Rate limit enforced | What it tells you |
|---|---|---|---|---|---|
| 1 | **VirusTotal** v3 | IP, domain, URL, hash | free | 4 requests/min | How many of ~70-90 engines flag it, threat label, reputation |
| 2 | **AbuseIPDB** v2 | IP | free | 30/min | Community abuse confidence (0-100%), report count, whitelist flag |
| 3 | **AlienVault OTX** | IP, domain, URL, hash | free | 60/min | Number of community threat "pulses" referencing it, benign validation |
| 4 | **URLhaus** (abuse.ch) | URL, domain, IP | abuse.ch Auth-Key | 60/min | Known malware-distribution URLs and hosts, online or offline |
| 5 | **MalwareBazaar** (abuse.ch) | hash | abuse.ch Auth-Key | 60/min | Known malware sample, family signature, file type |
| 6 | **ThreatFox** (abuse.ch) | IP, domain, URL | abuse.ch Auth-Key | 60/min | IOC database: malware family, threat type, confidence |
| 7 | **Feodo Tracker** (abuse.ch) | IP | none | feed cached 1 h | Botnet command-and-control (C2) blocklist |
| 8 | **CISA KEV** | CVE | none | feed cached 12 h | Vulnerabilities exploited in the wild, ransomware use |
| 9 | **FIRST EPSS** | CVE | none | 60/min | Probability of exploitation in the next 30 days |

One abuse.ch Auth-Key (from `auth.abuse.ch`) covers URLhaus, MalwareBazaar and ThreatFox.
Sources whose key is missing are marked `SKIP` in the output; the tool still works with any subset.

**Which sources answer for which indicator:**

| Indicator | Sources queried |
|---|---|
| IP address | VirusTotal, AbuseIPDB, OTX, URLhaus, ThreatFox, Feodo Tracker |
| Domain | VirusTotal, OTX, URLhaus, ThreatFox |
| URL | VirusTotal, OTX, URLhaus, ThreatFox |
| File hash (MD5/SHA-1/SHA-256) | VirusTotal, OTX, MalwareBazaar |
| CVE | CISA KEV, FIRST EPSS |
| Email address | Not enriched directly; its domain is extracted and enriched |

---

## 7. How each stage works

### 7.1 IOC extraction (`ioc.py`)

| Rule | Behaviour |
|---|---|
| **Defang handling** | `hxxp://`, `hxxps://`, `[.]`, `(.)`, `{.}`, `[dot]`, `[:]`, `[://]`, `[@]`, `[at]` are reversed before scanning. |
| **IPv4 / IPv6** | Candidates are validated with Python's `ipaddress`. Version numbers (`10.0.19045.1`) and octets above 255 are rejected. |
| **Public IPs only** | Private, loopback, link-local, multicast and reserved ranges are not sent to any external service. They appear in the transparency log with the reason. |
| **URLs** | Trailing punctuation and unbalanced brackets are trimmed. The host is also extracted as a domain or IP indicator. |
| **Domains** | The TLD must be in an embedded list (all gTLDs and ccTLDs commonly seen). File names such as `setup.exe`, `app.py`, `config.yaml` are not domains. |
| **Ambiguous TLDs** | `.sh .pl .rs .md .pm .so .ps .zip .mov` collide with file names, so a bare `script.sh` is ignored but `http://evil.sh/x` and `a@evil.sh` are accepted. |
| **Hashes** | Exact lengths 32, 40 or 64 hex characters; must not be part of a longer hex string; junk values (all zeros, repeated characters) are dropped. |
| **E-mail / CVE** | Addresses are lower-cased and their domain is added; CVE IDs are upper-cased. |
| **Allowlist** | Built-in noise (XML namespaces such as `schemas.microsoft.com`, `system.net`, `example.com`) plus your own `data/allowlist.txt`. Subdomains are matched. |
| **Deduplication** | Each indicator appears once, with up to five locations where it was seen. |

### 7.2 Ingestion (`ingest.py`)

| Input | What is extracted |
|---|---|
| `.eml` | Headers `From, Reply-To, Return-Path, Sender, X-Originating-IP`, every `Received` hop (sender IPs), URLs in both `text/plain` and `text/html` bodies, **SHA-256 of every attachment computed locally**, SPF/DKIM/DMARC results from `Authentication-Results`, subject, date, message ID |
| `.json` / `.jsonl` | Every string and number in the document, with its **field path** (e.g. `data.srcip`). Title and severity are detected from common keys; Wazuh (`agent.name`, `rule.id`, `rule.groups`) and Sysmon (`Computer`) hints go into metadata |
| `.csv` | Every cell, recorded by row and column name |
| `.log`, `.txt`, stdin | Line-by-line scan, recorded by line number |
| `--ioc` | Indicators typed on the command line |

This means the JSON output of Projects 03, 07, 08 and 09 in this portfolio can be fed straight in.

### 7.3 Enrichment (`engine.py`, `http.py`, `providers/`)

| Mechanism | Detail |
|---|---|
| **Parallelism** | One task per (indicator, provider); 8 worker threads. |
| **Rate limiting** | Per-provider reservation limiter spaces calls by `60 / limit` seconds and is thread-safe, so the free VirusTotal quota is respected automatically. |
| **Caching** | Successful answers (`ok`, `not_found`) are cached in SQLite: 24 h for hashes, 6 h for everything else. Errors are never cached. `--no-cache` forces fresh lookups. |
| **Feeds** | Feodo (1 h) and CISA KEV (12 h) are downloaded once and cached on disk. If a refresh fails, the stale copy is used and **labelled STALE**. |
| **Retries** | `502/503/504` are retried twice with back-off. |
| **Typed failures** | `ProviderError` has a kind: `auth`, `rate_limit`, `timeout`, `network`, `http`, `parse`. |
| **Containment** | A bug inside one provider becomes an `ERR` finding; it can never crash a case. |
| **Passive** | Only read/lookup endpoints are used. Nothing is uploaded or submitted for scanning. |

---

## 8. Scoring model

**Formula:** `score = min(100, sum of points from every source that answered)`.
Sources that failed or were skipped contribute nothing and are listed separately.

### 8.1 Points per source

| Source | Condition | Points |
|---|---|---|
| **VirusTotal** | 20+ engines malicious, or 5+ engines and 40%+ of all engines | +75 |
| | 10-19 engines | +60 |
| | 5-9 engines | +45 |
| | 2-4 engines | +30 |
| | exactly 1 engine (weak, often a false positive) | +15 |
| | 0 malicious but 3+ suspicious | +10 |
| **AbuseIPDB** | confidence 75-100% | +50 |
| | 50-74% | +40 |
| | 25-49% | +25 |
| | 1-24% | +10 |
| | flagged `isWhitelisted` | 0 and marked **benign** |
| **AlienVault OTX** | 10+ pulses | +30 |
| | 3-9 pulses | +20 |
| | 1-2 pulses | +10 |
| | OTX validation says benign (e.g. "Known False Positive") | 0 and marked **benign** |
| **URLhaus** | URL listed and online / offline | +70 / +50 |
| | host serves malware URLs, some online / none online | +65 / +45 |
| **MalwareBazaar** | hash is a known sample | +80 |
| **ThreatFox** | confidence 75% or more / lower | +60 / +40 |
| **Feodo Tracker** | listed C2, status online / offline (offline IPs may be reassigned) | +80 / +60 |
| **CISA KEV** | CVE is exploited in the wild | +80 |
| **FIRST EPSS** | probability 70%+ / 30%+ / 10%+ | +30 / +20 / +10 |

### 8.2 Verdict labels

| Score | Verdict | Meaning |
|---|---|---|
| 70 - 100 | **Malicious** | Strong or corroborated evidence |
| 40 - 69 | **Suspicious** | Meaningful signals; investigate |
| 10 - 39 | **Low Risk** | Weak signals only |
| 0 - 9 | **Not Flagged** | No source flagged it. This is **not** proof it is safe |
| benign mark and score below 40 | **Known Benign** | A trusted source vouches for it; weak noise is ignored |
| no source answered | **Unknown** | Never presented as clean |
| e-mail address | **Not Enriched** | Context only; its domain is enriched |

The **overall case verdict** is the worst indicator in the alert.

### 8.3 Notes the tool adds automatically

| Situation | Note |
|---|---|
| Two or more sources scored 40+ | `corroborated by N independent sources` |
| Only one source answered and nothing was flagged | `only one source answered - low confidence, do not treat as clean` |
| Benign mark overrides weak noise | `marked benign by ...; weak residual signals ignored (...)` |
| Benign mark but strong detection | `CONFLICT: ... say benign but other sources flag it - review manually` |
| A source failed | `sources that did not answer: ...` |
| A key is missing | `not queried (no API key): ...` |

---

## 9. Audit log (tamper-evident)

Every action is appended to the `audit_log` table as a hash chain:

```
entry_hash = SHA-256( previous_hash | timestamp | actor | action | case_id | detail_json )
```

The first entry chains to a genesis value of 64 zeros. Changing, inserting or deleting any past row breaks every
later hash, which `python -m soar verify-audit` detects and reports with the first broken entry number.

| Action | Written when |
|---|---|
| `case.created` | A case starts (source, title, input SHA-256, indicator counts) |
| `enrich.query` | Every provider call (provider, indicator, status, points, cached, milliseconds) |
| `case.verdict` | The case finishes (score and verdict) |

`python -m soar show <CASE-ID> --audit` prints the full trail of one case.

---

## 10. Installation

Requirements: Windows 10/11, **Python 3.11 or newer**, internet access.

```powershell
git clone https://github.com/DharunS360/Cybersecurity-BlueTeam-Projects.git
cd Cybersecurity-BlueTeam-Projects\12-SOAR-Playbook-Automation
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
notepad .env
python -m soar doctor
```

No administrator rights are needed.

---

## 11. Configuration

Secrets are read from environment variables or from a local `.env` file (git-ignored). Real environment variables
always take priority over `.env`.

| Variable | Required | Purpose |
|---|---|---|
| `VT_API_KEY` | optional | VirusTotal key (free tier works) |
| `ABUSEIPDB_API_KEY` | optional | AbuseIPDB key (free tier works) |
| `OTX_API_KEY` | optional | AlienVault OTX key (free) |
| `ABUSECH_API_KEY` | optional | abuse.ch Auth-Key for URLhaus, MalwareBazaar, ThreatFox |
| `SOAR_DATA_DIR` | optional | Folder for the database, feeds and allowlist (default: `./data`) |
| `SOAR_MAX_IOCS` | optional | Maximum indicators enriched per alert (default: 50). Extra ones are reported, not silently dropped |

| Built-in setting | Value |
|---|---|
| HTTP timeout | 20 seconds |
| Worker threads | 8 |
| Cache lifetime | 24 h for hashes, 6 h otherwise |

**Allowlist:** create `data/allowlist.txt` with one domain per line (`#` for comments) to exclude trusted domains.

---

## 12. Usage and command reference

| Command | Purpose |
|---|---|
| `python -m soar doctor` | Live-tests every configured source and reports PASS / FAIL / SKIP with latency |
| `python -m soar analyze --ioc <values...>` | Analyse one or more indicators (IP, domain, URL, hash, CVE) |
| `python -m soar analyze --file <path>` | Analyse a `.eml`, `.json`, `.jsonl`, `.csv`, `.log` or `.txt` file |
| `python -m soar analyze --text "<text>"` | Scan raw text for indicators |
| `Get-Content log.txt \| python -m soar analyze` | Read from standard input |
| `python -m soar cases [--limit N]` | List recent cases |
| `python -m soar show <CASE-ID>` | Print a stored case as JSON |
| `python -m soar show <CASE-ID> --audit` | Print that case's audit trail |
| `python -m soar verify-audit` | Verify the hash chain of the whole audit log |

| `analyze` option | Meaning |
|---|---|
| `--json <path>` | Also write the full report as JSON |
| `--title "<text>"` | Override the case title |
| `--no-cache` | Force fresh lookups |
| `-v`, `--verbose` | Show skipped sources and a verification link for every finding |

| Exit code | Meaning |
|---|---|
| `0` | Success, verdict not Malicious |
| `1` | Input error, or `doctor` found failing sources |
| `2` | Overall verdict is **Malicious** (lets scripts and playbooks branch) |
| `3` | `verify-audit` found tampering |

**Examples**

```powershell
python -m soar analyze --ioc CVE-2021-44228
python -m soar analyze --ioc 8.8.8.8 185.220.101.4 evil-example[.]com -v
python -m soar analyze --file C:\path\to\suspicious.eml --json report.json -v
python -m soar analyze --file alert.json --title "Wazuh SSH brute force"
python -m soar cases
python -m soar show CASE-20261114-F4AC0F --audit
python -m soar verify-audit
```

---

## 13. Example output (real run, trimmed)

Botnet C2 IP taken live from the Feodo Tracker blocklist, all nine sources active:

```
CASE-20261114-F4AC0F   Manual indicator lookup
====================================================================================================
OVERALL:  MALICIOUS   score 100/100
====================================================================================================

[Malicious] IP     162.243.103.246   score 100  (6/6 sources answered)
    +60  VirusTotal      14/92 engines flag malicious, 0 suspicious
    0    AbuseIPDB       abuse confidence 0% (1 reports from 1 users, last 90d)
    +30  AlienVault OTX  referenced in 50 community pulse(s)
    0    URLhaus         not listed on URLhaus
    +60  ThreatFox       2 ThreatFox record(s): Cobalt Strike (botnet_cc), confidence 90%
    +80  Feodo Tracker   listed botnet C2: Emotet port 8080 (offline) - feed age 0.2h
   note: corroborated by 3 independent sources
```

Google public DNS - a well-known benign address that one VirusTotal engine flags:

```
[Known Benign] IP     8.8.8.8   score 0  (6/6 sources answered)
    +15  VirusTotal      1/92 engines flag malicious, 0 suspicious
      0  AbuseIPDB       abuse confidence 0% (194 reports from 68 users) - listed as WHITELISTED by AbuseIPDB
      0  AlienVault OTX  referenced in 0 community pulse(s) - OTX validation marks it benign (Known False Positive)
      0  URLhaus         not listed on URLhaus
      0  ThreatFox       not listed on ThreatFox
      0  Feodo Tracker   not on current Feodo C2 blocklist
   note: marked benign by AbuseIPDB, AlienVault OTX; weak residual signals ignored (VirusTotal +15)
```

The EICAR anti-malware test file is recognised as harmless by design:

```
+75  VirusTotal  66/68 engines flag malicious (label: virus.eicar/test) - EICAR antivirus TEST file, harmless by design
```

---

## 14. JSON report format

`--json report.json` writes the complete case. Top-level fields:

| Field | Description |
|---|---|
| `case_id`, `created_at` | Unique case ID (`CASE-YYYYMMDD-XXXXXX`) and UTC timestamp |
| `source`, `title`, `severity` | Where the alert came from and how it was titled |
| `input_sha256` | SHA-256 of the analysed input (evidence integrity) |
| `meta` | Format-specific context (e-mail headers, SPF/DKIM/DMARC, attachment hashes, agent name, rule ID ...) |
| `overall_score`, `overall_verdict` | Case-level result |
| `skipped_indicators` | Everything excluded from enrichment, each with a reason |
| `indicators[]` | One object per indicator: `type`, `value`, `seen_in`, `score`, `verdict`, `sources_answered`, `sources_applicable`, `notes`, and `findings[]` |
| `findings[]` | Per source: `provider`, `status`, `points`, `reason`, `evidence`, `link`, `queried_at`, `cached` |

Finding `status` values: `ok`, `not_found`, `error`, `rate_limited`, `skipped`.

---

## 15. Testing

```powershell
python -m unittest discover -s . -p "test_*.py" -t . -v
```

**76 unit tests** run on every push via GitHub Actions (Ubuntu and Windows, Python 3.11 and 3.12).

| Test file | Tests | What it proves |
|---|---|---|
| `test_ioc.py` | 15 | Defanging, public/private IPs, version numbers not IPs, file names not domains, ambiguous TLDs, hashes, IPv6, allowlist, URL punctuation, de-duplication |
| `test_providers.py` | 28 | Every provider's parsing and points; HTTP error mapping (401/403/429/5xx/timeout/network); 404 handling; ThreatFox exact-IP filtering; feed disk caching and stale fallback; VirusTotal consensus rule; EICAR labelling; Feodo offline scoring |
| `test_scoring.py` | 10 | Verdict bands, point summing and cap, errors never clean, coverage reporting, benign override, benign-versus-strong conflict |
| `test_engine.py` | 9 | End-to-end pipeline, audit trail contents, cache hit and bypass, errors not cached, rate-limit status, buggy provider contained, missing-key skip, indicator-type routing, `SOAR_MAX_IOCS` cap reporting, JSON serialisation |
| `test_ingest.py` | 9 | Wazuh-style JSON with field paths, Sysmon hashes, JSONL, invalid JSON error, CSV row/column, log line numbers, full `.eml` (headers, body, attachment hash, SPF/DKIM/DMARC) |
| `test_store.py` | 5 | Valid chain, empty log, **tampered row detected**, **deleted row detected**, cache round trip and TTL |

The mocks live only in `tests/helpers.py`. The application code contains no mock or sample data.

---

## 16. Design decisions

| Decision | Reason |
|---|---|
| Failure is a first-class result | In security tooling, "no answer" must never look like "safe". |
| Points per source instead of a black-box model | Analysts can see and argue with every point. |
| Passive lookups only | Submitting a sample or URL can tip off an attacker or leak private data. |
| SQLite and standard library | Runs anywhere with one `pip install`; easy to audit. |
| Hash-chained audit log | Cheap, dependency-free tamper evidence for incident records. |
| Weak evidence is weighted low | A single VirusTotal engine or a community pulse is context, not proof. |
| Benign knowledge is used | Reduces false positives on well-known infrastructure. |
| Local attachment hashing | The file never leaves the machine; only its hash is looked up. |

---

## 17. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `SKIP ... no API key` in `doctor` | The key is empty or `.env` was not saved. Check `.env`, press Ctrl+S, no spaces or quotes around the key. |
| `FAIL ... auth: HTTP 401/403` | The key is wrong or not activated. Re-copy it. For abuse.ch use the Auth-Key from `auth.abuse.ch`. |
| `RATE ... 429` | Free quota used up (VirusTotal: 4/min, 500/day). Wait, or rely on the cache. |
| `ERR ... cannot connect` | No internet, DNS, proxy or firewall problem. |
| `Unknown` verdict | No source could answer. This is deliberate - it is **not** a clean result. Run `doctor`. |
| `input file not found` | Wrong path. Use the real file name. |
| `AUDIT LOG TAMPERED` | A row in `data/soar.db` was changed or removed after being written. |

---

## 18. Known limitations

- Threat intelligence is probabilistic. No tool can guarantee 100% accuracy; this one shows its evidence so a human can verify.
- A brand-new malicious domain may be unknown to every source. That is why "Not Flagged" is never "Clean".
- Scoring weights are expert-chosen, not statistically trained; they are documented above and easy to change.
- The embedded TLD list is not the full IANA list.
- Free API tiers are rate limited; large alerts are capped by `SOAR_MAX_IOCS` and the cap is reported.
- Phase 1 enriches and decides; response actions are not implemented yet (see roadmap).

---

## 19. Roadmap

| Phase | Scope | Status |
|---|---|---|
| **1** | Ingestion, IOC extraction, 9-source enrichment, explainable scoring, audit log, CLI, tests, CI | **Complete** |
| 2 | YAML playbooks (phishing, brute force, malware hash, suspicious IP, C2), response actions, analyst approval gate | Planned |
| 3 | Flask web dashboard: case view, IOC timeline, MITRE ATT&CK tags, HTML/PDF report export | Planned |
| 4 | Docker, extended CI, direct integration with Projects 03, 07, 08, 09 and 10 | Planned |

---

## 20. Responsible use

Built for defensive and educational purposes. Analyse only data you own or are authorised to assess.
API keys are read from environment variables or a git-ignored `.env`; no secrets are stored in this repository.

Released under the MIT License (see the repository root).