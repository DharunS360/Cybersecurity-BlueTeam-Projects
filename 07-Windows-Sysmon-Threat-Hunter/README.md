# 07-Windows-Sysmon-Threat-Hunter — SysmonHunter

**Release:** 1.4.2 (hardened local build)

A local Windows event threat-hunting utility. It analyses **operator-supplied Windows event records** from real `.evtx` exports, Event Viewer XML, or supported live Windows Event Log channels. It does not ship simulated attack logs, generated alerts, demo datasets, or a demo mode.

> **Important:** detections are rule-based investigative leads, not proof of compromise. A clean result means only that no enabled rule matched the records collected. It does not prove that a system is safe. Validate findings against the full event context and your environment.

## What it supports

- `.evtx` ingestion using `python-evtx`
- Event Viewer XML export and pasted XML
- Live collection using `wevtutil` under the current Windows user's permissions
- Sysmon, Security, System, PowerShell Operational, and Windows Defender Operational channels
- 104 registered rule definitions, including stateless and correlation detections
- Evidence SHA-256 hashes for uploaded EVTX/XML evidence
- MITRE ATT&CK technique references, event coverage summaries, and local HTML reports
- Local-only web UI bound to `127.0.0.1`
- session-bound CSRF token validation, Fetch Metadata cross-site rejection, loopback host checks, request size limits, and hardened XML parsing

Rule count is the number of registered rule definitions, not a claim of 104 independently validated attack detections. Some rules are heuristic and can produce false positives or miss activity when the required telemetry is absent.

## Requirements

- Windows 10 or Windows 11
- Python 3.11+ (Python 3.12 is a conservative choice; newer versions may work if dependencies support them)
- Sysmon installed and configured if Sysmon telemetry is required
- Administrator rights are **not** required to start the GUI or analyse uploaded EVTX files
- Reading protected live channels such as Security may require an appropriately authorized account or an exported EVTX file

## Install

Open PowerShell in this project folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, use the venv interpreter directly:

```powershell
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Start the application

Run as your normal Windows user. Do **not** run the Flask web server as Administrator merely to bypass Windows Event Log permissions.

```powershell
python app.py
```

Open this exact address in your browser:

**http://127.0.0.1:5000**

Do not alternate between `localhost` and `127.0.0.1`, or between different ports. The application intentionally enforces same-origin and loopback checks. If a POST returns `403`, refresh the home page at the exact address above and retry. Do not disable CSRF or origin validation.

Stop the server with `Ctrl+C`.

## Analyse genuine event data

### Option A — upload original EVTX exports (recommended for evidence)

1. Open Event Viewer (`eventvwr.msc`).
2. Navigate to the required channel, for example:
   - Applications and Services Logs → Microsoft → Windows → Sysmon → Operational
   - Windows Logs → Security
   - Windows Logs → System
   - Applications and Services Logs → Microsoft → Windows → PowerShell → Operational
3. Choose **Save All Events As…** and save the original `.evtx`.
4. In SysmonHunter, upload the `.evtx` file and select **Analyze files**.

You can upload more than one file. Preserve original files separately and do not edit them. The application computes SHA-256 hashes for uploaded evidence files. A hash identifies the exact file analysed; it does not establish that the source is trustworthy or untampered before collection.

### Option B — live scan

Select the channels and event limit in the **Scan this PC (live)** panel. The application uses `wevtutil` under the current account. Windows may deny access to protected channels. Such errors are displayed as collection notes; the application must not claim that a denied channel was scanned.

### Option C — Event Viewer XML

In Event Viewer, open an event → **Details** → **XML View**, then paste the complete `<Event>...</Event>` XML. Pasted XML is operator-supplied and its origin cannot be independently verified. For evidence handling, prefer original EVTX files.

## Sysmon installation and configuration

Sysmon is optional for analysing existing Security/System/PowerShell logs, but Sysmon telemetry is required for Sysmon-specific detections.

1. Obtain Sysmon from Microsoft's official Sysinternals distribution.
2. Review `sysmonconfig.xml` and confirm its schema version matches the installed Sysmon binary.
3. Inspect the current configuration before changing it.
4. Apply configuration only from an elevated PowerShell window when you intentionally choose to do so:

```powershell
.\Sysmon64.exe -s
.\Sysmon64.exe -c .\sysmonconfig.xml
```

Use the actual path and executable name on your machine. Applying a configuration changes system telemetry collection and requires administrative authorization. Do not run unknown configurations without reviewing them first.

Microsoft documentation:
- Sysmon overview: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
- Sysmon configuration: https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files

## CLI usage

List the registered rules:

```powershell
python hunter.py --rules
```

Analyse real EVTX files:

```powershell
python hunter.py --evtx "C:\Logs\Microsoft-Windows-Sysmon%4Operational.evtx" "C:\Logs\Security.evtx"
```

Scan supported live channels:

```powershell
python hunter.py --live --max 3000
```

The CLI writes HTML, JSON, and CSV findings into `reports/`.

## Output interpretation and limitations

- A rule match is a lead for analyst review, not a confirmed incident.
- Severity is a rule-assigned triage priority. It is not a calibrated probability or confidence score.
- ATT&CK mappings describe the behavior a rule is intended to detect; verify the mapping and event context before using it in formal reporting.
- Some rules require specific Sysmon event types or Windows audit policies. Missing telemetry creates blind spots.
- Event IDs and field names can differ by Windows version, audit policy, Sysmon version, and provider.
- A finding may be a legitimate administrative action, security tool, installer, or enterprise management activity.
- No finding does not mean no compromise.
- The application does not block processes, quarantine files, change firewall rules, or remediate hosts.

## Data handling and safety

- The web application binds only to `127.0.0.1`; it is not intended to be exposed to a LAN or the internet.
- The server runs with the current user's privileges and does not request UAC elevation.
- Session-bound CSRF token validation and Fetch Metadata cross-site rejection are enabled. An opaque `Origin: null` is accepted only after a valid session CSRF token; explicitly cross-site requests and untrusted non-null origins remain rejected. Do not remove these protections.
- Uploaded files are parsed locally and temporary EVTX copies are removed after processing.
- Generated reports can contain usernames, hostnames, IP addresses, command lines, and other sensitive security telemetry. Protect the `reports/` folder and redact reports before sharing.
- No source logs are uploaded to a remote service by this application.

## Troubleshooting

**403 when submitting an analysis**
- Open `http://127.0.0.1:5000` (not `localhost`).
- Refresh the page to obtain a current session token.
- Submit from that same tab and address.
- Ensure no browser extension or proxy is rewriting the request origin.
- Do not disable CSRF/origin checks.

**EVTX support missing**
```powershell
python -m pip install -r requirements.txt
```

**Access denied on Security or another protected channel**
- This is a Windows permission boundary, not a detection-engine failure.
- Export the channel to EVTX using an authorized account and upload that export.
- Do not elevate the web server solely to read a protected channel.

**No Sysmon events**
- Confirm the Sysmon service is installed and running.
- Confirm the Sysmon Operational channel is enabled.
- Confirm the active Sysmon configuration records the event types needed by the rules.

**No findings**
- Check the report's telemetry coverage and collection notes.
- Confirm the relevant channel and event IDs were actually collected.
- Review the rule definitions and validate using authorized, controlled testing in an isolated lab.
