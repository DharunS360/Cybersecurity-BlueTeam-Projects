# Changelog

All notable changes to SysmonHunter are documented in this file.

## 1.4.3 - Local browser POST and test discovery fix

- Added the `tests` package marker so test discovery works.
- Added CSRF-bound handling for an opaque `Origin: null` while continuing to reject cross-site requests and untrusted non-null origins.
- Added web security regression tests.

## 1.4.2 - Hardening release

### Changed
- Local POST origin validation now compares the browser Origin with the exact loopback origin used to open the application. Per-session CSRF validation remains mandatory; rejected origins are logged locally.
- Added loopback Host validation as defense in depth. The server remains bound to `127.0.0.1`.
- Added Windows Defender Operational to the live channel allowlist (where the channel exists and the current account can read it).
- Added hardened XML parsing with `defusedxml` for uploaded/pasted XML and EVTX record XML.
- Added explicit ATT&CK tactic coverage for Collection and Exfiltration rule metadata, and the non-ATT&CK Correlation label used by the multi-stage summary.
- Kept the 104-rule catalogue with unique IDs; `HUNT-101` through `HUNT-103` are reserved for stateful analytics.

### Removed
- Virtual environments, generated reports and demo/synthetic data modules. The application analyses operator-provided data only.

### Added
- Small code-level regression tests; records are created in memory and are not offered as demo input.

### Validation performed in the build environment
- Python syntax compilation passed for all shipped source files.
- Six unit/regression tests passed: unique rule IDs, severity values, tactic metadata, empty input, one process-event rule path, one benign non-match.
- Detection catalogue loads with 104 unique rule IDs.

### Validation required on the target machine
- Verify Flask browser integration (CSRF and Origin behaviour) in the user's browser.
- Verify live channel access under the user's actual Windows permissions.
- Validate parsing against original EVTX files and compare event counts with Event Viewer.
- Measure detection precision/recall on authorised, analyst-labelled datasets. Unit tests do not certify accuracy.
- Verify the Sysmon configuration schema against the installed Sysmon binary before applying it.