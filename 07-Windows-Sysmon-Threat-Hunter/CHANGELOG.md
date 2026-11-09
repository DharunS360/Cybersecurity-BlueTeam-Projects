## 1.4.3 - local browser POST and test discovery fix
- Added tests package marker.
- Added CSRF-bound handling for opaque Origin null while continuing to reject cross-site requests and untrusted non-null origins.
- Added web security regression tests.

# SysmonHunter 1.4.2 — Change log

## Changes in this release

- Updated local POST origin validation to compare the browser Origin with the exact loopback origin used to open the application. Per-session CSRF validation remains mandatory; rejected origins are logged locally.
- Added loopback Host validation as defense in depth. The server remains bound to `127.0.0.1`.
- Added Windows Defender Operational to the live channel allowlist (where the channel exists and the current account can read it).
- Added hardened XML parsing with `defusedxml` for uploaded/pasted XML and EVTX record XML.
- Added explicit ATT&CK tactic coverage for Collection and Exfiltration rule metadata, and the non-ATT&CK Correlation label used by the multi-stage summary.
- Kept the 104-rule catalogue with unique IDs; `HUNT-101` through `HUNT-103` are reserved for stateful analytics.
- Removed virtual environments, generated reports, and demo/synthetic data modules from the release package. The application analyses operator-provided data only.
- Added small code-level regression tests; test records are created in memory and are not offered as demo input.

## Validation performed in this build environment

- Python syntax compilation passed for all shipped Python source files.
- Six unit/regression tests passed: unique rule IDs, supported severity values, tactic metadata coverage, empty-input behavior, one process-event rule path, and a benign non-match.
- Detection catalogue loads with 104 unique rule IDs.
- Source archive reviewed to ensure it contains no virtual environment, prior user reports, or demo event files.

## Validation required on the target Windows machine

- Install dependencies and verify Flask browser integration, including CSRF and Origin behavior, in the user's Windows browser.
- Verify live channel access under the user's actual Windows permissions.
- Validate parsing against the user's original EVTX files and compare event counts against Event Viewer.
- Measure detection precision/recall against representative, authorized datasets and analyst-labelled outcomes. Accuracy is not certified by unit tests.
- Verify the optional Sysmon configuration schema against the locally installed Sysmon binary before applying it. It has not been applied to the host by this build.

