# ??? Sentinel - Multi-Source Threat Intelligence

An advanced Python GUI tool (PyQt5) that performs real-time threat intelligence on files using their SHA-256 hashes. It queries multiple threat intelligence sources to determine if a file is malicious, clean, or suspicious.

## Features
- **Modern Dark-Theme GUI:** Built with PyQt5, fully responsive.
- **Two Modes:**
  - **File Scan:** Select a local file to calculate its hash and analyze it.
  - **Hash Check:** Manually paste a SHA-256 hash to check its reputation.
- **Multi-Source Intelligence:**
  - ?? **VirusTotal:** Checks against 70+ antivirus engines.
  - ??? **AlienVault OTX:** Checks Open Threat Exchange pulses.
  - ?? **MalwareBazaar:** Checks the abuse.ch malware database.
- **Detailed Reporting:** Displays File Metadata, First/Last Seen dates, Threat tags, and a list of engines that flagged the file.
- **Actionable Buttons:** Copy Hash, Open VirusTotal report, and Open OTX report directly from the app.

## Setup
1. `pip install -r requirements.txt`
2. Rename `config.example.json` to `config.json` and add your API keys.
3. `python file_hash_checker.py`

## Security Note
- Your API keys are stored locally in `config.json` and are explicitly ignored in `.gitignore` to prevent leaks.
- Only the file SHA-256 hash is sent to the APIs. The file itself is never uploaded.
