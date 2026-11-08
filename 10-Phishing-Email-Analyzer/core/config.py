"""Configuration handling for PhishScope."""
import json
import os
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE / "config.json"
CACHE_DIR = BASE / "cache"
REPORT_DIR = BASE / "reports"

DEFAULTS = {
    "vt_api_key": "",
    "dns_timeout": 4.0,
    "http_timeout": 8.0,
    "max_url_lookups": 4,      # VirusTotal free tier = 4 requests/min
    "use_openphish": True,
    "use_dnsbl": True,
    "use_rdap": True,
    "use_geoip": True,
}

CACHE_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)


def load():
    cfg = dict(DEFAULTS)
    try:
        if CONFIG_FILE.exists():
            cfg.update(json.loads(CONFIG_FILE.read_text(encoding="utf-8")))
    except Exception:
        pass
    env = os.environ.get("VT_API_KEY")
    if env:
        cfg["vt_api_key"] = env
    return cfg


def save(cfg):
    data = {k: cfg.get(k, v) for k, v in DEFAULTS.items()}
    CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
