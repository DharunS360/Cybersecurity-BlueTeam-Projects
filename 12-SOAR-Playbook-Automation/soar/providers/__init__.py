from __future__ import annotations

from ..config import Settings
from ..http import HttpClient
from .abuseipdb import AbuseIPDB
from .abusech import MalwareBazaar, ThreatFox, URLhaus
from .base import Provider
from .feeds import EPSS, CisaKEV, FeodoTracker
from .otx import OTX
from .virustotal import VirusTotal

ALL_PROVIDERS = (VirusTotal, AbuseIPDB, OTX, URLhaus, MalwareBazaar, ThreatFox, FeodoTracker, CisaKEV, EPSS)


def build_providers(settings: Settings, http: HttpClient) -> list[Provider]:
    return [cls(settings, http) for cls in ALL_PROVIDERS]