"""IOC extraction: defang-aware, validated, de-duplicated.

Design goals: low false-positive rate (so analysts trust the output) and full
transparency - anything dropped is reported with a reason, never silently lost.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

from .models import IOC, IOCType

# Generic TLDs + all ccTLDs, embedded so extraction works offline.
_GTLDS = (
    "com net org info biz edu gov mil int xyz top site online club shop store app dev cloud "
    "tech live icu vip work link click page website space fun pro name mobi asia tel travel "
    "jobs museum aero coop cat xxx bank life world today email support services solutions "
    "network systems digital agency company group media news blog stream download review "
    "party win loan men date science racing accountant trade webcam kim bid host press buzz "
    "rest bar monster quest sbs cyou cfd lol one ltd inc llc art zip mov"
)
_CCTLDS = (
    "ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs "
    "bt bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec "
    "ee eg er es et eu fi fj fk fm fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy "
    "hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky "
    "kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv "
    "mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw "
    "qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf "
    "tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt "
    "za zm zw"
)
TLDS = set(_GTLDS.split()) | set(_CCTLDS.split())

# TLDs that collide with file extensions (script.sh, tool.pl, main.rs, notes.md ...).
# A bare "foo.sh" is ignored, but "http://foo.sh/x" or "a@foo.sh" is still extracted.
AMBIGUOUS_TLDS = {"sh", "pl", "rs", "md", "pm", "so", "ps", "zip", "mov"}

# Names that look like domains but are namespaces/noise in Windows & XML telemetry.
DEFAULT_ALLOWLIST = {
    "schemas.microsoft.com", "schemas.xmlsoap.org", "www.w3.org", "purl.org",
    "schemas.openxmlformats.org", "system.net", "system.io", "localhost", "example.com",
    "example.org", "example.net",
}

_DOMAIN_RE = re.compile(
    r"(?<![\w.\-@/])((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:[A-Za-z]{2,24}|xn--[A-Za-z0-9\-]{2,40}))(?![\w\-])"
)
_URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`\\^{}|]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_HASH_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
_EMAIL_RE = re.compile(r"(?<![\w.%+\-])[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9\-]+\.)+[A-Za-z]{2,24}(?![\w\-])")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

_REFANG = [
    (re.compile(r"hxxp(s?)", re.IGNORECASE), r"http\1"),
    (re.compile(r"fxp", re.IGNORECASE), "ftp"),
    (re.compile(r"\[\s*://\s*\]"), "://"),
    (re.compile(r"[\[\(\{]\s*(?:\.|dot)\s*[\]\)\}]", re.IGNORECASE), "."),
    (re.compile(r"[\[\(\{]\s*:\s*[\]\)\}]"), ":"),
    (re.compile(r"[\[\(\{]\s*(?:@|at)\s*[\]\)\}]", re.IGNORECASE), "@"),
]


def refang(text: str) -> str:
    """Undo common analyst defanging: hxxp, [.], (dot), [:], [@]."""
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def load_allowlist(path: Path | None) -> set[str]:
    allow = set(DEFAULT_ALLOWLIST)
    if path and path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if line:
                allow.add(line)
    return allow


def _allowlisted(domain: str, allow: set[str]) -> bool:
    return any(domain == a or domain.endswith("." + a) for a in allow)


def ip_scope(value: str) -> tuple[ipaddress._BaseAddress | None, str]:
    """Return (ip_obj, '') if publicly routable, else (None, reason)."""
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None, "invalid IP"
    if ip.is_global:
        return ip, ""
    if ip.is_loopback:
        return None, "loopback"
    if ip.is_link_local:
        return None, "link-local"
    if ip.is_multicast:
        return None, "multicast"
    if ip.is_private:
        return None, "private/non-routable range"
    return None, "reserved/non-routable range"


def _clean_url(url: str) -> str:
    url = url.rstrip(".,;:!?'\"")
    while url.endswith(")") and url.count(")") > url.count("("):
        url = url[:-1]
    while url.endswith("]") and url.count("]") > url.count("["):
        url = url[:-1]
    return url


def _valid_domain(d: str, strict: bool) -> bool:
    d = d.lower().rstrip(".")
    if len(d) > 253 or ".." in d:
        return False
    tld = d.rsplit(".", 1)[-1]
    if tld.startswith("xn--"):
        return True
    if tld not in TLDS:
        return False
    if strict and tld in AMBIGUOUS_TLDS:
        return False
    return not d.replace(".", "").isdigit()


class Collector:
    """Accumulates unique IOCs, remembering where each was seen, plus what was dropped."""

    def __init__(self, allowlist: set[str] | None = None) -> None:
        self.allow = allowlist if allowlist is not None else set(DEFAULT_ALLOWLIST)
        self._found: dict[tuple[str, str], IOC] = {}
        self.skipped: list[dict[str, str]] = []
        self._skipped_keys: set[tuple[str, str]] = set()

    # -- internal helpers -------------------------------------------------
    def _add(self, t: IOCType, value: str, note: str) -> None:
        key = (t.value, value)
        ioc = self._found.get(key)
        if ioc is None:
            ioc = self._found[key] = IOC(t, value, [])
        if note and note not in ioc.sources and len(ioc.sources) < 5:
            ioc.sources.append(note)

    def _skip(self, t: IOCType, value: str, reason: str) -> None:
        key = (t.value, value)
        if key not in self._skipped_keys:
            self._skipped_keys.add(key)
            self.skipped.append({"type": t.value, "value": value, "reason": reason})

    def _add_ip(self, raw: str, note: str) -> None:
        ip, why = ip_scope(raw)
        if ip is None:
            if why != "invalid IP":
                self._skip(IOCType.IP, raw, why)
            return
        self._add(IOCType.IP, ip.compressed, note)

    def _add_domain(self, raw: str, note: str, strict: bool) -> None:
        d = raw.lower().rstrip(".")
        if not _valid_domain(d, strict):
            return
        if _allowlisted(d, self.allow):
            self._skip(IOCType.DOMAIN, d, "allowlisted")
            return
        self._add(IOCType.DOMAIN, d, note)

    # -- public API -------------------------------------------------------
    def scan(self, text: str, note: str = "") -> None:
        if not text:
            return
        text = refang(text)

        for m in _URL_RE.finditer(text):
            url = _clean_url(m.group(0))
            try:
                host = urlsplit(url).hostname
            except ValueError:
                continue
            if not host:
                continue
            if _allowlisted(host.lower(), self.allow):
                self._skip(IOCType.URL, url, "allowlisted host")
                continue
            self._add(IOCType.URL, url, note)
            try:
                ipaddress.ip_address(host)
            except ValueError:
                self._add_domain(host, note, strict=False)
            else:
                self._add_ip(host, note)

        for m in _EMAIL_RE.finditer(text):
            email = m.group(0).lower()
            self._add(IOCType.EMAIL, email, note)
            self._add_domain(email.split("@", 1)[1], note, strict=False)

        for m in _IPV4_RE.finditer(text):
            self._add_ip(m.group(0), note)
        for m in _IPV6_RE.finditer(text):
            cand = m.group(0)
            if "::" in cand or cand.count(":") == 7:
                self._add_ip(cand, note)

        for m in _HASH_RE.finditer(text):
            h = m.group(0).lower()
            if len(set(h)) <= 2:          # 000..0, fff..f, abab.. - not a real digest
                continue
            self._add(IOCType.HASH, h, note)

        for m in _CVE_RE.finditer(text):
            self._add(IOCType.CVE, m.group(0).upper(), note)

        for m in _DOMAIN_RE.finditer(text):
            self._add_domain(m.group(1), note, strict=True)

    def add_hash(self, value: str, note: str) -> None:
        self._add(IOCType.HASH, value.lower(), note)

    @property
    def iocs(self) -> list[IOC]:
        return list(self._found.values())


def extract(text: str, allowlist: set[str] | None = None) -> Collector:
    c = Collector(allowlist)
    c.scan(text)
    return c