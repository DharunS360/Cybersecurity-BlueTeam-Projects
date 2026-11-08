"""URL extraction (text + HTML) and static URL heuristics."""
import ipaddress
import re
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs

from .domains import org_domain

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
              "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "lnkd.in", "s.id", "v.gd", "bl.ink"}
SUSP_TLDS = {"zip", "mov", "top", "xyz", "click", "icu", "tk", "gq", "cf", "ml", "ga", "work", "rest",
             "country", "support", "cam", "cyou", "monster", "sbs", "quest", "live", "buzz"}
BRANDS = {
    "paypal": ("paypal.com",), "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com",
                                             "outlook.com", "office365.com", "sharepoint.com", "windows.net"),
    "google": ("google.com", "gmail.com", "googleapis.com", "goo.gl", "youtube.com", "gstatic.com",
               "googleusercontent.com", "google.co.in"),
    "apple": ("apple.com", "icloud.com"), "amazon": ("amazon.com", "amazon.in", "amazonaws.com", "amazon.co.uk"),
    "netflix": ("netflix.com",), "facebook": ("facebook.com", "fb.com", "meta.com"),
    "instagram": ("instagram.com",), "linkedin": ("linkedin.com",), "dhl": ("dhl.com",),
    "fedex": ("fedex.com",), "paytm": ("paytm.com",), "phonepe": ("phonepe.com",),
    "hdfc": ("hdfcbank.com",), "icici": ("icicibank.com",), "sbi": ("sbi.co.in", "onlinesbi.sbi"),
    "whatsapp": ("whatsapp.com",), "dropbox": ("dropbox.com",), "docusign": ("docusign.com", "docusign.net"),
    "adobe": ("adobe.com",), "zoom": ("zoom.us",), "github": ("github.com",),
}
LEGIT = {d for v in BRANDS.values() for d in v}
KEYWORDS = ("login", "signin", "sign-in", "verify", "update", "secure", "account", "password",
            "wallet", "confirm", "webscr", "auth", "billing", "suspend")
URL_RX = re.compile(r"https?://[^\s<>\"'\)\]\}]+", re.I)


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.text, self.images, self.forms = [], [], [], []
        self._a, self._skip = None, 0

    def handle_starttag(self, tag, attrs):
        d = {k: (v or "") for k, v in attrs}
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a" and d.get("href"):
            self._a = {"href": d["href"].strip(), "text": []}
        elif tag == "img":
            self.images.append(d)
        elif tag == "form":
            self.forms.append(d.get("action", ""))

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._a is not None:
            self.links.append({"href": self._a["href"], "text": " ".join(self._a["text"]).strip()})
            self._a = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._a is not None and data.strip():
            self._a["text"].append(data.strip())


def parse_html(html):
    p = LinkParser()
    try:
        p.feed(html)
        p.close()
    except Exception:
        pass
    return p


def html_to_text(html):
    return re.sub(r"\s+", " ", " ".join(parse_html(html).text)).strip()


def extract_urls(text_parts, html_parts):
    seen, out = set(), []
    extras = {"pixels": [], "forms": []}

    def add(url, text, src):
        url = url.strip().rstrip(".,;:!?)")
        if not url or url in seen:
            return
        scheme = urlparse(url).scheme.lower()
        if scheme not in ("http", "https", "javascript", "data", "ftp"):
            return
        seen.add(url)
        out.append({"url": url, "text": text, "source": src})

    for html in html_parts:
        p = parse_html(html)
        for l in p.links:
            add(l["href"], l["text"], "html-href")
        for img in p.images:
            w, h = str(img.get("width", "")).strip(), str(img.get("height", "")).strip()
            if w in ("0", "1") or h in ("0", "1"):
                extras["pixels"].append(img.get("src", "")[:200])
        extras["forms"].extend(a for a in p.forms)
        for m in URL_RX.findall(html):
            add(m, "", "html-body")
    for t in text_parts:
        for m in URL_RX.findall(t):
            add(m, "", "text-body")
    return out, extras


def _edit(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _flag(code, text, sev, pts):
    return {"code": code, "text": text, "sev": sev, "pts": pts}


def analyze_url(url, text=""):
    flags = []
    p = urlparse(url)
    scheme = p.scheme.lower()
    if scheme in ("javascript", "data"):
        return {"host": "", "reg_domain": "", "flags": [_flag("SCRIPT_URI", f"{scheme}: URI in link", "high", 20)]}
    host = (p.hostname or "").lower()
    reg = org_domain(host)
    try:
        ipaddress.ip_address(host)
        flags.append(_flag("IP_HOST", "URL uses a raw IP address instead of a domain", "high", 20))
    except ValueError:
        pass
    if "xn--" in host:
        try:
            dec = host.encode("ascii").decode("idna")
        except Exception:
            dec = host
        flags.append(_flag("PUNYCODE", f"Punycode/IDN domain (decodes to: {dec})", "high", 18))
    elif any(ord(c) > 127 for c in host):
        flags.append(_flag("UNICODE_HOST", "Non-ASCII characters in hostname (homograph risk)", "high", 18))
    if "@" in p.netloc:
        flags.append(_flag("USERINFO", "Credentials/userinfo trick (user@host) in URL", "high", 20))
    if reg in SHORTENERS:
        flags.append(_flag("SHORTENER", f"URL shortener ({reg}) hides the real destination", "medium", 8))
    if host.rsplit(".", 1)[-1] in SUSP_TLDS:
        flags.append(_flag("SUSP_TLD", f"High-abuse TLD .{host.rsplit('.', 1)[-1]}", "medium", 8))
    if host.count(".") >= 4:
        flags.append(_flag("MANY_SUBDOMAINS", "Excessive subdomain depth", "low", 5))
    if scheme == "http":
        flags.append(_flag("HTTP_ONLY", "Unencrypted HTTP link", "low", 4))
    if len(url) > 200:
        flags.append(_flag("LONG_URL", "Very long URL", "low", 3))
    path_q = (p.path + "?" + p.query).lower()
    if any(k in path_q for k in KEYWORDS):
        flags.append(_flag("LOGIN_KW", "Credential/login keywords in path or query", "low", 5))
    for vals in parse_qs(p.query).values():
        if any(v.lower().startswith(("http://", "https://")) for v in vals):
            flags.append(_flag("REDIRECT_PARAM", "URL embeds another URL (possible open redirect)", "medium", 10))
            break
    if text:
        m = re.search(r"((?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/\s?#]|$)", text.lower())
        if m:
            cand = m.group(1)
            th = urlparse(cand if "//" in cand else "http://" + cand).hostname or ""
            if th and org_domain(th) != reg:
                flags.append(_flag("TEXT_MISMATCH", f"Link text shows '{th}' but goes to '{host}'", "high", 25))
    if reg not in LEGIT and host and not host.replace(".", "").isdigit():
        tokens = set(re.split(r"[.\-_]", host))
        label = reg.split(".")[0]
        norm = label.translate(str.maketrans("01345$@", "oleass" + "a"))
        for brand in BRANDS:
            if brand in tokens:
                flags.append(_flag("BRAND_IN_HOST", f"Brand '{brand}' used in a domain it doesn't own ({reg})", "high", 20))
                break
            if len(brand) >= 5 and label != brand and (norm == brand or _edit(label, brand) <= 1):
                flags.append(_flag("LOOKALIKE", f"Domain '{reg}' imitates '{brand}'", "high", 22))
                break
    return {"host": host, "reg_domain": reg, "flags": flags}
