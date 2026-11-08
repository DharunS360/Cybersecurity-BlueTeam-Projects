"""RFC 5322 parsing: headers, Received chain, bodies."""
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime

from .domains import domain_of

RX4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
RX6 = re.compile(r"\[?(?:IPv6:)?([0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})\]?")


def load(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    return raw, BytesParser(policy=policy.default).parsebytes(raw)


def hget(msg, name, default=""):
    try:
        v = msg.get(name)
        return str(v).strip() if v is not None else default
    except Exception:
        return default


def hall(msg, name):
    try:
        return [str(v).strip() for v in (msg.get_all(name) or [])]
    except Exception:
        return []


def addr_parts(value):
    try:
        pairs = getaddresses([value or ""])
    except Exception:
        pairs = []
    if not pairs:
        return "", "", ""
    disp, addr = pairs[0]
    addr = addr.strip().lower()
    return disp.strip(), addr, domain_of(addr)


def is_global(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _valid_ips(text):
    found = []
    for c in RX4.findall(text):
        try:
            ipaddress.ip_address(c)
            found.append(c)
        except ValueError:
            pass
    for c in RX6.findall(text):
        try:
            ipaddress.ip_address(c)
            found.append(c)
        except ValueError:
            pass
    return found


def parse_received(raw_hdr):
    h = re.sub(r"\s+", " ", raw_hdr)
    body, sep, datepart = h.rpartition(";")
    if not sep:
        body, datepart = h, ""
    m = re.search(r"\bfrom\b(.*?)(?=\bby\b|$)", body, re.I)
    from_clause = m.group(1).strip() if m else ""
    by = re.search(r"\bby\s+(\S+)", body, re.I)
    wth = re.search(r"\bwith\s+(\S+)", body, re.I)
    ips = _valid_ips(from_clause)
    ip = next((i for i in ips if is_global(i)), ips[0] if ips else "")
    dt = None
    try:
        dt = parsedate_to_datetime(datepart.strip())
    except Exception:
        pass
    return {"from": from_clause[:200], "by": by.group(1) if by else "",
            "with": wth.group(1) if wth else "", "ips": ips, "ip": ip, "dt": dt}


def build_hops(msg):
    hops = [parse_received(r) for r in hall(msg, "Received")][::-1]  # oldest first
    prev = None
    for i, h in enumerate(hops, 1):
        h["n"] = i
        dt = h.pop("dt")
        ts = None
        if dt is not None:
            try:
                ts = dt.timestamp() if dt.tzinfo else dt.replace(tzinfo=None).timestamp()
            except Exception:
                ts = None
        h["ts"] = ts
        h["delay"] = (ts - prev) if (ts is not None and prev is not None) else None
        if ts is not None:
            prev = ts
        h["time"] = dt.strftime("%Y-%m-%d %H:%M:%S %z") if dt is not None else ""
    return hops


def pick_ips(hops, msg):
    delivering = next((h["ip"] for h in reversed(hops) if h["ip"] and is_global(h["ip"])), "")
    origin = next((h["ip"] for h in hops if h["ip"] and is_global(h["ip"])), "")
    xo = hget(msg, "X-Originating-IP").strip("[] ")
    try:
        ipaddress.ip_address(xo)
    except ValueError:
        xo = ""
    return {"delivering": delivering, "origin": origin, "x_originating": xo}


def _content(part):
    try:
        return part.get_content()
    except Exception:
        try:
            payload = part.get_payload(decode=True) or b""
            return payload.decode(part.get_content_charset() or "utf-8", "replace")
        except Exception:
            return ""


def bodies(msg):
    text, html = [], []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if (part.get_content_disposition() or "") == "attachment":
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            text.append(str(_content(part)))
        elif ctype == "text/html":
            html.append(str(_content(part)))
    return text, html


def raw_headers(raw):
    head = raw.split(b"\r\n\r\n", 1)[0] if b"\r\n\r\n" in raw else raw.split(b"\n\n", 1)[0]
    return head.decode("utf-8", "replace")
