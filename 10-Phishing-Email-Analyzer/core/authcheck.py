"""Live SPF evaluation, DKIM verification and DMARC policy/alignment (real DNS)."""
import base64
import ipaddress
import re

from . import dnsutil
from .domains import org_domain, aligned

SPF_Q = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}


# ---------------------------------------------------------------- header results
def parse_auth_results(values):
    out = []
    for v in values:
        v = re.sub(r"\s+", " ", v)
        server = v.split(";")[0].strip()
        for m in re.finditer(r"(?:^|;|\s)(spf|dkim|dmarc|arc|compauth)\s*=\s*([A-Za-z]+)([^;]*)", v, re.I):
            out.append({"server": server, "method": m.group(1).lower(),
                        "result": m.group(2).lower(), "detail": m.group(3).strip()[:200]})
    return out


def parse_received_spf(values):
    out = []
    for v in values:
        m = re.match(r"\s*(pass|fail|softfail|neutral|none|permerror|temperror)", v, re.I)
        if m:
            out.append({"server": "Received-SPF", "method": "spf",
                        "result": m.group(1).lower(), "detail": re.sub(r"\s+", " ", v)[:200]})
    return out


def _tags(text):
    tags = {}
    for part in re.sub(r"[\r\n]", "", text).split(";"):
        k, _, v = part.partition("=")
        if k.strip():
            tags[k.strip().lower()] = v.strip()
    return tags


# ------------------------------------------------------------------------- SPF
class _Ctx:
    def __init__(self, ip, timeout):
        self.ip = ipaddress.ip_address(ip)
        self.timeout = timeout
        self.lookups = 0
        self.trace = []
        self.issues = []
        self.records = {}


def _cidr_hit(addr, c4, c6, ctx):
    try:
        a = ipaddress.ip_address(addr)
        if a.version != ctx.ip.version:
            return False
        pref = c4 if a.version == 4 else c6
        net = ipaddress.ip_network(f"{addr}/{pref}" if pref else addr, strict=False)
        return ctx.ip in net
    except ValueError:
        return False


def _host_ips(host, ctx):
    rtype = "A" if ctx.ip.version == 4 else "AAAA"
    return dnsutil.query(host, rtype, ctx.timeout)[0]


def _spf(domain, ctx, depth):
    if depth > 10:
        ctx.issues.append("Include depth exceeded")
        return "permerror"
    txt, st = dnsutil.query(domain, "TXT", ctx.timeout)
    if st in ("timeout", "error"):
        return "temperror"
    recs = [t for t in txt if t.lower().startswith("v=spf1")]
    if not recs:
        return "none"
    if len(recs) > 1:
        ctx.issues.append(f"Multiple SPF records at {domain} (permerror per RFC 7208)")
        return "permerror"
    rec = recs[0]
    ctx.records[domain] = rec
    redirect = None
    for term in rec.split()[1:]:
        if re.match(r"^[A-Za-z][A-Za-z0-9_.-]*=", term):
            if term.lower().startswith("redirect="):
                redirect = term.split("=", 1)[1]
            continue
        q = "+"
        if term[0] in "+-~?":
            q, term = term[0], term[1:]
        m = re.match(r"^([A-Za-z0-9]+)(?::([^/\s]*))?(?:/(\d+))?(?://(\d+))?$", term)
        if not m:
            ctx.issues.append(f"Unparseable term: {term}")
            return "permerror"
        mech = m.group(1).lower()
        arg, c4, c6 = m.group(2), m.group(3), m.group(4)
        hit = False
        if mech == "all":
            hit = True
        elif mech in ("ip4", "ip6"):
            if arg:
                hit = _cidr_hit(arg, c4, None, ctx) if mech == "ip4" else _cidr_hit(arg, None, c4, ctx)
        elif mech in ("a", "mx", "include", "exists", "ptr"):
            ctx.lookups += 1
            if ctx.lookups > 10:
                ctx.issues.append("More than 10 DNS-lookup mechanisms (RFC 7208 limit) -> permerror")
                return "permerror"
            target = arg or domain
            if "%" in target:
                ctx.issues.append(f"Macro not evaluated: {term}")
                continue
            if mech == "include":
                r = _spf(target, ctx, depth + 1)
                if r == "pass":
                    hit = True
                elif r in ("temperror", "permerror"):
                    return r
                elif r == "none":
                    ctx.issues.append(f"include:{target} has no SPF record")
                    return "permerror"
            elif mech == "a":
                hit = any(_cidr_hit(x, c4, c6, ctx) for x in _host_ips(target, ctx))
            elif mech == "mx":
                mxs, _ = dnsutil.query(target, "MX", ctx.timeout)
                for host in mxs[:10]:
                    if any(_cidr_hit(x, c4, c6, ctx) for x in _host_ips(host, ctx)):
                        hit = True
                        break
            elif mech == "exists":
                hit = bool(dnsutil.query(target, "A", ctx.timeout)[0])
            elif mech == "ptr":
                ctx.issues.append("ptr mechanism is deprecated (RFC 7208)")
        if hit:
            ctx.trace.append(f"{domain}: '{q}{mech}{(':' + arg) if arg else ''}' matched")
            return SPF_Q[q]
    if redirect:
        ctx.lookups += 1
        ctx.trace.append(f"{domain}: redirect -> {redirect}")
        return _spf(redirect, ctx, depth + 1)
    return "neutral"


def spf_check(ip, domain, timeout=4.0):
    try:
        ctx = _Ctx(ip, timeout)
    except ValueError:
        return {"domain": domain, "ip": ip, "result": "none", "record": "", "lookups": 0,
                "trace": [], "issues": ["Invalid IP"], "policy": ""}
    res = _spf(domain, ctx, 0)
    rec = ctx.records.get(domain, "")
    pol = ""
    if rec:
        m = re.search(r"\s([+\-~?]?)all\b", rec)
        pol = {"": "pass(+all)", "+": "pass(+all)", "-": "hardfail(-all)",
               "~": "softfail(~all)", "?": "neutral(?all)"}.get(m.group(1), "") if m else "no 'all'"
        if pol.startswith("pass"):
            ctx.issues.append("Record ends in +all: anyone can send as this domain")
    return {"domain": domain, "ip": ip, "result": res, "record": rec, "lookups": ctx.lookups,
            "trace": ctx.trace, "issues": ctx.issues, "policy": pol}


# ------------------------------------------------------------------------ DMARC
def dmarc_lookup(from_domain, timeout=4.0):
    tried = []
    for d in dict.fromkeys([from_domain, org_domain(from_domain)]):
        if not d:
            continue
        tried.append(d)
        txt, _ = dnsutil.query("_dmarc." + d, "TXT", timeout)
        recs = [t for t in txt if t.lower().lstrip().startswith("v=dmarc1")]
        if recs:
            tags = _tags(recs[0])
            return {"found": True, "domain": d, "record": recs[0], "policy": tags.get("p", "none").lower(),
                    "subdomain_policy": tags.get("sp", "").lower(), "pct": tags.get("pct", "100"),
                    "adkim": tags.get("adkim", "r").lower(), "aspf": tags.get("aspf", "r").lower(),
                    "rua": tags.get("rua", ""), "ruf": tags.get("ruf", "")}
    return {"found": False, "domain": from_domain, "record": "", "policy": "", "tried": tried}


# ------------------------------------------------------------------------- DKIM
def _key_bits(p):
    try:
        n = len(base64.b64decode(p + "=" * (-len(p) % 4)))
    except Exception:
        return None
    if n < 60:
        return None
    return 512 if n < 120 else 1024 if n < 230 else 2048 if n < 420 else 4096


def dkim_analyze(raw, sig_headers, from_domain, timeout=4.0):
    try:
        import dkim as dkimlib
    except Exception:
        dkimlib = None
    out = []
    for i, h in enumerate(sig_headers):
        t = _tags(h)
        d, s = t.get("d", "").lower(), t.get("s", "")
        signed = [x.strip().lower() for x in t.get("h", "").split(":")]
        e = {"index": i, "domain": d, "selector": s, "algo": t.get("a", ""), "canon": t.get("c", ""),
             "signs_from": "from" in signed,
             "aligned_relaxed": aligned(d, from_domain), "aligned_strict": aligned(d, from_domain, True),
             "verified": None, "error": "", "key": {}}
        if d and s:
            txt, st = dnsutil.query(f"{s}._domainkey.{d}", "TXT", timeout)
            rec = next((x for x in txt if "p=" in x), "")
            if rec:
                kt = _tags(rec)
                p = kt.get("p", "")
                e["key"] = {"found": True, "revoked": p == "", "bits": _key_bits(p) if p else None,
                            "testing": "y" in kt.get("t", "").lower(), "type": kt.get("k", "rsa")}
            else:
                e["key"] = {"found": False, "dns_status": st}
        if dkimlib is not None:
            try:
                try:
                    e["verified"] = bool(dkimlib.DKIM(raw).verify(idx=i))
                except TypeError:
                    e["verified"] = bool(dkimlib.verify(raw)) if i == 0 else None
            except Exception as ex:
                e["verified"] = False
                e["error"] = str(ex)[:140]
        out.append(e)
    return out
