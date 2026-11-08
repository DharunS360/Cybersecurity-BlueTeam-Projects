"""Orchestrates parsing, live DNS/threat-intel lookups, scoring and IOC extraction."""
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

from . import attach as AT
from . import authcheck as A
from . import config
from . import emailparse as ep
from . import intel
from . import urls as U
from .domains import org_domain, aligned
from .scoring import Findings, verdict, mitre_summary

URGENCY = [r"\burgent", r"immediately", r"within 24 hours", r"account (?:has been |will be |is )?(?:suspended|locked|disabled|closed|limited)",
           r"verify your (?:account|identity|password|email)", r"password (?:will )?expire", r"unusual (?:sign-?in|activity)",
           r"confirm your", r"click (?:here|below|the link)", r"gift card", r"wire transfer", r"payment (?:failed|declined|overdue)",
           r"final notice", r"act now", r"security alert", r"update your (?:payment|billing|details|information)",
           r"your (?:mailbox|storage) is full", r"invoice attached", r"kindly"]
BRAND_NAMES = {"paypal": ("paypal.com",), "microsoft": ("microsoft.com", "office.com", "outlook.com", "live.com", "microsoftonline.com"),
               "google": ("google.com", "gmail.com"), "apple": ("apple.com", "icloud.com"),
               "amazon": ("amazon.com", "amazon.in"), "netflix": ("netflix.com",), "dhl": ("dhl.com",),
               "fedex": ("fedex.com",), "paytm": ("paytm.com",), "hdfc": ("hdfcbank.com",), "icici": ("icicibank.com",),
               "sbi": ("sbi.co.in", "onlinesbi.sbi"), "linkedin": ("linkedin.com",), "docusign": ("docusign.com", "docusign.net")}
SEV_FROM_PTS = lambda p: "high" if p >= 20 else "medium" if p >= 8 else "low"


def _safe(fut, default=None):
    try:
        return fut.result(timeout=90) if fut is not None else default
    except Exception:
        return default


def _domain_intel(domain, cfg):
    out = {"domain": domain}
    if cfg.get("use_rdap", True):
        out["rdap"] = intel.rdap_age(domain, cfg["http_timeout"])
    if cfg.get("use_dnsbl", True):
        out["dbl"] = intel.dbl(domain, cfg["dns_timeout"])
    return out


def analyze(path, cfg=None, progress=None):
    cfg = cfg or config.load()
    P = progress or (lambda p, m: None)
    F = Findings()
    path = Path(path)

    P(3, "Parsing message")
    raw, msg = ep.load(str(path))
    subject = ep.hget(msg, "Subject")
    f_disp, f_addr, f_dom = ep.addr_parts(ep.hget(msg, "From"))
    rp_disp, rp_addr, rp_dom = ep.addr_parts(ep.hget(msg, "Return-Path"))
    rt_list = [ep.addr_parts(v) for v in ep.hall(msg, "Reply-To")]
    rt_doms = sorted({x[2] for x in rt_list if x[2]})
    envelope = rp_dom or f_dom
    hops = ep.build_hops(msg)
    ips = ep.pick_ips(hops, msg)
    text_parts, html_parts = ep.bodies(msg)
    body_text = "\n".join(text_parts).strip() or "\n".join(U.html_to_text(h) for h in html_parts)

    R = {"meta": {"file": str(path), "name": path.name, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
                  "md5": hashlib.md5(raw).hexdigest(), "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                  "subject": subject, "from": ep.hget(msg, "From"), "to": ep.hget(msg, "To"), "cc": ep.hget(msg, "Cc"),
                  "date": ep.hget(msg, "Date"), "message_id": ep.hget(msg, "Message-ID"),
                  "x_mailer": ep.hget(msg, "X-Mailer") or ep.hget(msg, "User-Agent")},
         "sender": {"from_display": f_disp, "from_addr": f_addr, "from_domain": f_dom, "return_path": rp_addr,
                    "return_path_domain": rp_dom, "reply_to": [x[1] for x in rt_list if x[1]], "reply_to_domains": rt_doms,
                    "envelope_domain": envelope, "x_originating_ip": ips["x_originating"]},
         "hops": hops, "ips": ips, "raw_headers": ep.raw_headers(raw), "body_preview": body_text[:20000]}

    # ------------------------------------------------------------ start live lookups
    P(10, "Starting live DNS / threat-intel lookups")
    ex = ThreadPoolExecutor(max_workers=12)
    dt_, ht_ = cfg["dns_timeout"], cfg["http_timeout"]
    T = {}
    if ips["delivering"] and envelope:
        T["spf"] = ex.submit(A.spf_check, ips["delivering"], envelope, dt_)
    if f_dom:
        T["dmarc"] = ex.submit(A.dmarc_lookup, f_dom, dt_)
    T["dkim"] = ex.submit(A.dkim_analyze, raw, ep.hall(msg, "DKIM-Signature"), f_dom, dt_)
    if cfg.get("use_openphish", True):
        T["feed"] = ex.submit(intel.openphish_feed, ht_)

    ip_roles = []
    for role, ip in (("Delivering (last external hop)", ips["delivering"]), ("Origin (first external hop)", ips["origin"]),
                     ("X-Originating-IP", ips["x_originating"])):
        if ip and ip not in [x[1] for x in ip_roles]:
            ip_roles.append((role, ip))
    for role, ip in ip_roles:
        if cfg.get("use_geoip", True):
            T[("geo", ip)] = ex.submit(intel.geoip, ip, ht_)
        if cfg.get("use_dnsbl", True):
            T[("bl", ip)] = ex.submit(intel.dnsbl_ip, ip, dt_)

    # URLs / attachments (static)
    url_items, extras = U.extract_urls(text_parts, html_parts)
    url_items = url_items[:120]
    for it in url_items:
        a = U.analyze_url(it["url"], it["text"])
        it.update(host=a["host"], reg_domain=a["reg_domain"], flags=a["flags"])
        it["score"] = min(60, sum(f["pts"] for f in it["flags"]))
        it.update(age_days=None, created=None, vt=None, feed=None, dbl=None)
    atts = AT.extract(msg)

    dom_set = [d for d in dict.fromkeys([org_domain(f_dom), org_domain(rp_dom)] +
               [it["reg_domain"] for it in sorted(url_items, key=lambda x: -x["score"])]) if d and "." in d][:10]
    for d in dom_set:
        T[("dom", d)] = ex.submit(_domain_intel, d, cfg)

    vt_items = []
    if cfg.get("vt_api_key"):
        vt_items = [("file", a["sha256"]) for a in atts]
        ranked = [it for it in sorted(url_items, key=lambda x: -x["score"]) if it["host"]]
        vt_items += [("url", it["url"]) for it in ranked[:int(cfg.get("max_url_lookups", 4))]]
        if vt_items:
            T["vt"] = ex.submit(intel.vt_batch, vt_items, cfg["vt_api_key"], ht_)

    # ---------------------------------------------------- header heuristics (offline)
    P(25, "Analyzing headers and sender identity")
    if not f_addr:
        F.add("high", "Headers", "Missing/unparseable From address", "Message has no valid From header", 15)
    if rp_dom and f_dom and not aligned(rp_dom, f_dom):
        F.add("medium", "Sender", "Return-Path domain differs from From domain",
              f"From={f_dom}  Return-Path={rp_dom} (common for bulk mailers, suspicious otherwise)", 8)
    bad_rt = [d for d in rt_doms if f_dom and not aligned(d, f_dom)]
    if bad_rt:
        F.add("high", "Sender", "Reply-To redirects replies to a different domain",
              f"From={f_dom}  Reply-To={', '.join(bad_rt)}", 15, "T1566")
    if f_disp:
        if re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", f_disp) and f_addr and f_disp.lower() != f_addr:
            F.add("high", "Sender", "Display name contains a different e-mail address",
                  f"Display '{f_disp}' vs actual <{f_addr}>", 20, "T1656")
        low = f_disp.lower()
        for brand, doms in BRAND_NAMES.items():
            if re.search(rf"\b{brand}\b", low) and org_domain(f_dom) not in doms:
                F.add("high", "Sender", f"Display name impersonates '{brand}'",
                      f"Display '{f_disp}' but sender domain is {f_dom}", 18, "T1656")
                break
    if not R["meta"]["message_id"]:
        F.add("low", "Headers", "Missing Message-ID", "Legitimate MTAs always add a Message-ID", 5)
    else:
        mid_dom = R["meta"]["message_id"].strip("<> ").rsplit("@", 1)[-1].lower()
        if f_dom and "@" in R["meta"]["message_id"] and not aligned(mid_dom, f_dom) and not aligned(mid_dom, rp_dom):
            F.add("low", "Headers", "Message-ID domain unrelated to sender",
                  f"Message-ID domain {mid_dom} vs {f_dom}", 4)
    try:
        sent = parsedate_to_datetime(R["meta"]["date"])
        if sent.tzinfo is None:
            sent = sent.replace(tzinfo=timezone.utc)
        if (sent - datetime.now(timezone.utc)).total_seconds() > 86400:
            F.add("medium", "Headers", "Date header is in the future", R["meta"]["date"], 6)
    except Exception:
        if not R["meta"]["date"]:
            F.add("low", "Headers", "Missing Date header", "", 4)
    if not hops:
        F.add("medium", "Routing", "No Received headers", "Headers may be stripped or forged", 8)
    slow = [h for h in hops if h["delay"] and h["delay"] > 6 * 3600]
    if slow:
        F.add("low", "Routing", "Large delay between hops", f"Hop {slow[0]['n']} delayed {int(slow[0]['delay'])}s", 3)

    # ------------------------------------------------------- body language / forms
    low_body = body_text.lower()
    hits = [p for p in URGENCY if re.search(p, low_body)]
    if hits:
        F.add("low" if len(hits) < 3 else "medium", "Content", f"Social-engineering language ({len(hits)} indicators)",
              f"{len(hits)} urgency/credential-lure phrases matched in body", min(15, 3 * len(hits)), "T1566")
    ext_forms = [f for f in extras["forms"] if f.lower().startswith("http")]
    if ext_forms:
        F.add("high", "Content", "HTML form embedded in e-mail posts to external site",
              f"Form action: {ext_forms[0][:100]}", 20, "T1598")
    if extras["pixels"]:
        F.add("info", "Content", f"{len(extras['pixels'])} tracking pixel(s)", extras["pixels"][0], 2)

    # --------------------------------------------------- wait for DNS-auth results
    P(40, "Evaluating SPF / DKIM / DMARC from live DNS")
    spf, dm, dkl = _safe(T.get("spf")), _safe(T.get("dmarc")), _safe(T.get("dkim"), [])
    hdr = A.parse_auth_results(ep.hall(msg, "Authentication-Results")) + A.parse_received_spf(ep.hall(msg, "Received-SPF"))
    hdr_res = lambda m: next((h["result"] for h in hdr if h["method"] == m), None)

    spf = spf or {"domain": envelope, "ip": ips["delivering"], "result": "none", "record": "", "lookups": 0,
                  "trace": [], "issues": ["No external delivering IP found or no envelope domain"], "policy": ""}
    spf_eff = hdr_res("spf") or spf["result"]
    spf["header_result"], spf["effective"] = hdr_res("spf"), spf_eff
    spf_good = spf_eff == "pass"

    dkim_pass_live = any(s["verified"] for s in dkl)
    dh = hdr_res("dkim")
    if dkim_pass_live or dh == "pass":
        dkim_eff = "pass"
    elif dkl:
        dkim_eff = "fail"
    else:
        dkim_eff = "none"
    dkim_aligned = any((s["verified"] or dh == "pass") and s["aligned_relaxed"] for s in dkl)

    dm = dm or {"found": False, "domain": f_dom, "record": "", "policy": ""}
    strict_spf, strict_dkim = dm.get("aspf") == "s", dm.get("adkim") == "s"
    spf_aligned = spf_good and aligned(envelope, f_dom, strict_spf)
    if dkl and dm.get("found"):
        dkim_aligned = any((s["verified"] or dh == "pass") and aligned(s["domain"], f_dom, strict_dkim) for s in dkl)
    dmarc_pass = spf_aligned or dkim_aligned
    dm_hdr = hdr_res("dmarc")
    dm.update(spf_aligned=spf_aligned, dkim_aligned=dkim_aligned,
              effective=dm_hdr or ("pass" if dmarc_pass else "fail" if dm.get("found") else "none"))
    R["auth"] = {"header_results": hdr, "spf": spf, "dkim": {"signatures": dkl, "effective": dkim_eff, "header_result": dh},
                 "dmarc": dm}

    spf_pts = {"fail": 25, "softfail": 12, "neutral": 8, "none": 8, "permerror": 10}
    if spf_eff in spf_pts:
        F.add("high" if spf_eff == "fail" else "medium", "Authentication", f"SPF {spf_eff.upper()}",
              f"Sender IP {spf['ip'] or 'unknown'} vs {spf['domain']} ({spf['policy'] or 'no record'})", spf_pts[spf_eff], "T1566")
    elif spf_good:
        F.add("good", "Authentication", "SPF pass", f"{spf['ip']} authorized for {spf['domain']}", 0)
    for issue in spf["issues"][:3]:
        if "+all" in issue or "10 DNS" in issue or "Multiple" in issue:
            F.add("medium", "Authentication", "SPF record weakness", issue, 6)
    if dkim_eff == "fail":
        F.add("high", "Authentication", "DKIM verification FAILED",
              "; ".join(s["error"] or f"{s['domain']} signature invalid" for s in dkl)[:200], 22, "T1566")
    elif dkim_eff == "none":
        F.add("low", "Authentication", "No DKIM signature", "Message is not cryptographically signed", 8)
    else:
        F.add("good", "Authentication", "DKIM pass", ", ".join(f"{s['domain']}/{s['selector']}" for s in dkl)[:120], 0)
    for s in dkl:
        k = s.get("key", {})
        if k.get("bits") and k["bits"] <= 512:
            F.add("medium", "Authentication", "Weak DKIM key", f"{s['domain']} uses ~{k['bits']}-bit key", 8)
        if k.get("revoked"):
            F.add("medium", "Authentication", "DKIM key revoked", f"{s['selector']}._domainkey.{s['domain']}", 8)
        if s["algo"].lower().startswith("rsa-sha1"):
            F.add("low", "Authentication", "DKIM uses deprecated rsa-sha1", s["domain"], 3)
    if not dm.get("found"):
        F.add("medium", "Authentication", "No DMARC record", f"_dmarc.{f_dom} not published - spoofing is unrestricted", 8, "T1656")
    elif dm["effective"] != "pass":
        F.add("high", "Authentication", "DMARC alignment FAILED",
              f"p={dm['policy']} | SPF aligned={spf_aligned} | DKIM aligned={dkim_aligned}", 20, "T1656")
    else:
        F.add("good", "Authentication", "DMARC pass", f"policy p={dm['policy']}", 0)
    if dm.get("found") and dm["policy"] == "none" and dm["effective"] != "pass":
        F.add("low", "Authentication", "DMARC policy is monitor-only (p=none)", "Spoofed mail is not blocked", 3)

    # --------------------------------------------------------- IP intelligence
    P(55, "Collecting IP reputation and geolocation")
    ip_intel = []
    for role, ip in ip_roles:
        g, bl = _safe(T.get(("geo", ip)), {}), _safe(T.get(("bl", ip)), [])
        ip_intel.append({"role": role, "ip": ip, "geo": g, "dnsbl": bl})
        listed = [b["list"] for b in bl if b.get("listed")]
        if listed:
            F.add("high", "Reputation", f"Sender IP {ip} blocklisted", "Listed on: " + ", ".join(listed), 25)
        if g.get("proxy") and not (spf_good and dkim_eff == "pass"):
            F.add("medium", "Reputation", f"{ip} is a proxy/VPN/Tor exit", f"{g.get('isp', '')} / {g.get('country', '')}", 10)
    R["ip_intel"] = ip_intel

    # ---------------------------------------------------- domain age + reputation
    P(65, "Domain age (RDAP) and blocklists")
    dom_info = {}
    for d in dom_set:
        dom_info[d] = _safe(T.get(("dom", d)), {})
    R["domains"] = dom_info
    for d in {org_domain(f_dom), org_domain(rp_dom)} - {""}:
        info = dom_info.get(d, {})
        age = (info.get("rdap") or {}).get("age_days")
        if age is not None and age < 30:
            F.add("high", "Reputation", f"Sender domain {d} registered {age} day(s) ago", "Newly registered domains are a top phishing indicator", 25, "T1583.001")
        elif age is not None and age < 90:
            F.add("medium", "Reputation", f"Sender domain {d} is only {age} days old", "", 10, "T1583.001")
        if (info.get("dbl") or {}).get("listed"):
            F.add("high", "Reputation", f"Sender domain {d} on Spamhaus DBL", info["dbl"].get("code", ""), 25)

    feed = _safe(T.get("feed"), (set(), set()))
    R["feeds"] = {"openphish_urls": len(feed[0])}
    vt = _safe(T.get("vt"), {})

    # --------------------------------------------------------------------- URLs
    P(78, "Scoring URLs")
    override = False
    for it in url_items:
        info = dom_info.get(it["reg_domain"], {})
        rd = info.get("rdap") or {}
        it["age_days"], it["created"] = rd.get("age_days"), rd.get("created")
        it["dbl"] = info.get("dbl")
        if rd.get("age_days") is not None and rd["age_days"] < 30 and org_domain(f_dom) != it["reg_domain"]:
            it["flags"].append({"code": "NEW_DOMAIN", "text": f"Domain registered {rd['age_days']} day(s) ago", "sev": "high", "pts": 20})
        if (it["dbl"] or {}).get("listed"):
            it["flags"].append({"code": "DBL", "text": "Domain on Spamhaus DBL", "sev": "high", "pts": 30})
        if it["url"] in feed[0]:
            it["feed"] = "OpenPhish: exact URL"
            it["flags"].append({"code": "FEED_URL", "text": "URL present in OpenPhish live feed", "sev": "critical", "pts": 60})
            override = True
        elif it["host"] and it["host"] in feed[1]:
            it["feed"] = "OpenPhish: host"
            it["flags"].append({"code": "FEED_HOST", "text": "Host present in OpenPhish live feed", "sev": "critical", "pts": 45})
        v = vt.get(f"url:{it['url']}")
        if v:
            it["vt"] = v
            if v.get("status") == "ok" and v.get("malicious", 0) >= 3:
                it["flags"].append({"code": "VT_MAL", "text": f"VirusTotal: {v['malicious']} engines flag URL malicious", "sev": "critical", "pts": 40})
                override = override or v["malicious"] >= 5
            elif v.get("status") == "ok" and (v.get("malicious", 0) + v.get("suspicious", 0)) >= 1:
                it["flags"].append({"code": "VT_SUSP", "text": "VirusTotal: some engines flag URL", "sev": "medium", "pts": 15})
        it["score"] = min(70, sum(f["pts"] for f in it["flags"]))
    url_items.sort(key=lambda x: -x["score"])
    bad_urls = [u for u in url_items if u["score"] >= 8]
    for it in bad_urls[:5]:
        sev = "critical" if it["score"] >= 40 else SEV_FROM_PTS(it["score"])
        F.add(sev, "URLs", f"Suspicious link: {it['host'] or it['url'][:40]}",
              "; ".join(f["text"] for f in it["flags"])[:260], min(it["score"], 45), "T1566.002,T1204.001")
    if len(bad_urls) > 5:
        F.add("info", "URLs", f"{len(bad_urls) - 5} additional suspicious link(s)", "See URLs tab", 0)
    R["urls"] = url_items

    # -------------------------------------------------------------- attachments
    P(88, "Scoring attachments")
    for a in atts:
        v = vt.get(f"file:{a['sha256']}")
        a["vt"] = v
        if v and v.get("status") == "ok" and v.get("malicious", 0) >= 1:
            a["flags"].append({"code": "VT_MAL", "text": f"VirusTotal: {v['malicious']} engines flag file ({v.get('label') or 'malware'})",
                               "sev": "critical", "pts": 40, "mitre": "T1204.002"})
            override = override or v["malicious"] >= 5
        for fl in a["flags"]:
            F.add(fl["sev"], "Attachments", f"{a['filename']}: {fl['text']}", f"sha256 {a['sha256'][:16]}...", fl["pts"],
                  "T1566.001," + fl["mitre"] if fl.get("mitre") else "T1566.001")
        for u in a["urls"]:
            if all(u != x["url"] for x in url_items):
                url_items.append({"url": u, "text": "", "source": f"attachment:{a['filename']}", "host": "", "reg_domain": "",
                                  "flags": [], "score": 0, "age_days": None, "created": None, "vt": None, "feed": None, "dbl": None})
    R["attachments"] = atts
    ex.shutdown(wait=False)

    # ------------------------------------------------------------- final verdict
    P(95, "Building verdict and IOCs")
    score = min(100, F.total())
    if override:
        score = max(score, 85)
    R["score"], R["verdict"] = score, verdict(score)
    R["findings"] = F.sorted()
    R["mitre"] = mitre_summary(R["findings"])

    iocs, seen = [], set()

    def ioc(t, v, ctx=""):
        if v and (t, v) not in seen:
            seen.add((t, v))
            iocs.append({"type": t, "value": v, "context": ctx})
    for role, ip in ip_roles:
        ioc("ip", ip, role)
    for h in hops:
        if h["ip"] and ep.is_global(h["ip"]):
            ioc("ip", h["ip"], f"hop {h['n']}")
    for d in (f_dom, rp_dom, *rt_doms):
        ioc("domain", d, "sender infrastructure")
    for e in (f_addr, rp_addr, *R["sender"]["reply_to"]):
        ioc("email", e, "sender")
    for u in url_items:
        ioc("url", u["url"], f"score {u['score']}")
        ioc("domain", u["host"], "from URL")
    for a in atts:
        ioc("sha256", a["sha256"], a["filename"])
        ioc("md5", a["md5"], a["filename"])
    R["iocs"] = iocs
    P(100, "Done")
    return R
