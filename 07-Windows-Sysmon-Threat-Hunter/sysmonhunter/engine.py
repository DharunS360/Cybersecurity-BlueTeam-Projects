"""Detection engine: stateless rules + stateful analytics + attack-chain correlation."""
import re
from collections import defaultdict
from datetime import timedelta

from .rules import STATELESS, STATEFUL_META, SEV_SCORE, pc

META = {m["id"]: m for m in STATEFUL_META}
DISCOVERY = [r"\bwhoami\b", r"\bnet1?\s+(user|group|localgroup|view|accounts)", r"\bnltest\b",
             r"\bipconfig\b", r"\bsysteminfo\b", r"\bnetstat\b", r"\btasklist\b", r"\barp\s+-a",
             r"\bquser\b", r"\bquery\s+user"]


def _finding(meta, ev, evidence, severity=None):
    d = ev["data"]
    dest = ""
    if ev["eid"] == 3:
        dest = "%s:%s" % (d.get("DestinationIp", ""), d.get("DestinationPort", ""))
    return {
        "rule_id": meta["id"], "name": meta["name"], "tactic": meta["tactic"],
        "technique": meta["technique"], "severity": severity or meta["severity"],
        "time": ev["time"].strftime("%Y-%m-%d %H:%M:%S"), "host": ev["host"], "eid": ev["eid"],
        "evidence": evidence,
        "image": d.get("Image") or d.get("NewProcessName") or d.get("SourceImage") or "",
        "parent": d.get("ParentImage") or d.get("ParentProcessName") or "",
        "cmd": d.get("CommandLine", ""),
        "user": d.get("User") or d.get("SubjectUserName") or d.get("TargetUserName") or "",
        "guid": d.get("ProcessGuid") or d.get("SourceProcessGuid") or d.get("SourceProcessGUID") or "",
        "dest": dest,
    }


def brute_force(events):
    groups = defaultdict(list)
    for ev in events:
        if ev["eid"] == 4625:
            groups[(ev["host"], ev["data"].get("IpAddress") or "-")].append(ev)
    out = []
    for (host, ip), lst in groups.items():
        lst.sort(key=lambda e: e["time"])
        i, best_i, best_n = 0, 0, 0
        for j in range(len(lst)):
            while (lst[j]["time"] - lst[i]["time"]).total_seconds() > 300:
                i += 1
            if j - i + 1 > best_n:
                best_i, best_n = i, j - i + 1
        if best_n < 5:
            continue
        win = lst[best_i:best_i + best_n]
        users = {e["data"].get("TargetUserName", "") for e in win}
        last = win[-1]["time"]
        ok = next((e for e in events if e["eid"] == 4624 and e["host"] == host and
                   (e["data"].get("IpAddress") or "-") == ip and
                   last <= e["time"] <= last + timedelta(seconds=600)), None)
        spray = len(users) >= 5
        meta = dict(META["HUNT-101"])
        meta["name"] = "Password spraying" if spray else "Brute force logon attempts"
        meta["technique"] = "T1110.003" if spray else "T1110.001"
        text = "%d failures from %s against %d account(s) in 5 min" % (best_n, ip, len(users))
        sev = "High"
        if ok:
            text += "; SUCCESS followed as %s" % ok["data"].get("TargetUserName", "?")
            sev = "Critical"
        out.append(_finding(meta, win[-1], text, sev))
    return out


def discovery_burst(events):
    per_host = defaultdict(list)
    for ev in events:
        p = pc(ev)
        if not p:
            continue
        for idx, pat in enumerate(DISCOVERY):
            if re.search(pat, p[1]):
                per_host[ev["host"]].append((ev["time"], idx, ev))
                break
    out = []
    for host, items in per_host.items():
        items.sort(key=lambda x: x[0])
        for j in range(len(items)):
            win = [x for x in items[:j + 1] if (items[j][0] - x[0]).total_seconds() <= 300]
            if len({x[1] for x in win}) >= 4:
                out.append(_finding(META["HUNT-102"], items[j][2],
                                    "%d discovery commands (%d distinct) within 5 minutes"
                                    % (len(win), len({x[1] for x in win}))))
                break
    return out


def correlate(findings):
    from .rules import TACTICS
    per_host = defaultdict(list)
    for f in findings:
        per_host[f["host"]].append(f)
    out = []
    for host, lst in per_host.items():
        lst.sort(key=lambda f: f["time"])
        best = []
        for i in range(len(lst)):
            t0 = lst[i]["time"]
            win = [f for f in lst[i:] if _secs(t0, f["time"]) <= 1800]
            if len({f["tactic"] for f in win}) > len({f["tactic"] for f in best}):
                best = win
        tactics = {f["tactic"] for f in best}
        if len(tactics) >= 3:
            ordered = [t for t in TACTICS if t in tactics]
            ev = {"time": _parse(best[-1]["time"]), "host": host, "eid": 0, "data": {}}
            meta = META["HUNT-103"]
            fnd = _finding(meta, ev, "Kill-chain progression on %s: %s (%d findings)" %
                           (host, " > ".join(ordered), len(best)))
            fnd["user"] = ""
            out.append(fnd)
    return out


def _parse(s):
    from datetime import datetime
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")


def _secs(a, b):
    return (_parse(b) - _parse(a)).total_seconds()


def analyze(events):
    events = sorted(events, key=lambda e: e["time"])
    findings = []
    for ev in events:
        for r in STATELESS:
            try:
                res = r["fn"](ev)
            except Exception:
                continue
            if not res:
                continue
            evidence, sev = res if isinstance(res, tuple) else (res, None)
            findings.append(_finding(r, ev, evidence, sev))
    findings += brute_force(events)
    findings += discovery_burst(events)
    findings += correlate(findings)
    seen, unique = set(), []
    for f in sorted(findings, key=lambda f: (f["time"], -SEV_SCORE[f["severity"]])):
        key = (f["rule_id"], f["host"], f["time"], f["evidence"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    for n, f in enumerate(unique, 1):
        f["id"] = "F-%03d" % n
    return unique