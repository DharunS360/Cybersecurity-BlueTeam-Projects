"""Findings collection, risk score and MITRE ATT&CK mapping."""

MITRE = {
    "T1566": ("Phishing", "Initial Access"),
    "T1566.001": ("Phishing: Spearphishing Attachment", "Initial Access"),
    "T1566.002": ("Phishing: Spearphishing Link", "Initial Access"),
    "T1598": ("Phishing for Information", "Reconnaissance"),
    "T1656": ("Impersonation", "Defense Evasion"),
    "T1036.002": ("Masquerading: Right-to-Left Override", "Defense Evasion"),
    "T1036.007": ("Masquerading: Double File Extension", "Defense Evasion"),
    "T1036.008": ("Masquerading: Masquerade File Type", "Defense Evasion"),
    "T1204.001": ("User Execution: Malicious Link", "Execution"),
    "T1204.002": ("User Execution: Malicious File", "Execution"),
    "T1059.005": ("Command and Scripting: Visual Basic", "Execution"),
    "T1221": ("Template Injection", "Defense Evasion"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1027.006": ("Obfuscated Files: HTML Smuggling", "Defense Evasion"),
    "T1027.013": ("Obfuscated Files: Encrypted/Encoded File", "Defense Evasion"),
    "T1583.001": ("Acquire Infrastructure: Domains", "Resource Development"),
    "T1584": ("Compromise Infrastructure", "Resource Development"),
    "T1534": ("Internal Spearphishing / BEC lures", "Lateral Movement"),
}

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "good": 5}


class Findings:
    def __init__(self):
        self.items = []

    def add(self, sev, cat, title, detail, pts=0, mitre=None):
        self.items.append({"sev": sev, "cat": cat, "title": title, "detail": detail,
                           "points": pts, "mitre": mitre or ""})

    def total(self):
        return sum(i["points"] for i in self.items)

    def sorted(self):
        return sorted(self.items, key=lambda i: (SEV_ORDER.get(i["sev"], 9), -i["points"]))


def verdict(score):
    if score >= 65:
        return {"label": "MALICIOUS / PHISHING", "level": "critical", "color": "#ff4d5e"}
    if score >= 40:
        return {"label": "LIKELY PHISHING", "level": "high", "color": "#ff8a3d"}
    if score >= 20:
        return {"label": "SUSPICIOUS", "level": "medium", "color": "#f5b942"}
    return {"label": "LOW RISK", "level": "low", "color": "#2ecc71"}


def mitre_summary(findings):
    agg = {}
    for f in findings:
        for code in [c.strip() for c in f.get("mitre", "").split(",") if c.strip()]:
            name, tactic = MITRE.get(code, (code, "-"))
            e = agg.setdefault(code, {"id": code, "name": name, "tactic": tactic, "evidence": []})
            e["evidence"].append(f["title"])
    return sorted(agg.values(), key=lambda x: x["id"])
