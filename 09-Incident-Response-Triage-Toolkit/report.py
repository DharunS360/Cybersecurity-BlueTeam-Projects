"""
report.py - case-folder export: JSON, per-artifact CSV, IOC feed, HTML report,
chain-of-custody note and SHA-256 manifest of every exported file.
"""
import csv
import hashlib
import html
import json
import os
from datetime import datetime

SEV_COLORS = {"Critical": "#ff3b5c", "High": "#ff8a3d", "Medium": "#f5c542", "Low": "#4cc9f0", "Info": "#8892a6"}
SEV_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
SECTIONS = ["findings", "processes", "network", "persistence", "events", "files", "artifacts", "timeline", "iocs"]


def h(x):
    return html.escape(str(x if x is not None else ""))


def _cols(rows):
    cols = []
    for r in rows:
        for k in r:
            if k not in cols:
                cols.append(k)
    return cols


def write_csv(path, rows):
    cols = _cols(rows) or ["empty"]
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in cols})


def _sha(path):
    d = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            d.update(chunk)
    return d.hexdigest()


def _badge(sev):
    c = SEV_COLORS.get(sev, "#8892a6")
    return '<span class="b" style="background:%s">%s</span>' % (c, h(sev or "-"))


def _table(headers, rows):
    out = ["<table><thead><tr>%s</tr></thead><tbody>" % "".join("<th>%s</th>" % h(x) for x in headers)]
    for r in rows:
        out.append("<tr>%s</tr>" % "".join("<td>%s</td>" % c for c in r))
    out.append("</tbody></table>")
    return "".join(out)


def build_html(data):
    m, s = data["meta"], data["summary"]
    cards = "".join('<div class="card"><div class="n" style="color:%s">%d</div><div>%s</div></div>'
                    % (SEV_COLORS[k], s["counts"][k], k) for k in ("Critical", "High", "Medium", "Low"))
    gauge_color = SEV_COLORS["Critical"] if s["score"] >= 75 else SEV_COLORS["High"] if s["score"] >= 50 else \
        SEV_COLORS["Medium"] if s["score"] >= 25 else SEV_COLORS["Low"]
    meta_rows = [(h(k), h(v)) for k, v in m.items() if k != "Warnings"]
    warn = "".join("<li>%s</li>" % h(w) for w in m.get("Warnings", []))
    finds = _table(["Severity", "Category", "Finding", "Entity", "MITRE ATT&CK", "Time"],
                   [(_badge(f["Severity"]), h(f["Category"]), "<b>%s</b><br><small>%s</small>" % (h(f["Title"]), h(f["Detail"][:400]).replace("\n", "<br>")),
                     h(f["Entity"]), h((f["MITRE"] + " " + f["Technique"]).strip()), h(f["Time"])) for f in data["findings"][:300]])
    mitre = _table(["Technique", "Name", "Findings"], [(h(t), h(n), c) for t, n, c in s["top_mitre"]])
    iocs = _table(["Severity", "Type", "Value", "Count", "VirusTotal", "Context"],
                  [(_badge(i["Severity"]), h(i["Type"]), "<code>%s</code>" % h(i["Value"]), i["Count"], h(i["VT"]), h(i["Context"]))
                   for i in data["iocs"] if SEV_RANK[i["Severity"]] >= 1][:400])
    tl = _table(["Time", "Severity", "Source", "Event", "Summary"],
                [(h(t["Time"]), _badge(t["Severity"]) if t["Severity"] else "", h(t["Source"]), h(t["Event"]), h(t["Summary"]))
                 for t in data["timeline"] if t["Severity"]][:500])
    counts = _table(["Artifact", "Records"], [(h(k), len(data[k])) for k in SECTIONS if k in data])
    return """<!doctype html><html><head><meta charset="utf-8"><title>IR Triage Report - %(host)s</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#0b0f19;color:#dbe4f5;margin:0;padding:32px}
h1{margin:0 0 4px;font-size:28px}h2{margin-top:36px;border-bottom:1px solid #263149;padding-bottom:6px;color:#9fb0d0}
.sub{color:#8892a6}.cards{display:flex;gap:14px;margin:20px 0}.card{flex:1;background:#121827;border:1px solid #263149;border-radius:12px;padding:16px;text-align:center}
.n{font-size:38px;font-weight:700}.bar{height:16px;background:#1c2438;border-radius:8px;overflow:hidden}.bar>div{height:100%%;background:%(gc)s;width:%(score)d%%}
table{border-collapse:collapse;width:100%%;margin-top:10px;font-size:13px}th{background:#161e33;text-align:left;padding:8px;color:#9fb0d0}
td{padding:7px 8px;border-bottom:1px solid #1c2438;vertical-align:top;word-break:break-word}.b{color:#0b0f19;font-weight:700;padding:2px 9px;border-radius:10px;font-size:12px}
small{color:#8892a6}code{color:#7bdff2}li{margin:4px 0;color:#f5c542}
</style></head><body>
<h1>Incident Response Triage Report</h1>
<div class="sub">Host <b>%(host)s</b> &middot; Analyst %(analyst)s &middot; Collected %(when)s &middot; %(tool)s</div>
<h2>Risk Assessment</h2>
<div class="bar"><div></div></div><p><b style="color:%(gc)s">%(label)s</b> &mdash; score %(score)d / 100</p>
<div class="cards">%(cards)s</div>
%(warn)s
<h2>Top MITRE ATT&amp;CK Techniques</h2>%(mitre)s
<h2>Findings</h2>%(finds)s
<h2>Indicators of Compromise</h2>%(iocs)s
<h2>Flagged Timeline</h2>%(tl)s
<h2>Collection Summary</h2>%(counts)s
<h2>Host &amp; Collection Metadata</h2>%(meta)s
</body></html>""" % {
        "host": h(m["Hostname"]), "analyst": h(m["Analyst"]), "when": h(m["CollectionStartLocal"]), "tool": h(m["Tool"]),
        "gc": gauge_color, "score": s["score"], "label": s["label"], "cards": cards,
        "warn": ("<h2>Collection Warnings</h2><ul>%s</ul>" % warn) if warn else "",
        "mitre": mitre, "finds": finds, "iocs": iocs, "tl": tl, "counts": counts,
        "meta": _table(["Field", "Value"], meta_rows)}


def export_case(data, base_dir):
    m = data["meta"]
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    case = os.path.join(base_dir, "%s_%s" % (m["Hostname"], stamp))
    os.makedirs(os.path.join(case, "csv"), exist_ok=True)

    with open(os.path.join(case, "case_data.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    for sec in SECTIONS:
        write_csv(os.path.join(case, "csv", sec + ".csv"), data.get(sec, []))

    # IOC feeds
    write_csv(os.path.join(case, "iocs.csv"), data["iocs"])
    with open(os.path.join(case, "blocklist_iocs.txt"), "w", encoding="utf-8") as f:
        f.write("# Medium+ IOCs from %s on %s\n" % (m["Hostname"], m["CollectionStartLocal"]))
        for i in data["iocs"]:
            if SEV_RANK[i["Severity"]] >= 2 and i["Type"] in ("IPv4", "Domain", "URL", "SHA256", "SHA1", "MD5"):
                f.write("%s\t%s\n" % (i["Type"], i["Value"]))

    with open(os.path.join(case, "report.html"), "w", encoding="utf-8") as f:
        f.write(build_html(data))

    with open(os.path.join(case, "chain_of_custody.txt"), "w", encoding="utf-8") as f:
        f.write("CHAIN OF CUSTODY / COLLECTION RECORD\n" + "=" * 40 + "\n")
        for k, v in m.items():
            f.write("%-22s %s\n" % (k + ":", v))
        f.write("\nExported (local): %s\nAll files in this case folder are listed with SHA-256 in SHA256SUMS.txt\n"
                % datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # manifest last, covering everything else
    lines = []
    for root, _, files in os.walk(case):
        for name in sorted(files):
            p = os.path.join(root, name)
            lines.append("%s *%s" % (_sha(p), os.path.relpath(p, case).replace("\\", "/")))
    with open(os.path.join(case, "SHA256SUMS.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(lines, key=lambda x: x.split("*")[1])) + "\n")
    return case
