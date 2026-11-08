"""Exporters: JSON, IOC CSV, self-contained HTML report."""
import csv
import json
from html import escape

from .domains import defang


def to_json(R, path):
    slim = {k: v for k, v in R.items() if k not in ("raw_headers",)}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(slim, fh, indent=2, default=str)


def iocs_csv(R, path, defanged=True):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["type", "value", "context"])
        for i in R["iocs"]:
            v = defang(i["value"]) if defanged and i["type"] in ("url", "domain", "email", "ip") else i["value"]
            w.writerow([i["type"], v, i["context"]])


def to_html(R, path):
    v, m, a = R["verdict"], R["meta"], R["auth"]
    e = escape
    rows = "".join(
        f"<tr><td class='s {e(f['sev'])}'>{e(f['sev'].upper())}</td><td>{e(f['cat'])}</td><td><b>{e(f['title'])}</b><br>"
        f"<span class='d'>{e(f['detail'])}</span></td><td>{f['points']}</td><td>{e(f['mitre'])}</td></tr>"
        for f in R["findings"])
    urls = "".join(f"<tr><td>{u['score']}</td><td>{e(defang(u['url']))}</td><td>{e('; '.join(x['text'] for x in u['flags']))}</td></tr>"
                   for u in R["urls"][:60])
    atts = "".join(f"<tr><td>{e(x['filename'])}</td><td>{e(x['kind'])}</td><td>{x['size']}</td><td class='m'>{x['sha256']}</td>"
                   f"<td>{e('; '.join(f['text'] for f in x['flags']))}</td></tr>" for x in R["attachments"])
    iocs = "".join(f"<tr><td>{e(i['type'])}</td><td class='m'>{e(defang(i['value']) if i['type'] in ('url','domain','email','ip') else i['value'])}</td>"
                   f"<td>{e(i['context'])}</td></tr>" for i in R["iocs"])
    mitre = "".join(f"<tr><td>{e(t['id'])}</td><td>{e(t['name'])}</td><td>{e(t['tactic'])}</td></tr>" for t in R["mitre"])
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>PhishScope Report</title><style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#0b0f1a;color:#e6ecff;margin:0;padding:32px}}
h1{{margin:0}} h2{{border-bottom:1px solid #26334f;padding-bottom:6px;margin-top:34px;color:#8fb8ff}}
.badge{{display:inline-block;padding:8px 18px;border-radius:10px;font-weight:800;background:{v['color']};color:#0b0f1a}}
table{{border-collapse:collapse;width:100%;margin-top:10px}} td,th{{border:1px solid #26334f;padding:7px 10px;text-align:left;vertical-align:top;font-size:13px}}
th{{background:#17213a}} .d{{color:#8b9bbf}} .m{{font-family:Consolas,monospace;font-size:12px;word-break:break-all}}
.s{{font-weight:800}} .critical,.high{{color:#ff4d5e}} .medium{{color:#f5b942}} .low{{color:#4da3ff}} .good{{color:#2ecc71}}
</style></head><body>
<h1>PhishScope - Phishing Email Analysis Report</h1>
<p>Generated {e(m['analyzed_at'])} UTC | File: {e(m['name'])} | SHA-256: <span class='m'>{m['sha256']}</span></p>
<p><span class='badge'>{e(v['label'])} - {R['score']}/100</span></p>
<h2>Message</h2><table>
<tr><th>Subject</th><td>{e(m['subject'])}</td></tr><tr><th>From</th><td>{e(m['from'])}</td></tr>
<tr><th>To</th><td>{e(m['to'])}</td></tr><tr><th>Date</th><td>{e(m['date'])}</td></tr>
<tr><th>Message-ID</th><td>{e(m['message_id'])}</td></tr></table>
<h2>Authentication</h2><table>
<tr><th>SPF</th><td>{e(a['spf']['effective'])} (live: {e(a['spf']['result'])}) - {e(a['spf']['record'])}</td></tr>
<tr><th>DKIM</th><td>{e(a['dkim']['effective'])}</td></tr>
<tr><th>DMARC</th><td>{e(a['dmarc']['effective'])} - {e(a['dmarc'].get('record', ''))}</td></tr></table>
<h2>Findings</h2><table><tr><th>Severity</th><th>Category</th><th>Finding</th><th>Pts</th><th>MITRE</th></tr>{rows}</table>
<h2>URLs</h2><table><tr><th>Score</th><th>URL (defanged)</th><th>Flags</th></tr>{urls}</table>
<h2>Attachments</h2><table><tr><th>File</th><th>Type</th><th>Size</th><th>SHA-256</th><th>Flags</th></tr>{atts}</table>
<h2>MITRE ATT&amp;CK</h2><table><tr><th>ID</th><th>Technique</th><th>Tactic</th></tr>{mitre}</table>
<h2>Indicators of Compromise</h2><table><tr><th>Type</th><th>Value</th><th>Context</th></tr>{iocs}</table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
