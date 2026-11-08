#!/usr/bin/env python3
"""SysmonHunter Web - upload logs, paste events or scan this PC live from the browser."""
import json
import os
import re
import tempfile
import threading
import webbrowser
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime

from flask import Flask, Response, request

from sysmonhunter.demo import generate
from sysmonhunter.engine import analyze
from sysmonhunter.parser import LIVE_CHANNELS, event_from_element, is_admin, read_evtx, read_live
from sysmonhunter.report import TEMPLATE, build_graph
from sysmonhunter.rules import SEV_ORDER, SEV_SCORE, TACTICS, catalog

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1 GB upload limit
HERE = os.path.dirname(os.path.abspath(__file__))

CSS = """
*{box-sizing:border-box}body{margin:0;background:radial-gradient(1200px 600px at 80% -10%,#10234a 0,#070b14 60%);color:#e2e8f0;font:15px/1.5 Segoe UI,system-ui,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:28px}h1{margin:0;font-size:30px}h1 span{color:#38bdf8}
.muted{color:#8b9bb8}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:18px;margin-top:22px}
.card{background:#0f1626;border:1px solid #1f2a44;border-radius:14px;padding:20px}.card h2{margin:0 0 6px;font-size:17px;color:#38bdf8}
.drop{display:block;border:2px dashed #2b3b63;border-radius:12px;padding:26px;text-align:center;cursor:pointer;margin:12px 0;color:#8b9bb8}
.drop:hover{border-color:#38bdf8}input[type=file]{display:none}
textarea{width:100%;height:120px;background:#0b1222;border:1px solid #1f2a44;color:#e2e8f0;border-radius:8px;padding:8px;font-family:Consolas,monospace;font-size:12px}
input[type=number]{background:#0b1222;border:1px solid #1f2a44;color:#e2e8f0;border-radius:6px;padding:4px 8px;width:90px}
button{background:#38bdf8;color:#04121f;border:0;border-radius:8px;padding:10px 18px;font-weight:700;cursor:pointer;margin-top:10px}button:hover{background:#7dd3fc}
.badge{display:inline-block;padding:2px 10px;border-radius:10px;font-size:12px;margin-right:8px}.ok{background:#14532d}.warn{background:#7c2d12}
label.c{display:block;font-size:13px;margin:3px 0}a{color:#38bdf8}
"""

INDEX = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>SysmonHunter</title><style>%(css)s</style></head><body><div class="wrap">
<h1>Sysmon<span>Hunter</span></h1>
<p class="muted">Windows Event + Sysmon threat hunting. Give it logs, get ATT&amp;CK-mapped detections, a kill-chain verdict and a 3D attack graph.</p>
<div><span class="badge %(admin_cls)s">%(admin_txt)s</span><span class="badge %(evtx_cls)s">%(evtx_txt)s</span><span class="badge ok">%(rules)d detection rules</span></div>
<div class="grid">
<form class="card" method="post" action="/analyze" enctype="multipart/form-data">
<h2>1. Upload log files</h2><div class="muted">.evtx (Sysmon / Security / System / PowerShell) or .xml exported with wevtutil. Multiple files allowed.</div>
<input type="hidden" name="mode" value="upload">
<label class="drop" id="dz"><span id="dzt">Click to choose files</span><input type="file" name="files" id="fi" multiple accept=".evtx,.xml,.txt"></label>
<button type="submit">Analyze files</button></form>
<form class="card" method="post" action="/analyze">
<h2>2. Paste event XML</h2><div class="muted">Paste one or many &lt;Event&gt; XML blocks (Event Viewer &gt; Details &gt; XML View).</div>
<input type="hidden" name="mode" value="paste"><textarea name="xml" placeholder="&lt;Event xmlns=...&gt; ... &lt;/Event&gt;"></textarea>
<button type="submit">Analyze pasted events</button></form>
<form class="card" method="post" action="/analyze">
<h2>3. Scan this PC (live)</h2><div class="muted">Reads the newest events from this machine. Run the app from an Administrator terminal for the Security log.</div>
<input type="hidden" name="mode" value="live">
<div style="margin:10px 0">%(channels)s</div>Max events per log: <input type="number" name="max" value="3000" min="100" max="50000">
<br><button type="submit">Scan live logs</button></form>
<form class="card" method="post" action="/analyze">
<h2>4. Demo</h2><div class="muted">Simulated intrusion (phishing, persistence, credential theft, lateral movement, ransomware prep). Good for a quick tour.</div>
<input type="hidden" name="mode" value="demo"><button type="submit">Run demo</button></form>
</div>
<p class="muted" style="margin-top:24px">Runs 100%% locally on 127.0.0.1. Nothing is uploaded to the internet.</p></div>
<script>document.getElementById('fi').onchange=function(e){var n=e.target.files.length;document.getElementById('dzt').textContent=n?n+' file(s) selected: '+Array.from(e.target.files).map(function(f){return f.name}).join(', '):'Click to choose files';};</script>
</body></html>"""


def page(message, code=200):
    html = ("<!DOCTYPE html><html><head><meta charset='utf-8'><style>%s</style></head><body><div class='wrap'>"
            "<h1>Sysmon<span>Hunter</span></h1><div class='card' style='margin-top:20px'><h2>Notice</h2><p></p></div>"
            "<p><a href='/'>&larr; Back</a></p></div></body></html>") % CSS
    from html import escape
    html = html.replace("<p></p>", "<p>%s</p>" % escape(message), 1)
    return Response(html, status=code, mimetype="text/html")


def events_from_xml(text):
    text = re.sub(r"<\?xml[^>]*\?>", "", text or "").strip()
    if not text:
        return []
    root = ET.fromstring("<Wrapper>" + text + "</Wrapper>")
    out = []
    for el in root.iter():
        if el.tag.split("}")[-1] == "Event":
            ev = event_from_element(el)
            if ev:
                out.append(ev)
    return out


def render(source, count, findings, events):
    hosts = defaultdict(list)
    for f in findings:
        hosts[f["host"]].append(SEV_SCORE[f["severity"]])
    rows = sorted(({"host": h, "count": len(v), "score": min(100, sum(v) // 2)} for h, v in hosts.items()),
                  key=lambda x: -x["score"])
    data = {"meta": {"source": source, "events": count, "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
            "findings": findings, "hosts": rows, "tactics": TACTICS, "sev": SEV_ORDER,
            "graph": build_graph(events, findings), "rules": len(catalog())}
    html = TEMPLATE.replace("__DATA__", json.dumps(data).replace("</", "<\\/"))
    return html.replace("<h1>", '<p><a href="/">&larr; New analysis</a></p><h1>', 1)


@app.route("/")
def index():
    try:
        import Evtx  # noqa: F401
        evtx_ok = True
    except ImportError:
        evtx_ok = False
    admin = is_admin()
    channels = "".join('<label class="c"><input type="checkbox" name="channel" value="%s" checked> %s</label>' % (c, c)
                       for c in LIVE_CHANNELS)
    return Response(INDEX % {
        "css": CSS, "channels": channels, "rules": len(catalog()),
        "admin_cls": "ok" if admin else "warn", "admin_txt": "Administrator" if admin else "Not admin (Security log limited)",
        "evtx_cls": "ok" if evtx_ok else "warn", "evtx_txt": ".evtx support ready" if evtx_ok else "python-evtx missing: pip install python-evtx",
    }, mimetype="text/html")


@app.route("/analyze", methods=["POST"])
def run():
    mode = request.form.get("mode", "")
    events, notes, source = [], [], ""
    try:
        if mode == "demo":
            events, source = generate(), "Demo dataset (simulated intrusion)"
        elif mode == "live":
            channels = request.form.getlist("channel") or LIVE_CHANNELS
            limit = max(100, min(50000, int(request.form.get("max") or 3000)))
            source = "Live logs: " + os.environ.get("COMPUTERNAME", "localhost")
            for ch in channels:
                evs, err = read_live(ch, limit)
                if err:
                    notes.append("%s: %s" % (ch, err.splitlines()[0]))
                events += evs
        elif mode == "upload":
            names = []
            for f in request.files.getlist("files"):
                if not f or not f.filename:
                    continue
                names.append(f.filename)
                ext = os.path.splitext(f.filename)[1].lower()
                if ext == ".evtx":
                    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".evtx")
                    tmp.close()
                    try:
                        f.save(tmp.name)
                        events += read_evtx(tmp.name)
                    finally:
                        os.unlink(tmp.name)
                elif ext in (".xml", ".txt"):
                    events += events_from_xml(f.read().decode("utf-8", "replace"))
                else:
                    notes.append("Skipped unsupported file: " + f.filename)
            source = "Uploaded: " + ", ".join(names)
        elif mode == "paste":
            events, source = events_from_xml(request.form.get("xml", "")), "Pasted event XML"
        else:
            return page("Unknown mode.", 400)
    except SystemExit as exc:
        return page(str(exc), 500)
    except Exception as exc:
        return page("Could not process the input: %s" % exc, 500)

    if not events:
        return page("No events could be parsed. " + " ".join(notes) + " Check the file type or run as Administrator for live scans.", 400)

    findings = analyze(events)
    html = render(source, len(events), findings, events)
    out_dir = os.path.join(HERE, "reports")
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "web_report_%s.html" % datetime.now().strftime("%Y%m%d_%H%M%S")), "w", encoding="utf-8") as fh:
        fh.write(html)
    return Response(html, mimetype="text/html")


if __name__ == "__main__":
    port = 5000
    print("SysmonHunter Web running at http://127.0.0.1:%d  (Ctrl+C to stop)" % port)
    threading.Timer(1.2, lambda: webbrowser.open("http://127.0.0.1:%d" % port)).start()
    app.run(host="127.0.0.1", port=port, debug=False)