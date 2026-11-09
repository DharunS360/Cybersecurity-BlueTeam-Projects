#!/usr/bin/env python3
"""SysmonHunter Web - upload logs, paste events or scan this PC live from the browser."""
import json
import hashlib
import secrets
import hmac
import os
import re
import ipaddress
from urllib.parse import urlsplit
import tempfile
import threading
import webbrowser
from defusedxml import ElementTree as ET
from datetime import datetime

from flask import Flask, Response, request, session

from sysmonhunter.engine import analyze
from sysmonhunter.parser import LIVE_CHANNELS, event_from_element, is_admin, read_evtx, read_live
from sysmonhunter.report import TEMPLATE, build_graph, host_risk_rows, telemetry_coverage
from sysmonhunter.rules import SEV_ORDER, TACTICS, catalog

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_SECURE=False)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024 * 1024  # 256 MB local upload limit
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
<p class="muted">Windows Event + Sysmon threat hunting. Analyse genuine event records and review evidence-linked detections.</p>
<div><span class="badge %(admin_cls)s">%(admin_txt)s</span><span class="badge %(evtx_cls)s">%(evtx_txt)s</span><span class="badge ok">%(rules)d detection rules</span></div>
<div class="grid">
<form class="card" method="post" action="/analyze" enctype="multipart/form-data">
<h2>1. Upload log files</h2><div class="muted">.evtx (Sysmon / Security / System / PowerShell) or .xml exported with wevtutil. Multiple files allowed.</div>
<input type="hidden" name="mode" value="upload"><input type="hidden" name="csrf_token" value="%(csrf)s">
<label class="drop" id="dz"><span id="dzt">Click to choose files</span><input type="file" name="files" id="fi" multiple accept=".evtx,.xml,.txt"></label>
<button type="submit">Analyze files</button></form>
<form class="card" method="post" action="/analyze">
<h2>2. Paste event XML</h2><div class="muted">Paste one or many &lt;Event&gt; XML blocks (Event Viewer &gt; Details &gt; XML View).</div>
<input type="hidden" name="mode" value="paste"><input type="hidden" name="csrf_token" value="%(csrf)s"><textarea name="xml" placeholder="&lt;Event xmlns=...&gt; ... &lt;/Event&gt;"></textarea>
<button type="submit">Analyze pasted events</button></form>
<form class="card" method="post" action="/analyze">
<h2>3. Scan this PC (live)</h2><div class="muted">Reads the newest events from this machine using your current Windows permissions. The web server never elevates itself. Protected channels may return Access Denied; upload EVTX exports if needed.</div>
<input type="hidden" name="mode" value="live"><input type="hidden" name="csrf_token" value="%(csrf)s">
<div style="margin:10px 0">%(channels)s</div>Max events per log: <input type="number" name="max" value="3000" min="100" max="50000">
<br><button type="submit">Scan live logs</button></form>
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
    try:
        root = ET.fromstring("<Wrapper>" + text + "</Wrapper>")
    except ET.ParseError as exc:
        raise ValueError("The supplied XML is not well-formed: %s" % exc) from exc
    out = []
    for el in root.iter():
        if el.tag.split("}")[-1] == "Event":
            ev = event_from_element(el)
            if ev:
                out.append(ev)
    return out


def render(source, count, findings, events, notes=None):
    rows = host_risk_rows(findings)
    data = {"meta": {"source": source, "events": count, "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")},
            "findings": findings, "hosts": rows, "tactics": TACTICS, "sev": SEV_ORDER,
            "graph": build_graph(events, findings), "coverage": telemetry_coverage(events), "rules": len(catalog()), "notices": notes or []}
    # Escape HTML-significant characters before embedding JSON in a script.
    payload = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    payload = (payload.replace("&", "\\u0026").replace("<", "\\u003c")
                      .replace(">", "\\u003e").replace("\u2028", "\\u2028")
                      .replace("\u2029", "\\u2029"))
    html = TEMPLATE.replace("__DATA__", payload)
    return html.replace("<h1>", '<p><a href="/">&larr; New analysis</a></p><h1>', 1)



@app.after_request
def harden_response(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.errorhandler(413)
def too_large(_error):
    return page("Upload exceeds the 256 MB limit. Split the EVTX export into smaller files and retry.", 413)


@app.route("/")
def index():
    try:
        import Evtx  # noqa: F401
        evtx_ok = True
    except ImportError:
        evtx_ok = False
    admin = is_admin()
    csrf = session.setdefault("_csrf", secrets.token_urlsafe(32))
    channels = "".join('<label class="c"><input type="checkbox" name="channel" value="%s" checked> %s</label>' % (c, c)
                       for c in LIVE_CHANNELS)
    return Response(INDEX % {
        "css": CSS, "channels": channels, "rules": len(catalog()),
        "admin_cls": "ok" if admin else "warn", "admin_txt": "Administrator" if admin else "Standard user (protected live channels may be limited)",
        "csrf": csrf,
        "evtx_cls": "ok" if evtx_ok else "warn", "evtx_txt": ".evtx support ready" if evtx_ok else "python-evtx missing: pip install python-evtx",
    }, mimetype="text/html")


def _is_loopback_name(hostname):
    """Accept only literal loopback addresses or localhost names."""
    if not hostname:
        return False
    name = hostname.rstrip(".").lower()
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False




@app.before_request
def enforce_loopback_host():
    # The server is bound to 127.0.0.1. Reject unexpected Host headers as defense
    # in depth; do not trust forwarded headers from arbitrary local processes.
    try:
        hostname = urlsplit(request.host_url).hostname
    except ValueError:
        hostname = None
    if not _is_loopback_name(hostname):
        return page("This application is available only through a loopback address.", 403)



def _same_local_origin(origin_value):
    """Require a same-origin HTTP request to this loopback-only application."""
    try:
        origin = urlsplit(origin_value)
        target = urlsplit(request.host_url)
        # Origin headers are serialized origins, not arbitrary URLs.
        if origin.scheme != "http" or origin.username or origin.password:
            return False
        if origin.path not in ("", "/") or origin.query or origin.fragment:
            return False
        if not _is_loopback_name(origin.hostname) or not _is_loopback_name(target.hostname):
            return False
        origin_port = origin.port if origin.port is not None else 80
        target_port = target.port if target.port is not None else 80
        return origin.scheme == target.scheme and origin.hostname.lower() == target.hostname.lower() and origin_port == target_port
    except (TypeError, ValueError):
        return False


@app.route("/analyze", methods=["POST"])
def run():
    if not _is_loopback_name(urlsplit(request.host_url).hostname):
        return page("This application accepts requests only through a loopback address.", 403)
    try:
        if request.remote_addr and not ipaddress.ip_address(request.remote_addr).is_loopback:
            return page("This application accepts requests only from this computer.", 403)
    except ValueError:
        return page("The client address could not be validated.", 403)
    supplied = request.form.get("csrf_token", "")
    expected = session.get("_csrf", "")
    if not expected or not hmac.compare_digest(supplied, expected):
        return page("This request could not be verified. Refresh the page and try again.", 403)
    # Fetch Metadata is an additional browser signal. Reject explicitly
    # cross-site submissions, but do not treat Origin: null as proof of an
    # attack when the session-bound CSRF token has already been validated.
    # Browsers can serialize opaque/local-file/sandboxed origins as "null".
    fetch_site = request.headers.get("Sec-Fetch-Site", "").strip().lower()
    if fetch_site == "cross-site":
        app.logger.warning("Rejected cross-site POST to /analyze from %r", request.remote_addr)
        return page("Cross-site requests are not accepted. Open SysmonHunter directly at http://127.0.0.1:5000 and retry.", 403)

    origin = request.headers.get("Origin")
    if origin and origin.lower() != "null" and not _same_local_origin(origin):
        app.logger.warning("Rejected request origin %r for local host %r", origin, request.host)
        return page("The browser origin does not match this local application. Open http://127.0.0.1:5000, refresh the page, and retry.", 403)
    if origin and origin.lower() == "null":
        app.logger.info("Accepted opaque Origin only after valid session CSRF token; Fetch-Site=%r", fetch_site or "not supplied")
    mode = request.form.get("mode", "")
    events, notes, source = [], [], ""
    try:
        if mode == "live":
            requested = request.form.getlist("channel")
            channels = [ch for ch in requested if ch in LIVE_CHANNELS] if requested else list(LIVE_CHANNELS)
            if not channels:
                return page("Select at least one supported Windows event channel.", 400)
            try:
                limit = max(100, min(50000, int(request.form.get("max") or 3000)))
            except ValueError:
                return page("Maximum events must be a whole number between 100 and 50000.", 400)
            source = "Live logs: " + os.environ.get("COMPUTERNAME", "localhost")
            for ch in channels:
                evs, err = read_live(ch, limit)
                if err:
                    notes.append("%s: %s" % (ch, err.splitlines()[0]))
                events += evs
        elif mode == "upload":
            names = []
            uploaded = [f for f in request.files.getlist("files") if f and f.filename]
            if not uploaded:
                return page("Choose at least one .evtx or exported .xml file before analyzing.", 400)
            for f in uploaded:
                if not f or not f.filename:
                    continue
                names.append(os.path.basename(f.filename.replace("\\\\", "/")))
                ext = os.path.splitext(f.filename)[1].lower()
                if ext == ".evtx":
                    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".evtx")
                    tmp.close()
                    try:
                        f.save(tmp.name)
                        digest = hashlib.sha256()
                        with open(tmp.name, "rb") as evidence_file:
                            for chunk in iter(lambda: evidence_file.read(1024 * 1024), b""):
                                digest.update(chunk)
                        notes.append("Evidence SHA-256 (%s): %s" % (os.path.basename(f.filename.replace("\\\\", "/")), digest.hexdigest()))
                        try:
                            parsed = read_evtx(tmp.name)
                            events.extend(parsed)
                            if not parsed:
                                notes.append("No readable event records found in: " + os.path.basename(f.filename.replace("\\\\", "/")))
                        except Exception as exc:
                            notes.append("Could not parse %s: %s" % (os.path.basename(f.filename.replace("\\\\", "/")), str(exc).splitlines()[0]))
                    finally:
                        try:
                            os.unlink(tmp.name)
                        except OSError:
                            pass
                elif ext in (".xml", ".txt"):
                    raw = f.read()
                    notes.append("Evidence SHA-256 (%s): %s" % (os.path.basename(f.filename.replace("\\\\", "/")), hashlib.sha256(raw).hexdigest()))
                    try:
                        decoded = raw.decode("utf-8-sig")
                    except UnicodeDecodeError:
                        decoded = raw.decode("utf-16", "replace")
                    try:
                        parsed = events_from_xml(decoded)
                        events.extend(parsed)
                        if not parsed:
                            notes.append("No event records found in: " + os.path.basename(f.filename.replace("\\\\", "/")))
                    except ValueError as exc:
                        notes.append("Could not parse %s: %s" % (os.path.basename(f.filename.replace("\\\\", "/")), str(exc)))
                else:
                    notes.append("Skipped unsupported file: " + os.path.basename(f.filename.replace("\\\\", "/")))
            source = "Uploaded: " + ", ".join(names)
        elif mode == "paste":
            events, source = events_from_xml(request.form.get("xml", "")), "Pasted event XML"
            pasted = request.form.get("xml", "")
            notes.append("XML provenance note: pasted XML is operator-supplied; SysmonHunter cannot independently prove its origin. Prefer original EVTX or live collection for evidence handling.")
            notes.append("Pasted XML SHA-256: %s" % hashlib.sha256(pasted.encode("utf-8")).hexdigest())
        else:
            return page("Unknown mode.", 400)
    except SystemExit as exc:
        return page(str(exc), 500)
    except ValueError as exc:
        return page(str(exc), 400)
    except Exception:
        app.logger.exception("Analysis request failed")
        return page("The analysis could not be completed. Check the terminal for the detailed error. "
                    "For EVTX uploads, confirm python-evtx is installed and the file is valid.", 500)

    # Multiple uploaded exports can overlap. Deduplicate by stable event identity
    # while preserving original order and all distinct records.
    unique_events, seen_events = [], set()
    for ev in events:
        key = (ev.get("host"), ev.get("channel"), ev.get("record_id"), ev.get("provider"),
               ev.get("eid"), ev.get("time"), json.dumps(ev.get("data", {}), sort_keys=True, ensure_ascii=False))
        if key in seen_events:
            continue
        seen_events.add(key)
        unique_events.append(ev)
    events = unique_events

    if not events:
        return page("No events could be parsed. " + " ".join(notes) + " Check the file type and Windows channel permissions.", 400)

    try:
        diagnostics = []
        findings = analyze(events, diagnostics=diagnostics)
        if diagnostics:
            for diagnostic in diagnostics:
                app.logger.error("Detection rule %s failed: %s", diagnostic.get("rule_id"), diagnostic.get("error"))
            notes.append("Detection rule errors: %d rule evaluation(s) failed. Review the application terminal; affected rules were not silently treated as clean." % len(diagnostics))
        html = render(source, len(events), findings, events, notes)
        out_dir = os.path.join(HERE, "reports")
        os.makedirs(out_dir, exist_ok=True)
        report_name = "web_report_%s.html" % datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        with open(os.path.join(out_dir, report_name), "w", encoding="utf-8") as fh:
            fh.write(html)
    except Exception:
        app.logger.exception("Detection, correlation, or report rendering failed")
        return page("The events were parsed, but detection/report generation failed. Check the application terminal for the detailed traceback.", 500)
    return Response(html, mimetype="text/html")



if __name__ == "__main__":
    port = 5000
    print("SysmonHunter Web running at http://127.0.0.1:%d  (Ctrl+C to stop)" % port)
    print("Security note: the Flask web server runs with the current user privileges; it never requests UAC elevation.")
    threading.Timer(1.2, lambda: webbrowser.open("http://127.0.0.1:%d" % port)).start()
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True, use_reloader=False)
