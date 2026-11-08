"""PhishScope main window (PyQt5)."""
import sys
import traceback
from html import escape
from pathlib import Path

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QGuiApplication, QKeySequence
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
                             QTabWidget, QFileDialog, QProgressBar, QPlainTextEdit, QTextBrowser, QDialog,
                             QLineEdit, QCheckBox, QFormLayout, QDialogButtonBox, QMessageBox, QFrame,
                             QShortcut, QDoubleSpinBox, QSpinBox, QGridLayout)

from core import config, engine, report
from core.domains import defang, org_domain
from . import theme
from .widgets import Card, Chip, Gauge, mk_table, fill_table


class Worker(QThread):
    progress = pyqtSignal(int, str)
    done = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, path, cfg):
        super().__init__()
        self.path, self.cfg = path, cfg

    def run(self):
        try:
            R = engine.analyze(self.path, self.cfg, lambda p, m: self.progress.emit(p, m))
            self.done.emit(R)
        except Exception:
            self.failed.emit(traceback.format_exc())


class SettingsDialog(QDialog):
    def __init__(self, cfg, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setMinimumWidth(520)
        self.cfg = dict(cfg)
        form = QFormLayout(self)
        self.vt = QLineEdit(cfg.get("vt_api_key", ""))
        self.vt.setEchoMode(QLineEdit.Password)
        self.vt.setPlaceholderText("VirusTotal API key (free key works, 4 req/min)")
        self.maxurl = QSpinBox()
        self.maxurl.setRange(0, 50)
        self.maxurl.setValue(int(cfg.get("max_url_lookups", 4)))
        self.dns = QDoubleSpinBox()
        self.dns.setRange(1, 20)
        self.dns.setValue(float(cfg.get("dns_timeout", 4)))
        self.http = QDoubleSpinBox()
        self.http.setRange(2, 30)
        self.http.setValue(float(cfg.get("http_timeout", 8)))
        form.addRow("VirusTotal API key", self.vt)
        form.addRow("Max URLs to check on VT", self.maxurl)
        form.addRow("DNS timeout (s)", self.dns)
        form.addRow("HTTP timeout (s)", self.http)
        self.boxes = {}
        for key, label in (("use_openphish", "OpenPhish live feed"), ("use_dnsbl", "DNSBL / Spamhaus DBL"),
                           ("use_rdap", "RDAP domain age"), ("use_geoip", "GeoIP / ASN (ip-api.com)")):
            cb = QCheckBox(label)
            cb.setChecked(bool(cfg.get(key, True)))
            self.boxes[key] = cb
            form.addRow("", cb)
        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        form.addRow(bb)

    def result_cfg(self):
        c = self.cfg
        c["vt_api_key"] = self.vt.text().strip()
        c["max_url_lookups"] = self.maxurl.value()
        c["dns_timeout"], c["http_timeout"] = self.dns.value(), self.http.value()
        for k, cb in self.boxes.items():
            c[k] = cb.isChecked()
        return c


def _fmt_delay(s):
    if s is None:
        return ""
    s = int(s)
    if s < 0:
        return f"{s}s (clock skew)"
    if s < 120:
        return f"{s}s"
    if s < 7200:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {(s % 3600) // 60}m"


def _rc(res):
    return theme.RESULT_COLOR.get(str(res).lower(), theme.MUTED)


def _kv(rows):
    out = "<table cellpadding='3' style='width:100%'>"
    for k, v, *col in rows:
        c = col[0] if col else theme.TEXT
        out += (f"<tr><td style='color:{theme.MUTED};white-space:nowrap;vertical-align:top'>{escape(str(k))}</td>"
                f"<td style='color:{c};word-break:break-all'>{escape(str(v))}</td></tr>")
    return out + "</table>"


class MainWindow(QMainWindow):
    def __init__(self, initial=None):
        super().__init__()
        self.cfg = config.load()
        self.R, self.worker, self.defang_on = None, None, True
        self.setWindowTitle("PhishScope - Phishing Email Analyzer | Blue Team Project 10")
        self.resize(1580, 940)
        self.setAcceptDrops(True)
        self._build()
        QShortcut(QKeySequence("Ctrl+O"), self, activated=self.open_file)
        if initial:
            self.analyze(initial)

    # ------------------------------------------------------------------- layout
    def _build(self):
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        v = QVBoxLayout(root)
        v.setContentsMargins(18, 16, 18, 12)
        v.setSpacing(12)

        head = QFrame()
        head.setObjectName("header")
        hl = QHBoxLayout(head)
        hl.setContentsMargins(20, 12, 16, 14)
        tl = QVBoxLayout()
        t = QLabel("PhishScope")
        t.setObjectName("title")
        s = QLabel("Phishing e-mail analyzer  |  live SPF / DKIM / DMARC  |  attachment triage  |  threat intel  |  MITRE ATT&CK")
        s.setObjectName("subtitle")
        tl.addWidget(t)
        tl.addWidget(s)
        hl.addLayout(tl, 1)
        self.btn_open = QPushButton("Open .eml")
        self.btn_open.clicked.connect(self.open_file)
        self.btn_json = QPushButton("Export JSON")
        self.btn_html = QPushButton("HTML Report")
        self.btn_ioc = QPushButton("IOC CSV")
        self.btn_set = QPushButton("Settings")
        for b in (self.btn_json, self.btn_html, self.btn_ioc, self.btn_set):
            b.setObjectName("ghost")
        self.btn_json.clicked.connect(lambda: self.export("json"))
        self.btn_html.clicked.connect(lambda: self.export("html"))
        self.btn_ioc.clicked.connect(lambda: self.export("ioc"))
        self.btn_set.clicked.connect(self.open_settings)
        for b in (self.btn_open, self.btn_json, self.btn_html, self.btn_ioc, self.btn_set):
            hl.addWidget(b)
        v.addWidget(head)

        body = QHBoxLayout()
        body.setSpacing(14)
        left = QVBoxLayout()
        left.setSpacing(14)
        gc = Card("Threat verdict")
        self.gauge = Gauge()
        gc.lay.addWidget(self.gauge, 1)
        self.verdict = QLabel("Drop an .eml file here")
        self.verdict.setObjectName("verdict")
        self.verdict.setAlignment(Qt.AlignCenter)
        gc.lay.addWidget(self.verdict)
        left.addWidget(gc, 3)
        ac = Card("E-mail authentication")
        row = QHBoxLayout()
        self.c_spf, self.c_dkim, self.c_dmarc = Chip("SPF"), Chip("DKIM"), Chip("DMARC")
        for c in (self.c_spf, self.c_dkim, self.c_dmarc):
            row.addWidget(c)
        ac.lay.addLayout(row)
        left.addWidget(ac)
        sc = Card("Message summary")
        self.summary = QLabel("No message loaded.")
        self.summary.setWordWrap(True)
        self.summary.setTextFormat(Qt.RichText)
        self.summary.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        sc.lay.addWidget(self.summary)
        left.addWidget(sc, 2)
        lw = QWidget()
        lw.setLayout(left)
        lw.setFixedWidth(370)
        body.addWidget(lw)

        self.tabs = QTabWidget()
        self.t_find = mk_table(["Severity", "Category", "Finding", "Detail", "Pts", "MITRE"], [90, 110, 300, 520, 50, 120])
        self.tabs.addTab(self.t_find, "Findings")

        auth = QWidget()
        av = QVBoxLayout(auth)
        grid = QHBoxLayout()
        self.b_spf, self.b_dkim, self.b_dmarc = QTextBrowser(), QTextBrowser(), QTextBrowser()
        for title, b in (("SPF (live evaluation)", self.b_spf), ("DKIM (live verification)", self.b_dkim),
                         ("DMARC (policy + alignment)", self.b_dmarc)):
            c = Card(title)
            b.setStyleSheet("background: transparent; border: none;")
            c.lay.addWidget(b)
            grid.addWidget(c)
        av.addLayout(grid, 3)
        self.t_authhdr = mk_table(["Source", "Method", "Result", "Detail"], [220, 80, 90, 600])
        av.addWidget(QLabel("Authentication results recorded by receiving servers (headers):"))
        av.addWidget(self.t_authhdr, 1)
        self.tabs.addTab(auth, "Authentication")

        route = QWidget()
        rv = QVBoxLayout(route)
        self.t_hops = mk_table(["#", "From", "By", "IP", "Time", "Delay", "Protocol"], [40, 330, 280, 130, 190, 90, 90])
        rv.addWidget(self.t_hops, 3)
        rv.addWidget(QLabel("IP intelligence (GeoIP / ASN / DNSBL):"))
        self.t_ip = mk_table(["Role", "IP", "Location", "ISP / ASN", "Reverse DNS", "Flags", "DNSBL"], [190, 120, 200, 260, 200, 120, 200])
        rv.addWidget(self.t_ip, 2)
        self.tabs.addTab(route, "Routing")

        self.t_sender = mk_table(["Field", "Value", "Assessment"], [200, 420, 400])
        self.tabs.addTab(self.t_sender, "Sender")
        self.t_urls = mk_table(["Risk", "URL (defanged)", "Link text", "Domain age", "Feeds / VT", "Flags"], [55, 380, 160, 90, 170, 500])
        self.tabs.addTab(self.t_urls, "URLs")
        self.t_att = mk_table(["File", "Detected", "Size", "Entropy", "SHA-256", "VirusTotal", "Flags"], [190, 80, 80, 70, 280, 140, 400])
        self.tabs.addTab(self.t_att, "Attachments")

        ioc = QWidget()
        iv = QVBoxLayout(ioc)
        bar = QHBoxLayout()
        self.cb_defang = QCheckBox("Defang URLs / domains / IPs")
        self.cb_defang.setChecked(True)
        self.cb_defang.toggled.connect(self._refill_iocs)
        btn_copy = QPushButton("Copy all IOCs")
        btn_copy.setObjectName("ghost")
        btn_copy.clicked.connect(self.copy_iocs)
        bar.addWidget(self.cb_defang)
        bar.addStretch(1)
        bar.addWidget(btn_copy)
        iv.addLayout(bar)
        self.t_ioc = mk_table(["Type", "Indicator", "Context"], [90, 600, 300])
        iv.addWidget(self.t_ioc)
        self.tabs.addTab(ioc, "IOCs")

        self.t_mitre = mk_table(["ID", "Technique", "Tactic", "Evidence"], [100, 340, 170, 600])
        self.tabs.addTab(self.t_mitre, "MITRE ATT&CK")
        self.p_headers = QPlainTextEdit()
        self.p_headers.setReadOnly(True)
        self.tabs.addTab(self.p_headers, "Raw headers")
        self.p_body = QPlainTextEdit()
        self.p_body.setReadOnly(True)
        self.tabs.addTab(self.p_body, "Body (text only)")
        for tbl in (self.t_find, self.t_authhdr, self.t_hops, self.t_ip, self.t_sender, self.t_urls, self.t_att,
                    self.t_ioc, self.t_mitre):
            tbl.cellDoubleClicked.connect(lambda r, c, t=tbl: self._copy_cell(t, r, c))
        body.addWidget(self.tabs, 1)
        v.addLayout(body, 1)

        foot = QHBoxLayout()
        self.status = QLabel("Ready. Drag & drop an .eml file anywhere, or press Ctrl+O. Double-click any cell to copy it.")
        self.status.setObjectName("subtitle")
        self.progress = QProgressBar()
        self.progress.setFixedWidth(360)
        self.progress.setValue(0)
        foot.addWidget(self.status, 1)
        foot.addWidget(self.progress)
        v.addLayout(foot)
        self._set_export(False)

    # ------------------------------------------------------------------ actions
    def _set_export(self, on):
        for b in (self.btn_json, self.btn_html, self.btn_ioc):
            b.setEnabled(on)

    def _copy_cell(self, t, r, c):
        it = t.item(r, c)
        if it:
            QGuiApplication.clipboard().setText(it.text())
            self.status.setText(f"Copied: {it.text()[:90]}")

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        for u in e.mimeData().urls():
            self.analyze(u.toLocalFile())
            break

    def open_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Open e-mail", str(Path.home()),
                                           "E-mail (*.eml *.txt *.msg);;All files (*.*)")
        if p:
            self.analyze(p)

    def open_settings(self):
        d = SettingsDialog(self.cfg, self)
        if d.exec_():
            self.cfg = d.result_cfg()
            config.save(self.cfg)
            self.status.setText("Settings saved.")

    def analyze(self, path):
        if self.worker and self.worker.isRunning():
            return
        self.gauge.reset()
        self.verdict.setText("Analyzing...")
        self.verdict.setStyleSheet(f"color:{theme.ACCENT}")
        self._set_export(False)
        self.btn_open.setEnabled(False)
        self.worker = Worker(path, self.cfg)
        self.worker.progress.connect(lambda p, m: (self.progress.setValue(p), self.status.setText(m)))
        self.worker.done.connect(self.show_result)
        self.worker.failed.connect(self.on_fail)
        self.worker.start()

    def on_fail(self, tb):
        self.btn_open.setEnabled(True)
        self.verdict.setText("Analysis failed")
        QMessageBox.critical(self, "Analysis failed", tb[-1500:])

    def export(self, kind):
        if not self.R:
            return
        stem = Path(self.R["meta"]["name"]).stem
        ext = {"json": "JSON (*.json)", "html": "HTML (*.html)", "ioc": "CSV (*.csv)"}[kind]
        suffix = {"json": ".json", "html": ".html", "ioc": "_iocs.csv"}[kind]
        p, _ = QFileDialog.getSaveFileName(self, "Export", str(config.REPORT_DIR / (stem + suffix)), ext)
        if not p:
            return
        {"json": report.to_json, "html": report.to_html,
         "ioc": lambda R, path: report.iocs_csv(R, path, self.cb_defang.isChecked())}[kind](self.R, p)
        self.status.setText(f"Exported: {p}")

    # ------------------------------------------------------------------ display
    def show_result(self, R):
        self.R = R
        self.btn_open.setEnabled(True)
        self._set_export(True)
        v, m, au, snd = R["verdict"], R["meta"], R["auth"], R["sender"]
        self.gauge.set_score(R["score"], v["label"], v["color"])
        self.verdict.setText(v["label"])
        self.verdict.setStyleSheet(f"color:{v['color']}")
        self.c_spf.set_result(au["spf"]["effective"], _rc(au["spf"]["effective"]))
        self.c_dkim.set_result(au["dkim"]["effective"], _rc(au["dkim"]["effective"]))
        self.c_dmarc.set_result(au["dmarc"]["effective"], _rc(au["dmarc"]["effective"]))
        sev = {}
        for f in R["findings"]:
            sev[f["sev"]] = sev.get(f["sev"], 0) + 1
        self.summary.setText(
            f"<b>Subject</b><br>{escape(m['subject'][:140])}<br><br><b>From</b><br>{escape(m['from'][:120])}<br><br>"
            f"<b>Date</b>: {escape(m['date'])}<br><b>URLs</b>: {len(R['urls'])} &nbsp; <b>Attachments</b>: {len(R['attachments'])}"
            f" &nbsp; <b>Hops</b>: {len(R['hops'])}<br><b>Findings</b>: "
            f"{sev.get('critical', 0) + sev.get('high', 0)} high, {sev.get('medium', 0)} medium, {sev.get('low', 0)} low<br>"
            f"<span style='color:{theme.MUTED}'>SHA-256 {m['sha256'][:32]}...</span>")

        fill_table(self.t_find, [[(f["sev"].upper(), theme.SEV_COLOR.get(f["sev"])), f["cat"], f["title"], f["detail"],
                                  f["points"], f["mitre"]] for f in R["findings"]])
        self._fill_auth(R)
        fill_table(self.t_hops, [[h["n"], h["from"], h["by"], h["ip"], h["time"],
                                  (_fmt_delay(h["delay"]), theme.WARN if (h["delay"] or 0) > 3600 else None), h["with"]]
                                 for h in R["hops"]])
        rows = []
        for i in R["ip_intel"]:
            g = i["geo"]
            flags = ", ".join(x for x, on in (("proxy/VPN", g.get("proxy")), ("hosting/DC", g.get("hosting")),
                                              ("mobile", g.get("mobile"))) if on)
            bl = ", ".join(("LISTED " if b.get("listed") else "clean ") + b["list"] for b in i["dnsbl"]) or "n/a"
            listed = any(b.get("listed") for b in i["dnsbl"])
            rows.append([i["role"], i["ip"], g.get("error") or f"{g.get('city', '')}, {g.get('regionName', '')}, {g.get('country', '')}",
                         f"{g.get('isp', '')} / {g.get('as', '')}", g.get("reverse", ""),
                         (flags, theme.WARN if flags else None), (bl, theme.BAD if listed else None)])
        fill_table(self.t_ip, rows)

        dom = R["domains"].get(org_domain(snd["from_domain"]), {})
        rd = (dom or {}).get("rdap") or {}
        age = rd.get("age_days")
        srows = [["From display name", snd["from_display"], ""],
                 ["From address", snd["from_addr"], ""],
                 ["Return-Path", snd["return_path"], ("Domain differs from From" if snd["return_path_domain"] and snd["return_path_domain"] != snd["from_domain"] else "Matches From", None)],
                 ["Reply-To", ", ".join(snd["reply_to"]), ("Different domain" if any(d != snd["from_domain"] for d in snd["reply_to_domains"]) else "", theme.WARN)],
                 ["Envelope (SPF) domain", snd["envelope_domain"], ""],
                 ["Sender domain age", f"{age} days (created {rd.get('created', '')[:10]})" if age is not None else "unknown",
                  ("NEWLY REGISTERED" if age is not None and age < 30 else "", theme.BAD)],
                 ["Registrar", rd.get("registrar", ""), ""],
                 ["X-Mailer / User-Agent", m["x_mailer"], ""],
                 ["X-Originating-IP", snd["x_originating_ip"], ""],
                 ["Message-ID", m["message_id"], ""], ["To", m["to"], ""], ["Cc", m["cc"], ""]]
        fill_table(self.t_sender, srows)
        self._fill_urls(R)
        fill_table(self.t_att, [[a["filename"], a["kind"], f"{a['size']:,}", a["entropy"], a["sha256"], self._vt_txt(a["vt"]),
                                 ("; ".join(f["text"] for f in a["flags"]) or "no static indicators",
                                  theme.BAD if a["flags"] else theme.GOOD)] for a in R["attachments"]])
        self._refill_iocs()
        fill_table(self.t_mitre, [[t["id"], t["name"], t["tactic"], "; ".join(dict.fromkeys(t["evidence"]))[:300]] for t in R["mitre"]])
        self.p_headers.setPlainText(R["raw_headers"])
        self.p_body.setPlainText(R["body_preview"])
        self.progress.setValue(100)
        self.status.setText(f"Analysis complete: {v['label']} ({R['score']}/100). Double-click any cell to copy.")

    @staticmethod
    def _vt_txt(v):
        if not v:
            return ("not checked", theme.MUTED)
        if v.get("status") == "ok":
            bad = v.get("malicious", 0)
            return (f"{bad} malicious / {v.get('suspicious', 0)} susp.", theme.BAD if bad else theme.GOOD)
        return (v.get("status", ""), theme.MUTED)

    def _fill_urls(self, R):
        rows = []
        for u in R["urls"]:
            col = theme.BAD if u["score"] >= 25 else theme.WARN if u["score"] >= 8 else theme.GOOD
            tag = []
            if u.get("feed"):
                tag.append(u["feed"])
            if u.get("vt"):
                tag.append("VT: " + self._vt_txt(u["vt"])[0])
            rows.append([(u["score"], col), defang(u["url"])[:220], u["text"][:60],
                         f"{u['age_days']}d" if u.get("age_days") is not None else "", ", ".join(tag),
                         "; ".join(f["text"] for f in u["flags"])])
        fill_table(self.t_urls, rows)

    def _fill_auth(self, R):
        a = R["auth"]
        s = a["spf"]
        self.b_spf.setHtml(_kv([
            ("Result", f"{s['effective'].upper()}  (live: {s['result']})", _rc(s["effective"])),
            ("Checked IP", s["ip"]), ("Domain", s["domain"]), ("Policy", s["policy"]),
            ("DNS lookups", f"{s['lookups']} / 10"), ("Record", s["record"] or "none published"),
            ("Evaluation", " > ".join(s["trace"]) or "no mechanism matched"),
            ("Issues", "; ".join(s["issues"]) or "none")]))
        sigs = a["dkim"]["signatures"]
        if not sigs:
            self.b_dkim.setHtml(_kv([("Result", "NONE - no DKIM-Signature header", theme.WARN)]))
        else:
            rows = [("Result", a["dkim"]["effective"].upper(), _rc(a["dkim"]["effective"]))]
            for g in sigs:
                k = g.get("key", {})
                rows += [(f"Signature {g['index'] + 1}", f"d={g['domain']}  s={g['selector']}  a={g['algo']}"),
                         ("Verified", {True: "YES (crypto verified)", False: "NO", None: "not verified (install dkimpy)"}[g["verified"]],
                          theme.GOOD if g["verified"] else theme.BAD),
                         ("Aligned with From", f"relaxed={g['aligned_relaxed']}  strict={g['aligned_strict']}"),
                         ("Covers From header", str(g["signs_from"])),
                         ("Public key", (f"~{k.get('bits')}-bit {k.get('type', 'rsa')}" + ("  REVOKED" if k.get("revoked") else "")
                                         + ("  (test mode)" if k.get("testing") else "")) if k.get("found") else "NOT FOUND in DNS"),
                         ("Error", g["error"])]
            self.b_dkim.setHtml(_kv(rows))
        d = a["dmarc"]
        if not d.get("found"):
            self.b_dmarc.setHtml(_kv([("Result", "NO DMARC RECORD", theme.WARN), ("Domain", d.get("domain", "")),
                                      ("Impact", "Domain can be spoofed without receiver-side enforcement")]))
        else:
            self.b_dmarc.setHtml(_kv([
                ("Result", d["effective"].upper(), _rc(d["effective"])), ("Policy (p)", d["policy"]),
                ("Subdomain policy", d["subdomain_policy"] or "inherits"), ("pct", d["pct"]),
                ("SPF aligned", str(d["spf_aligned"]) + f"  (mode {d['aspf']})"),
                ("DKIM aligned", str(d["dkim_aligned"]) + f"  (mode {d['adkim']})"),
                ("Reports", d["rua"] or "none"), ("Record", d["record"])]))
        fill_table(self.t_authhdr, [[h["server"], h["method"].upper(), (h["result"].upper(), _rc(h["result"])), h["detail"]]
                                    for h in a["header_results"]])

    def _refill_iocs(self):
        if not self.R:
            return
        df = self.cb_defang.isChecked()
        fill_table(self.t_ioc, [[i["type"], defang(i["value"]) if df and i["type"] in ("url", "domain", "email", "ip") else i["value"],
                                 i["context"]] for i in self.R["iocs"]])

    def copy_iocs(self):
        if not self.R:
            return
        lines = [self.t_ioc.item(r, 1).text() for r in range(self.t_ioc.rowCount())]
        QGuiApplication.clipboard().setText("\n".join(lines))
        self.status.setText(f"{len(lines)} IOCs copied to clipboard")


def run(initial=None):
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    app.setStyleSheet(theme.stylesheet())
    w = MainWindow(initial)
    w.show()
    sys.exit(app.exec_())
