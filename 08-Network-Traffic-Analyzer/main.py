"""Network Traffic Analyzer v2 - Blue Team Console (mini NDR).

Live capture / PCAP analysis with flow tracking, process attribution, TLS SNI + JA3, GeoIP/ASN enrichment,
threat-intel matching and MITRE ATT&CK mapped detections.

Run as Administrator with Npcap installed:  python main.py
"""
import csv
import html
import json
import os
import sys
import threading
import time

import pyqtgraph as pg
from PyQt5 import QtCore, QtGui, QtWidgets
from scapy.all import AsyncSniffer, Ether, PcapReader, conf, wrpcap

from core.analyzer import ADVICE, Analyzer, LogWriter
from core.enrich import Enricher, ProcessMapper, local_addresses
from core.intel import ThreatIntel

BASE = os.path.dirname(os.path.abspath(__file__))
REPORTS = os.path.join(BASE, "reports")
SEV_COLOR = {"Critical": "#ff4d6d", "High": "#ff9f43", "Medium": "#ffd166", "Low": "#7bdff2"}
APP_COLOR = {"HTTPS": "#58d6ff", "QUIC": "#a78bfa", "DNS": "#34d399", "HTTP": "#fbbf24", "ARP": "#f472b6"}

QSS = """
* { font-family: 'Segoe UI'; font-size: 13px; color: #e6edf3; }
QMainWindow, QWidget#root { background: #0b0f19; }
QFrame#card { background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #1d2840, stop:1 #101726);
              border: 1px solid #2f4268; border-radius: 14px; }
QLabel#kpiTitle { color: #8aa0c2; font-size: 11px; font-weight: 600; }
QLabel#kpiValue { font-size: 24px; font-weight: 700; }
QLabel#title { font-size: 22px; font-weight: 700; color: #ffffff; }
QLabel#sub { color: #8aa0c2; }
QLabel#section { color: #58d6ff; font-weight: 700; font-size: 13px; padding: 4px 2px; }
QPushButton { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #3a7bff, stop:1 #1f4fb8);
              border: 1px solid #5a95ff; border-radius: 8px; padding: 7px 14px; font-weight: 600; }
QPushButton:hover { background: #4b87ff; }
QPushButton:disabled { background: #1a2335; border-color: #2b3a55; color: #5d6b85; }
QPushButton#danger { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #ef4466, stop:1 #b01e3c); border-color: #ff6b88; }
QPushButton#ghost { background: #131c2f; border: 1px solid #34486f; }
QPushButton#ghost:hover { background: #1b2842; }
QTabWidget::pane { border: 1px solid #2b3a55; border-radius: 10px; top: -1px; background: #0e1524; }
QTabBar::tab { background: #121a2b; padding: 9px 16px; border: 1px solid #2b3a55; border-bottom: none;
               border-top-left-radius: 9px; border-top-right-radius: 9px; margin-right: 3px; color: #8aa0c2; }
QTabBar::tab:selected { background: #1d2a45; color: #58d6ff; font-weight: 600; }
QTableWidget { background: #0e1524; border: none; alternate-background-color: #111a2d;
               selection-background-color: #24406e; gridline-color: #0e1524; }
QHeaderView::section { background: #16213a; padding: 6px; border: none; border-bottom: 2px solid #3a7bff; font-weight: 600; }
QComboBox, QLineEdit, QTextEdit { background: #0e1524; border: 1px solid #2f4268; border-radius: 8px; padding: 6px 10px; }
QComboBox QAbstractItemView { background: #0e1524; selection-background-color: #24406e; }
QCheckBox { color: #8aa0c2; }
QStatusBar { background: #0b0f19; color: #8aa0c2; }
QMenu { background: #121a2b; border: 1px solid #2f4268; }
QMenu::item:selected { background: #24406e; }
"""


def human(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return "%d B" % n if u == "B" else "%.1f %s" % (n, u)
        n /= 1024.0
    return "%.1f PB" % n


def tstr(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts))


def dur(s):
    s = int(s)
    return "%dh%02dm" % (s // 3600, s % 3600 // 60) if s >= 3600 else ("%dm%02ds" % (s // 60, s % 60) if s >= 60 else "%ds" % s)


def risk_color(r):
    return "#ff4d6d" if r >= 70 else ("#ffd166" if r >= 40 else ("#7bdff2" if r > 0 else None))


def list_ifaces():
    out = []
    try:
        for i in conf.ifaces.values():
            name = getattr(i, "name", str(i))
            desc = getattr(i, "description", "") or name
            ip = getattr(i, "ip", "") or ""
            out.append((("%s  [%s]" % (desc, ip)) if ip else desc, i, bool(ip and ip != "0.0.0.0")))
    except Exception:
        pass
    out.sort(key=lambda x: not x[2])
    return out


class Card(QtWidgets.QFrame):
    def __init__(self, title, color="#58d6ff"):
        super().__init__()
        self.setObjectName("card")
        eff = QtWidgets.QGraphicsDropShadowEffect(self)
        eff.setBlurRadius(30)
        eff.setOffset(0, 8)
        eff.setColor(QtGui.QColor(0, 0, 0, 180))
        self.setGraphicsEffect(eff)
        lay = QtWidgets.QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        t = QtWidgets.QLabel(title.upper())
        t.setObjectName("kpiTitle")
        self.v = QtWidgets.QLabel("0")
        self.v.setObjectName("kpiValue")
        self.v.setStyleSheet("color:%s;" % color)
        lay.addWidget(t)
        lay.addWidget(self.v)

    def set(self, text, color=None):
        self.v.setText(text)
        if color:
            self.v.setStyleSheet("color:%s;" % color)


def make_table(headers, widths=None):
    t = QtWidgets.QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    t.setAlternatingRowColors(True)
    t.verticalHeader().setVisible(False)
    t.verticalHeader().setDefaultSectionSize(25)
    t.setShowGrid(False)
    t.horizontalHeader().setStretchLastSection(True)
    for i, w in enumerate(widths or []):
        t.setColumnWidth(i, w)
    return t


def put(t, row, vals, colors=None, row_color=None):
    for c, v in enumerate(vals):
        it = QtWidgets.QTableWidgetItem(str(v))
        col = (colors or {}).get(c) or row_color
        if col:
            it.setForeground(QtGui.QBrush(QtGui.QColor(col)))
        t.setItem(row, c, it)


def fill(t, rows, colors_fn=None):
    t.setUpdatesEnabled(False)
    t.setRowCount(len(rows))
    for i, vals in enumerate(rows):
        put(t, i, vals, *(colors_fn(vals) if colors_fn else ()))
    t.setUpdatesEnabled(True)


def section(text):
    l = QtWidgets.QLabel(text)
    l.setObjectName("section")
    return l


class PcapWorker(QtCore.QThread):
    done = QtCore.pyqtSignal(int, str)

    def __init__(self, path, analyzer):
        super().__init__()
        self.path, self.an = path, analyzer

    def run(self):
        n, err = 0, ""
        try:
            with PcapReader(self.path) as r:
                for p in r:
                    self.an.process(p)
                    n += 1
                    if n % 2000 == 0:
                        self.an.sweep()
        except Exception as e:
            err = str(e)
        self.done.emit(n, err)


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Traffic Analyzer v2 - Blue Team Console")
        self.resize(1520, 940)
        self.intel = ThreatIntel()
        self.enricher = Enricher()
        self.procmap = ProcessMapper()
        self.logger = LogWriter(BASE)
        self.an = Analyzer(self.intel, self.enricher, self.procmap, self.logger)
        self.sniffer = None
        self.worker = None
        self.state = "IDLE"
        self.alert_idx = 0
        self.last_sweep = 0.0
        self._build()
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(1000)
        threading.Thread(target=self.intel.update, daemon=True).start()

    # ------------------------------------------------------------------- UI
    def _build(self):
        root = QtWidgets.QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        v = QtWidgets.QVBoxLayout(root)
        v.setContentsMargins(20, 14, 20, 6)
        v.setSpacing(10)

        t = QtWidgets.QLabel("Network Traffic Analyzer")
        t.setObjectName("title")
        s = QtWidgets.QLabel("Flows | Process attribution | TLS SNI + JA3 | GeoIP/ASN | DNS analytics | Threat intel | MITRE ATT&CK")
        s.setObjectName("sub")
        v.addWidget(t)
        v.addWidget(s)

        ctl = QtWidgets.QHBoxLayout()
        self.cmb = QtWidgets.QComboBox()
        self.cmb.setMinimumWidth(340)
        for text, obj, _ in list_ifaces():
            self.cmb.addItem(text, obj)
        try:
            for k in range(self.cmb.count()):
                if self.cmb.itemData(k) is conf.iface:
                    self.cmb.setCurrentIndex(k)
                    break
        except Exception:
            pass
        self.bpf = QtWidgets.QLineEdit()
        self.bpf.setPlaceholderText("BPF filter (optional)")
        self.bpf.setMaximumWidth(200)
        self.b_start = QtWidgets.QPushButton("Start Capture")
        self.b_stop = QtWidgets.QPushButton("Stop")
        self.b_stop.setObjectName("danger")
        self.b_stop.setEnabled(False)
        self.b_pcap = QtWidgets.QPushButton("Load PCAP")
        self.b_savepcap = QtWidgets.QPushButton("Save PCAP")
        self.b_clear = QtWidgets.QPushButton("Clear")
        self.b_intel = QtWidgets.QPushButton("Update Intel")
        for b in (self.b_pcap, self.b_savepcap, self.b_clear, self.b_intel):
            b.setObjectName("ghost")
        self.b_export = QtWidgets.QPushButton("Export Report")
        self.chk_geo = QtWidgets.QCheckBox("Online GeoIP/ASN")
        self.chk_geo.setChecked(True)
        self.chk_geo.setToolTip("Sends remote public IPs to ipwho.is for country/ASN lookup. Untick for fully offline use.")
        for w in (self.cmb, self.bpf, self.b_start, self.b_stop, self.b_pcap, self.b_savepcap, self.b_clear,
                  self.b_intel, self.b_export, self.chk_geo):
            ctl.addWidget(w)
        ctl.addStretch()
        v.addLayout(ctl)
        self.b_start.clicked.connect(self.start)
        self.b_stop.clicked.connect(self.stop)
        self.b_pcap.clicked.connect(self.load_pcap)
        self.b_savepcap.clicked.connect(self.save_pcap)
        self.b_clear.clicked.connect(self.clear_all)
        self.b_intel.clicked.connect(lambda: threading.Thread(target=self.intel.update, daemon=True).start())
        self.b_export.clicked.connect(self.export)
        self.chk_geo.toggled.connect(lambda on: setattr(self.enricher, "enabled", on))

        kr = QtWidgets.QHBoxLayout()
        kr.setSpacing(12)
        self.k_pkts = Card("Packets")
        self.k_bytes = Card("Traffic", "#a78bfa")
        self.k_flows = Card("Active flows", "#34d399")
        self.k_hosts = Card("Remote hosts", "#58d6ff")
        self.k_alerts = Card("Alerts", "#ffd166")
        self.k_risky = Card("High-risk hosts", "#ff4d6d")
        self.k_ioc = Card("Intel IOCs", "#34d399")
        self.k_state = Card("Status", "#8aa0c2")
        for k in (self.k_pkts, self.k_bytes, self.k_flows, self.k_hosts, self.k_alerts, self.k_risky, self.k_ioc, self.k_state):
            kr.addWidget(k)
        v.addLayout(kr)

        pg.setConfigOptions(antialias=True, background="#0e1524", foreground="#8aa0c2")
        self.tabs = QtWidgets.QTabWidget()
        v.addWidget(self.tabs, 1)
        self._tab_overview()
        self._tab_flows()
        self._tab_procs()
        self._tab_dests()
        self._tab_tls()
        self._tab_dns()
        self._tab_packets()
        self._tab_alerts()
        self._tab_mitre()
        self._tab_intel()
        self.statusBar().showMessage("Ready. Run as Administrator with Npcap installed for live capture.")

    def _tab_overview(self):
        w = QtWidgets.QWidget()
        g = QtWidgets.QGridLayout(w)
        self.bw_plot = pg.PlotWidget(title="Bandwidth last 120s (KB/s)")
        self.bw_plot.showGrid(x=False, y=True, alpha=0.2)
        self.bw_plot.addLegend(offset=(10, 10))
        self.bw_up = self.bw_plot.plot(pen=pg.mkPen("#ff9f43", width=2), name="Upload", fillLevel=0, brush=(255, 159, 67, 40))
        self.bw_down = self.bw_plot.plot(pen=pg.mkPen("#58d6ff", width=2), name="Download", fillLevel=0, brush=(88, 214, 255, 40))
        self.pr_plot = pg.PlotWidget(title="Applications (packets)")
        self.pr_plot.showGrid(x=False, y=True, alpha=0.2)
        self.pr_bar = pg.BarGraphItem(x=[0], height=[0], width=0.6, brush="#3a7bff")
        self.pr_plot.addItem(self.pr_bar)
        g.addWidget(self.bw_plot, 0, 0, 1, 3)
        g.addWidget(self.pr_plot, 0, 3, 1, 2)
        self.t_ov_dom = make_table(["Top destinations", "Sent", "Recv"], [260, 80, 80])
        self.t_ov_cc = make_table(["Country", "Flows", "Traffic"], [120, 70, 90])
        self.t_ov_proc = make_table(["Top processes", "Flows", "Traffic"], [190, 70, 90])
        for i, tb in enumerate((self.t_ov_dom, self.t_ov_cc, self.t_ov_proc)):
            g.addWidget(tb, 1, i if i < 2 else 2, 1, 1 if i < 2 else 3)
        g.setRowStretch(0, 3)
        g.setRowStretch(1, 2)
        self.w_over = w
        self.tabs.addTab(w, "Overview")

    def _tab_flows(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)
        bar = QtWidgets.QHBoxLayout()
        self.flow_filter = QtWidgets.QLineEdit()
        self.flow_filter.setPlaceholderText("Filter: process, IP, domain, country, org, state ...")
        self.flow_view = QtWidgets.QComboBox()
        self.flow_view.addItems(["Active flows", "Recently closed"])
        self.flow_sort = QtWidgets.QComboBox()
        self.flow_sort.addItems(["Sort: most recent", "Sort: most data", "Sort: highest risk"])
        bar.addWidget(self.flow_filter, 1)
        bar.addWidget(self.flow_view)
        bar.addWidget(self.flow_sort)
        l.addLayout(bar)
        self.t_flow = make_table(["Process", "PID", "App", "Local", "Remote", "Domain / SNI", "Country", "Org / ASN",
                                  "Sent", "Recv", "Pkts", "Time", "State", "Risk"],
                                 [130, 55, 65, 150, 150, 210, 70, 190, 75, 75, 55, 65, 100, 50])
        l.addWidget(self.t_flow)
        self.w_flows = w
        self.tabs.addTab(w, "Flows")

    def _tab_procs(self):
        self.t_proc = make_table(["Process", "PIDs", "Flows", "Remote hosts", "Sent", "Received", "Risk"],
                                 [220, 140, 70, 110, 100, 100, 60])
        self.tabs.addTab(self.t_proc, "Processes")

    def _tab_dests(self):
        self.t_dest = make_table(["Host", "IP", "Country", "Org", "Flows", "Sent", "Received", "Risk"],
                                 [280, 140, 70, 260, 60, 90, 90, 60])
        self.tabs.addTab(self.t_dest, "Destinations")

    def _tab_tls(self):
        self.t_tls = make_table(["Time", "Client", "Server", "SNI", "JA3", "TLS", "Process"],
                                [80, 130, 130, 280, 270, 70, 150])
        self.tabs.addTab(self.t_tls, "TLS / JA3")

    def _tab_dns(self):
        self.t_dns = make_table(["Time", "Client", "Query", "Type", "Response", "RTT ms"], [80, 130, 420, 60, 380, 70])
        self.tabs.addTab(self.t_dns, "DNS")

    def _tab_packets(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)
        self.pk_filter = QtWidgets.QLineEdit()
        self.pk_filter.setPlaceholderText("Filter new packets: IP, app, port, text ...")
        l.addWidget(self.pk_filter)
        self.t_pk = make_table(["Time", "Source", "Destination", "L4", "App", "Sport", "Dport", "Len", "Info"],
                               [80, 180, 180, 55, 65, 60, 60, 60, 300])
        l.addWidget(self.t_pk)
        self.w_pk = w
        self.tabs.addTab(w, "Packets")

    def _tab_alerts(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)
        sp = QtWidgets.QSplitter(QtCore.Qt.Vertical)
        self.t_al = make_table(["Time", "Severity", "Detection", "Process", "Source", "Destination", "Detail", "MITRE ATT&CK"],
                               [75, 80, 190, 130, 140, 170, 520, 240])
        self.t_al.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.t_al.customContextMenuRequested.connect(self._alert_menu)
        self.t_al.itemSelectionChanged.connect(self._alert_select)
        self.al_detail = QtWidgets.QTextEdit()
        self.al_detail.setReadOnly(True)
        self.al_detail.setPlaceholderText("Select an alert to see what it means and what to do. Right-click to allowlist.")
        sp.addWidget(self.t_al)
        sp.addWidget(self.al_detail)
        sp.setSizes([520, 160])
        l.addWidget(sp)
        self.tabs.addTab(w, "Alerts")

    def _tab_mitre(self):
        self.t_mitre = make_table(["MITRE ATT&CK technique", "Detections"], [520, 100])
        self.tabs.addTab(self.t_mitre, "ATT&CK")

    def _tab_intel(self):
        w = QtWidgets.QWidget()
        l = QtWidgets.QVBoxLayout(w)
        bar = QtWidgets.QHBoxLayout()
        self.ioc_in = QtWidgets.QLineEdit()
        self.ioc_in.setPlaceholderText("IOC lookup: paste an IP, domain or JA3 hash and press Enter")
        self.ioc_out = QtWidgets.QLabel("")
        self.ioc_in.returnPressed.connect(lambda: self.ioc_out.setText(self.intel.lookup(self.ioc_in.text())))
        bar.addWidget(self.ioc_in)
        l.addLayout(bar)
        l.addWidget(self.ioc_out)
        self.t_feeds = make_table(["Feed", "Status"], [420, 300])
        l.addWidget(self.t_feeds)
        l.addWidget(section("Allowlist (suppressed alerts) - stored in data/allowlist.txt"))
        self.allow_lbl = QtWidgets.QLabel("")
        self.allow_lbl.setWordWrap(True)
        l.addWidget(self.allow_lbl)
        l.addStretch()
        self.tabs.addTab(w, "Threat Intel")

    # -------------------------------------------------------------- alerts UI
    def _alert_select(self):
        rows = self.t_al.selectionModel().selectedRows()
        if not rows:
            return
        a = self.t_al.item(rows[0].row(), 0).data(QtCore.Qt.UserRole)
        if a is None:
            return
        self.al_detail.setHtml(
            "<b style='color:%s'>[%s] %s</b><br><br><b>Detail:</b> %s<br><b>Process:</b> %s<br><b>Source:</b> %s &nbsp; "
            "<b>Destination:</b> %s<br><b>MITRE:</b> %s<br><br><b>What it means / what to do:</b><br>%s" % (
                SEV_COLOR.get(a.severity, "#fff"), a.severity, html.escape(a.kind), html.escape(a.detail),
                html.escape(a.proc or "-"), html.escape(a.src), html.escape(a.dst), html.escape(a.mitre),
                html.escape(ADVICE.get(a.kind, "Investigate the involved hosts and processes."))))

    def _alert_menu(self, pos):
        it = self.t_al.itemAt(pos)
        if it is None:
            return
        a = self.t_al.item(it.row(), 0).data(QtCore.Qt.UserRole)
        menu = QtWidgets.QMenu(self)
        acts = {}
        for label, val in (("Allowlist destination  %s" % a.dst, a.dst), ("Allowlist source  %s" % a.src, a.src)):
            if val:
                acts[menu.addAction(label)] = val
        chosen = menu.exec_(self.t_al.viewport().mapToGlobal(pos))
        if chosen in acts:
            self.an.allow_add(acts[chosen])
            self.statusBar().showMessage("Allowlisted %s - future alerts for it are suppressed" % acts[chosen])

    # -------------------------------------------------------------- capture
    def start(self):
        if self.sniffer or (self.worker and self.worker.isRunning()):
            return
        iface = self.cmb.currentData()
        bpf = self.bpf.text().strip() or None
        self.an.set_local_ips(local_addresses())
        self.an.live = True
        try:
            self.sniffer = AsyncSniffer(iface=iface, prn=self.an.process, store=False, filter=bpf)
            self.sniffer.start()
        except Exception as e:
            self.sniffer = None
            QtWidgets.QMessageBox.critical(self, "Capture error", str(e))
            return
        self.state = "LIVE"
        self.b_start.setEnabled(False)
        self.b_stop.setEnabled(True)
        QtCore.QTimer.singleShot(2500, self._verify)

    def _verify(self):
        if self.sniffer is not None and not getattr(self.sniffer, "running", True):
            err = getattr(self.sniffer, "exception", None)
            QtWidgets.QMessageBox.warning(
                self, "Capture did not start",
                "%s\n\nRun as Administrator and make sure Npcap is installed (https://npcap.com)." % (err or ""))
            self.stop()

    def stop(self):
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None
        self.an.live = False
        self.state = "IDLE"
        self.b_start.setEnabled(True)
        self.b_stop.setEnabled(False)

    def load_pcap(self):
        if self.worker and self.worker.isRunning():
            return
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Open capture", "", "Captures (*.pcap *.pcapng *.cap)")
        if not path:
            return
        self.stop()
        self.clear_all()
        self.an.set_local_ips(set())
        self.an.live = False
        self.state = "PCAP"
        self.worker = PcapWorker(path, self.an)
        self.worker.done.connect(self._pcap_done)
        self.worker.start()
        self.statusBar().showMessage("Analyzing %s ..." % path)

    def _pcap_done(self, n, err):
        self.state = "IDLE"
        self.statusBar().showMessage("PCAP finished: %d packets analyzed" % n + (" | error: " + err if err else ""))

    def save_pcap(self):
        ring = self.an.ring_snapshot()
        if not ring:
            QtWidgets.QMessageBox.information(self, "Save PCAP", "No packets captured yet.")
            return
        os.makedirs(REPORTS, exist_ok=True)
        path = os.path.join(REPORTS, "capture_%s.pcap" % time.strftime("%Y%m%d_%H%M%S"))
        pkts = []
        for ts, raw in ring:
            try:
                p = Ether(raw)
                p.time = ts
                pkts.append(p)
            except Exception:
                continue
        wrpcap(path, pkts)
        self.statusBar().showMessage("Saved %d packets -> %s (open in Wireshark)" % (len(pkts), path))

    def clear_all(self):
        self.an.reset()
        self.alert_idx = 0
        for t in (self.t_pk, self.t_al, self.t_flow, self.t_proc, self.t_dest, self.t_tls, self.t_dns, self.t_mitre):
            t.setRowCount(0)

    # -------------------------------------------------------------- refresh
    def refresh(self):
        if self.state != "PCAP" and time.time() - self.last_sweep > 5:
            self.last_sweep = time.time()
            self.an.sweep()
        s = self.an.snapshot()
        self.k_pkts.set("{:,}".format(s["total"]))
        self.k_bytes.set(human(s["bytes"]))
        self.k_flows.set("{:,}".format(s["active"]))
        self.k_hosts.set("{:,}".format(s["hosts"]))
        hi = s["sev"].get("Critical", 0) + s["sev"].get("High", 0)
        self.k_alerts.set(str(s["alerts"]), "#ff4d6d" if hi else "#ffd166")
        self.k_risky.set(str(s["risky"]), "#ff4d6d" if s["risky"] else "#34d399")
        self.k_ioc.set("{:,}".format(self.intel.total()))
        self.k_state.set(self.state, {"LIVE": "#34d399", "PCAP": "#ffd166"}.get(self.state, "#8aa0c2"))
        if self.state != "PCAP":
            err = (" | process map: " + self.procmap.error) if self.procmap.error else ""
            self.statusBar().showMessage("Threat intel: %s | GeoIP queue: %d%s" % (self.intel.status, len(self.enricher.pending), err))

        self.bw_up.setData(s["up"] or [0])
        self.bw_down.setData(s["down"] or [0])
        items = sorted(s["proto"].items(), key=lambda kv: kv[1], reverse=True)[:9]
        if items:
            self.pr_bar.setOpts(x=list(range(len(items))), height=[v for _, v in items], width=0.6)
            self.pr_plot.getAxis("bottom").setTicks([[(i, k) for i, (k, _) in enumerate(items)]])

        pk = self.an.drain_packets()[-300:]
        ft = self.pk_filter.text().strip().lower()
        if pk:
            self.t_pk.setUpdatesEnabled(False)
            for ts, src, dst, l4, app, sp, dp, ln, info in pk:
                vals = [tstr(ts), src, dst, l4, app, sp or "", dp or "", ln, info]
                if ft and ft not in " ".join(str(x) for x in vals).lower():
                    continue
                self.t_pk.insertRow(0)
                put(self.t_pk, 0, vals, row_color=APP_COLOR.get(app))
            while self.t_pk.rowCount() > 1500:
                self.t_pk.removeRow(self.t_pk.rowCount() - 1)
            self.t_pk.setUpdatesEnabled(True)

        new = self.an.get_alerts(self.alert_idx)
        for a in new:
            self.t_al.insertRow(0)
            put(self.t_al, 0, [tstr(a.ts), a.severity, a.kind, a.proc or "-", a.src, a.dst, a.detail, a.mitre],
                row_color=SEV_COLOR.get(a.severity))
            self.t_al.item(0, 0).setData(QtCore.Qt.UserRole, a)
        self.alert_idx += len(new)

        cur = self.tabs.currentWidget()
        if cur is self.w_over:
            self._fill_overview(s)
        elif cur is self.w_flows:
            self._fill_flows(s)
        elif cur is self.t_proc:
            rows = sorted(s["procs"].items(), key=lambda kv: kv[1]["out"] + kv[1]["inn"], reverse=True)
            fill(self.t_proc, [[n, ",".join(str(p) for p in sorted(p["pids"]) if p)[:30] or "-", p["flows"], len(p["remotes"]),
                                human(p["out"]), human(p["inn"]), p["risk"]] for n, p in rows],
                 lambda v: ({6: risk_color(v[6])}, None))
        elif cur is self.t_dest:
            rows = sorted(s["dests"], key=lambda d: d["out"] + d["inn"], reverse=True)[:500]
            fill(self.t_dest, [[d["host"], d["ip"], d["cc"], d["org"], d["flows"], human(d["out"]), human(d["inn"]), d["risk"]]
                               for d in rows], lambda v: ({7: risk_color(v[7])}, None))
        elif cur is self.t_tls:
            fill(self.t_tls, [[tstr(a), b, c, d or "-", e, f, g] for a, b, c, d, e, f, g in s["tls"]])
        elif cur is self.t_dns:
            fill(self.t_dns, [[tstr(a), b, c, d, e or "(waiting)", ("%.0f" % f) if f is not None else ""] for a, b, c, d, e, f in s["dns"]],
                 lambda v: ({4: "#ff9f43"} if v[4] == "NXDOMAIN" else {}, None))
        elif cur is self.t_mitre:
            fill(self.t_mitre, sorted(([k, v] for k, v in s["mitre"].items()), key=lambda x: -x[1]))
        elif cur is self.tabs.widget(self.tabs.count() - 1):
            fill(self.t_feeds, [[k, v] for k, v in self.intel.feed_status.items()],
                 lambda v: ({1: "#34d399" if v[1].startswith("OK") else "#ff9f43"}, None))
            self.allow_lbl.setText(", ".join(sorted(self.an.allow)) or "(empty)")

    def _fill_overview(self, s):
        dests = sorted(s["dests"], key=lambda d: d["out"] + d["inn"], reverse=True)[:8]
        fill(self.t_ov_dom, [[d["host"], human(d["out"]), human(d["inn"])] for d in dests])
        cc = sorted(s["countries"].items(), key=lambda kv: kv[1]["bytes"], reverse=True)[:8]
        fill(self.t_ov_cc, [[k, v["flows"], human(v["bytes"])] for k, v in cc])
        pr = sorted(s["procs"].items(), key=lambda kv: kv[1]["out"] + kv[1]["inn"], reverse=True)[:8]
        fill(self.t_ov_proc, [[k, v["flows"], human(v["out"] + v["inn"])] for k, v in pr])

    def _fill_flows(self, s):
        rows = s["flows"] if self.flow_view.currentIndex() == 0 else s["closed"]
        sort = self.flow_sort.currentIndex()
        key = (lambda r: -r["last"]) if sort == 0 else ((lambda r: -(r["out"] + r["inn"])) if sort == 1 else (lambda r: -r["risk"]))
        rows = sorted(rows, key=key)
        ft = self.flow_filter.text().strip().lower()
        out = []
        for r in rows:
            vals = [r["proc"], r["pid"] or "-", r["app"], r["local"], r["remote"], r["domain"] or "-", r["cc"],
                    (r["org"] + (" " + r["asn"] if r["asn"] else "")).strip() or "-", human(r["out"]), human(r["inn"]),
                    r["pkts"], dur(r["dur"]), r["state"], r["risk"]]
            if ft and ft not in " ".join(str(x) for x in vals).lower():
                continue
            out.append(vals)
            if len(out) >= 600:
                break
        fill(self.t_flow, out, lambda v: ({13: risk_color(v[13])}, "#ffb3c0" if v[13] >= 70 else None))

    # --------------------------------------------------------------- export
    def export(self):
        os.makedirs(REPORTS, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        s = self.an.snapshot()
        alerts = self.an.get_alerts(0)
        data = {
            "generated": time.strftime("%Y-%m-%d %H:%M:%S"), "packets": s["total"], "bytes": s["bytes"],
            "applications": s["proto"], "severity_counts": s["sev"], "mitre": s["mitre"],
            "alerts": [dict(time=tstr(a.ts), severity=a.severity, detection=a.kind, process=a.proc, src=a.src, dst=a.dst,
                            detail=a.detail, mitre=a.mitre, advice=ADVICE.get(a.kind, "")) for a in alerts],
            "top_destinations": sorted(s["dests"], key=lambda d: d["out"] + d["inn"], reverse=True)[:25],
            "processes": {k: dict(flows=v["flows"], remotes=len(v["remotes"]), sent=v["out"], received=v["inn"], risk=v["risk"])
                          for k, v in s["procs"].items()},
        }
        jp = os.path.join(REPORTS, "nta_report_%s.json" % stamp)
        hp = os.path.join(REPORTS, "nta_report_%s.html" % stamp)
        cp = os.path.join(REPORTS, "nta_flows_%s.csv" % stamp)
        with open(jp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=list)
        with open(cp, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["process", "pid", "app", "local", "remote", "domain", "country", "org", "sent", "received", "state", "risk"])
            for r in s["flows"] + s["closed"]:
                w.writerow([r["proc"], r["pid"], r["app"], r["local"], r["remote"], r["domain"], r["cc"], r["org"],
                            r["out"], r["inn"], r["state"], r["risk"]])
        arows = "".join(
            "<tr><td>%s</td><td style='color:%s'><b>%s</b></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            % (a["time"], SEV_COLOR.get(a["severity"], "#fff"), a["severity"], html.escape(a["detection"]),
               html.escape(a["process"] or "-"), html.escape(a["src"]), html.escape(a["dst"]), html.escape(a["detail"]),
               html.escape(a["mitre"])) for a in data["alerts"])
        drows = "".join("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            html.escape(d["host"]), d["ip"], d["cc"], html.escape(d["org"]), human(d["out"]), human(d["inn"]))
            for d in data["top_destinations"])
        doc = ("<html><head><meta charset='utf-8'><title>NTA Report</title><style>body{background:#0b0f19;color:#e6edf3;"
               "font-family:Segoe UI,Arial;padding:30px}table{border-collapse:collapse;width:100%%;margin-bottom:30px}"
               "td,th{border:1px solid #2b3a55;padding:7px;text-align:left;font-size:13px}th{background:#16213a}h1,h2{color:#58d6ff}"
               "</style></head><body><h1>Network Traffic Analysis Report</h1><p>Generated %s | %d packets | %s | %d alerts</p>"
               "<h2>Alerts</h2><table><tr><th>Time</th><th>Severity</th><th>Detection</th><th>Process</th><th>Source</th>"
               "<th>Destination</th><th>Detail</th><th>MITRE</th></tr>%s</table><h2>Top destinations</h2><table><tr><th>Host</th>"
               "<th>IP</th><th>Country</th><th>Org</th><th>Sent</th><th>Received</th></tr>%s</table></body></html>"
               % (data["generated"], s["total"], human(s["bytes"]), len(alerts), arows, drows))
        with open(hp, "w", encoding="utf-8") as f:
            f.write(doc)
        self.statusBar().showMessage("Report saved: " + hp)
        QtWidgets.QMessageBox.information(self, "Report exported", "Saved:\n%s\n%s\n%s" % (hp, jp, cp))

    def closeEvent(self, e):
        self.stop()
        self.enricher.save()
        e.accept()


def main():
    QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
    app = QtWidgets.QApplication(sys.argv)
    app.setStyleSheet(QSS)
    w = MainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()