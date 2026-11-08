"""
gui.py - PyQt5 analyst console for the IR Triage Toolkit.
"""
import csv
import ctypes
import getpass
import json
import os
import subprocess
import sys
import time
import traceback

from PyQt5.QtCore import (QAbstractTableModel, QModelIndex, QRectF, QSortFilterProxyModel, Qt, QThread, QTimer, pyqtSignal)
from PyQt5.QtGui import QBrush, QColor, QFont, QLinearGradient, QPainter, QPen
from PyQt5.QtWidgets import (QApplication, QCheckBox, QComboBox, QFileDialog, QFrame, QGraphicsDropShadowEffect,
                             QGridLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                             QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSpinBox,
                             QSplitter, QTableView, QTabWidget, QTreeWidget, QTreeWidgetItem, QTreeWidgetItemIterator,
                             QVBoxLayout, QWidget)

import analysis as A
import collectors as C
import engine
import report

SEV_COLORS = {"Critical": "#ff3b5c", "High": "#ff8a3d", "Medium": "#f5c542", "Low": "#4cc9f0", "Info": "#8892a6"}
SEV_RANK = A.SEV_RANK
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION = "1.1"

COLUMNS = {
    "findings": ["Severity", "Score", "Category", "Title", "Entity", "MITRE", "Technique", "Time", "Detail"],
    "processes": ["Severity", "PID", "PPID", "Name", "Parent", "User", "Path", "CmdLine", "Started", "Signature", "Signer", "SHA256", "New", "Flags"],
    "network": ["Severity", "Proto", "Local", "LPort", "Remote", "RPort", "Hostname", "State", "PID", "Process", "Scope", "Signature", "Path", "New", "Flags"],
    "persistence": ["Severity", "Type", "Name", "Location", "Value", "Target", "Signature", "Signer", "Context", "Modified", "New", "Flags"],
    "events": ["Severity", "Time", "Log", "EventID", "Provider", "Detail", "Message", "Flags"],
    "files": ["Severity", "Kind", "Name", "Path", "Size", "Created", "Modified", "Signature", "SHA256", "New", "Flags"],
    "artifacts": ["Severity", "Category", "Name", "Detail", "Time", "New", "Flags"],
    "timeline": ["Time", "Severity", "Source", "Event", "Summary"],
    "iocs": ["Severity", "Type", "Value", "Count", "Context", "Sources", "VT"],
}
TABS = [("Findings", "findings"), ("Processes", "processes"), ("Network", "network"), ("Persistence", "persistence"),
        ("Event Logs", "events"), ("Files && Execution", "files"), ("System Artifacts", "artifacts"),
        ("Timeline", "timeline"), ("IOCs", "iocs")]

STYLE = """
QWidget{background:#0b0f19;color:#e6edf7;font-family:'Segoe UI';font-size:10pt}
QLabel{background:transparent}
QFrame#header{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #151d36,stop:1 #1d1a3d);border:1px solid #263149;border-radius:14px}
QFrame#card{background:qlineargradient(x1:0,y1:0,x2:0,y2:1,stop:0 #1a2236,stop:1 #111726);border:1px solid #263149;border-radius:14px}
QTabWidget::pane{border:1px solid #263149;border-radius:10px;top:-1px}
QTabBar::tab{background:#121827;padding:9px 18px;margin-right:3px;border-top-left-radius:9px;border-top-right-radius:9px;color:#9fb0d0}
QTabBar::tab:selected{background:#1f2a48;color:#ffffff;font-weight:600}
QTableView{background:#0f1524;alternate-background-color:#121a2c;gridline-color:#1c2438;selection-background-color:#2b3a67;border:none}
QHeaderView::section{background:#161e33;color:#9fb0d0;padding:7px;border:0;border-right:1px solid #1c2438}
QLineEdit,QSpinBox,QComboBox,QPlainTextEdit,QListWidget{background:#0f1524;border:1px solid #263149;border-radius:8px;padding:5px}
QPushButton{background:#1f2a48;border:1px solid #2f3d66;border-radius:9px;padding:8px 16px;font-weight:600}
QPushButton:hover{background:#2a3860}
QPushButton:disabled{color:#5b6580;background:#141b2e}
QPushButton#primary{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #7b61ff,stop:1 #4cc9f0);color:#0b0f19;border:none}
QPushButton#danger{background:#5a1f2e;border-color:#8a2f45}
QProgressBar{background:#121827;border:1px solid #263149;border-radius:8px;text-align:center;height:18px}
QProgressBar::chunk{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #7b61ff,stop:1 #4cc9f0);border-radius:7px}
QCheckBox{spacing:7px}
QSplitter::handle{background:#1c2438}
"""


def shadow(widget, blur=30, dy=8):
    ef = QGraphicsDropShadowEffect()
    ef.setBlurRadius(blur)
    ef.setOffset(0, dy)
    ef.setColor(QColor(0, 0, 0, 170))
    widget.setGraphicsEffect(ef)


# --------------------------------------------------------------------------- table infrastructure
class DictModel(QAbstractTableModel):
    def __init__(self, columns):
        super().__init__()
        self.columns, self.rows, self.blobs = columns, [], []

    def set_rows(self, rows):
        self.beginResetModel()
        self.rows = rows
        self.blobs = [" ".join(str(r.get(c, "")) for c in self.columns).lower() for r in rows]
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.columns)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self.columns[section]
        return None

    def data(self, idx, role=Qt.DisplayRole):
        if not idx.isValid():
            return None
        row, col = self.rows[idx.row()], self.columns[idx.column()]
        val = row.get(col, "")
        sev = row.get("Severity", "")
        if role == Qt.DisplayRole:
            s = "" if val is None else str(val)
            return s if len(s) <= 300 else s[:300] + "..."
        if role == Qt.ToolTipRole:
            return str(val)[:1200]
        if role == Qt.BackgroundRole:
            if col == "Severity" and sev in SEV_COLORS:
                return QColor(SEV_COLORS[sev])
            if sev in ("Critical", "High"):
                c = QColor(SEV_COLORS[sev])
                c.setAlpha(30)
                return QBrush(c)
        if role == Qt.ForegroundRole and col == "Severity" and sev in SEV_COLORS:
            return QColor("#0b0f19")
        if role == Qt.FontRole and col == "Severity":
            f = QFont()
            f.setBold(True)
            return f
        if role == Qt.TextAlignmentRole and col == "Severity":
            return Qt.AlignCenter
        return None


class Proxy(QSortFilterProxyModel):
    def __init__(self):
        super().__init__()
        self.text, self.minrank = "", -1

    def set_filter(self, text, minrank):
        self.text, self.minrank = text.lower().strip(), minrank
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):
        m = self.sourceModel()
        if self.minrank >= 0 and SEV_RANK.get(m.rows[row].get("Severity", ""), -1) < self.minrank:
            return False
        return (not self.text) or (self.text in m.blobs[row])

    def lessThan(self, a, b):
        m = self.sourceModel()
        col = m.columns[a.column()]
        va, vb = m.rows[a.row()].get(col, ""), m.rows[b.row()].get(col, "")
        if col == "Severity":
            return SEV_RANK.get(va, -1) < SEV_RANK.get(vb, -1)
        if isinstance(va, (int, float)) and isinstance(vb, (int, float)):
            return va < vb
        return str(va).lower() < str(vb).lower()


class TablePage(QWidget):
    def __init__(self, key, default_sort=None):
        super().__init__()
        self.key, self.default_sort = key, default_sort
        self.model = DictModel(COLUMNS[key])
        self.proxy = Proxy()
        self.proxy.setSourceModel(self.model)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Filter rows (searches every column)...")
        self.sev = QComboBox()
        self.sev.addItems(["All severities", "Low and above", "Medium and above", "High and above", "Critical only"])
        self.count = QLabel("0 rows")
        self.btn_csv = QPushButton("Export CSV")
        top = QHBoxLayout()
        for w in (self.search, self.sev, self.count, self.btn_csv):
            top.addWidget(w)
        top.setStretch(0, 1)

        self.view = QTableView()
        self.view.setModel(self.proxy)
        self.view.setSortingEnabled(True)
        self.view.setAlternatingRowColors(True)
        self.view.setTextElideMode(Qt.ElideMiddle)
        self.view.setSelectionBehavior(QTableView.SelectRows)
        self.view.setEditTriggers(QTableView.NoEditTriggers)
        self.view.verticalHeader().setVisible(False)
        self.view.verticalHeader().setDefaultSectionSize(26)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.view.customContextMenuRequested.connect(self.menu)

        self.detail = QPlainTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setPlaceholderText("Select a row to see every field...")
        split = QSplitter(Qt.Vertical)
        split.addWidget(self.view)
        split.addWidget(self.detail)
        split.setSizes([620, 160])

        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(split)

        self.search.textChanged.connect(self.apply_filter)
        self.sev.currentIndexChanged.connect(self.apply_filter)
        self.btn_csv.clicked.connect(self.export_csv)
        self.view.selectionModel().currentRowChanged.connect(self.on_row)

    def set_rows(self, rows):
        self.model.set_rows(rows)
        self.view.resizeColumnsToContents()
        for c in range(self.model.columnCount()):
            self.view.setColumnWidth(c, max(60, min(self.view.columnWidth(c), 360)))
        self.apply_filter()
        if self.default_sort and self.default_sort[0] in self.model.columns:
            self.view.sortByColumn(self.model.columns.index(self.default_sort[0]), self.default_sort[1])

    def apply_filter(self):
        rank = {0: -1, 1: 1, 2: 2, 3: 3, 4: 4}[self.sev.currentIndex()]
        self.proxy.set_filter(self.search.text(), rank)
        self.count.setText("%d / %d rows" % (self.proxy.rowCount(), len(self.model.rows)))

    def current_row(self):
        idx = self.view.currentIndex()
        if not idx.isValid():
            return None
        return self.model.rows[self.proxy.mapToSource(idx).row()]

    def on_row(self, *_):
        r = self.current_row()
        if r:
            self.detail.setPlainText("\n".join("%-14s %s" % (k + ":", v) for k, v in r.items() if not k.startswith("_")))

    def menu(self, pos):
        idx = self.view.indexAt(pos)
        if not idx.isValid():
            return
        m = QMenu(self)
        src = self.proxy.mapToSource(idx)
        row, col = self.model.rows[src.row()], self.model.columns[src.column()]
        a1, a2, a3 = m.addAction("Copy cell"), m.addAction("Copy row as JSON"), m.addAction("Filter by this value")
        m.addSeparator()
        allow = {}
        for label, kind, val in (("Allowlist this name", "names", row.get("Name") or row.get("Process")),
                                 ("Allowlist this path", "paths", row.get("Path") or row.get("Target")),
                                 ("Allowlist this hash", "hashes", row.get("SHA256")),
                                 ("Allowlist this finding title", "titles", row.get("Title"))):
            if val:
                allow[m.addAction(label)] = (kind, str(val))
        act = m.exec_(self.view.viewport().mapToGlobal(pos))
        if act in allow:
            A.add_allow(*allow[act])
            QMessageBox.information(self, "Allowlist updated", "Saved to allowlist.json. It is applied on the next triage run.")
            return
        if act == a1:
            QApplication.clipboard().setText(str(row.get(col, "")))
        elif act == a2:
            QApplication.clipboard().setText(json.dumps(row, indent=2, default=str))
        elif act == a3:
            self.search.setText(str(row.get(col, "")))

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export table", os.path.join(BASE_DIR, self.key + ".csv"), "CSV (*.csv)")
        if path:
            report.write_csv(path, self.model.rows)


# --------------------------------------------------------------------------- custom widgets
class Gauge(QWidget):
    def __init__(self):
        super().__init__()
        self.value, self.label = 0, "NO DATA"
        self.setMinimumSize(280, 250)

    def set_value(self, v, label):
        self.value, self.label = v, label
        self.update()

    def color(self):
        v = self.value
        return QColor(SEV_COLORS["Critical"] if v >= 75 else SEV_COLORS["High"] if v >= 50 else
                      SEV_COLORS["Medium"] if v >= 25 else SEV_COLORS["Low"])

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        s = min(self.width() - 50, self.height() - 60)
        rect = QRectF((self.width() - s) / 2, 24, s, s)
        pen = QPen(QColor("#1c2438"), 20)
        pen.setCapStyle(Qt.RoundCap)
        p.setPen(pen)
        p.drawArc(rect, 225 * 16, -270 * 16)
        span = int(-270 * 16 * self.value / 100)
        glow = QColor(self.color())
        glow.setAlpha(60)
        p.setPen(QPen(glow, 32, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(rect, 225 * 16, span)
        p.setPen(QPen(self.color(), 20, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(rect, 225 * 16, span)
        p.setPen(QColor("#ffffff"))
        f = QFont("Segoe UI", 34, QFont.Bold)
        p.setFont(f)
        p.drawText(rect, Qt.AlignCenter, str(self.value))
        p.setFont(QFont("Segoe UI", 11, QFont.Bold))
        p.setPen(self.color())
        p.drawText(QRectF(rect.left(), rect.center().y() + 30, rect.width(), 30), Qt.AlignCenter, self.label)


class BarChart(QWidget):
    def __init__(self):
        super().__init__()
        self.items = []
        self.setMinimumHeight(250)

    def set_items(self, items):
        self.items = items
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        if not self.items:
            p.setPen(QColor("#8892a6"))
            p.drawText(self.rect(), Qt.AlignCenter, "No ATT&CK techniques observed yet")
            return
        n = len(self.items)
        rh = min(34.0, (self.height() - 10) / n)
        mx = max(c for _, _, c in self.items)
        left, right = int(min(270, self.width() * 0.55)), 50
        for i, (tid, name, cnt) in enumerate(self.items):
            y = 6 + i * rh
            p.setPen(QColor("#9fb0d0"))
            p.setFont(QFont("Segoe UI", 9))
            p.drawText(QRectF(0, y, left - 10, rh), Qt.AlignVCenter | Qt.AlignRight, "%s  %s" % (tid, name[:26]))
            w = (self.width() - left - right) * cnt / mx
            g = QLinearGradient(left, 0, left + max(w, 1), 0)
            g.setColorAt(0, QColor("#7b61ff"))
            g.setColorAt(1, QColor("#4cc9f0"))
            p.setPen(Qt.NoPen)
            p.setBrush(QBrush(g))
            p.drawRoundedRect(QRectF(left, y + rh * 0.18, max(w, 4), rh * 0.64), 5, 5)
            p.setPen(QColor("#ffffff"))
            p.drawText(QRectF(left + w + 8, y, 40, rh), Qt.AlignVCenter, str(cnt))


class ProcessTree(QWidget):
    HEAD = ["Process", "PID", "User", "Signature", "Severity", "Command line"]

    def __init__(self):
        super().__init__()
        self.matches, self.mi = [], -1
        self.tree = QTreeWidget()
        self.tree.setColumnCount(len(self.HEAD))
        self.tree.setHeaderLabels(self.HEAD)
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setStyleSheet("QTreeWidget{background:#0f1524;alternate-background-color:#121a2c;border:none}"
                                "QTreeWidget::item:selected{background:#2b3a67}")
        self.search = QLineEdit()
        self.search.setPlaceholderText("Find process by name / PID / command line, press Enter (again for next match)...")
        b1, b2, b3 = QPushButton("Expand all"), QPushButton("Collapse all"), QPushButton("Show flagged branches")
        top = QHBoxLayout()
        for w in (self.search, b1, b2, b3):
            top.addWidget(w)
        top.setStretch(0, 1)
        lay = QVBoxLayout(self)
        lay.addLayout(top)
        lay.addWidget(self.tree)
        b1.clicked.connect(self.tree.expandAll)
        b2.clicked.connect(self.tree.collapseAll)
        b3.clicked.connect(self.show_flagged)
        self.search.returnPressed.connect(self.find)

    def set_rows(self, rows):
        self.tree.clear()
        by_pid = {r["PID"]: r for r in rows}
        kids, roots = {}, []
        for r in rows:
            p = r["PPID"]
            if p == r["PID"] or p not in by_pid or not r.get("Parent"):
                roots.append(r)
            else:
                kids.setdefault(p, []).append(r)
        seen = set()
        self.flagged = []

        def build(r, parent):
            if r["PID"] in seen:
                return
            seen.add(r["PID"])
            it = QTreeWidgetItem([r["Name"] or "(unknown)", str(r["PID"]), r["User"], r.get("Signature", ""),
                                  r.get("Severity", ""), (r["CmdLine"] or r["Path"])[:240]])
            (parent or self.tree.invisibleRootItem()).addChild(it)
            sev = r.get("Severity", "")
            if sev in SEV_COLORS:
                col = QColor(SEV_COLORS[sev])
                if SEV_RANK[sev] >= 2:
                    for c in range(len(self.HEAD)):
                        it.setForeground(c, QBrush(col))
                    self.flagged.append(it)
                it.setBackground(4, col)
                it.setForeground(4, QBrush(QColor("#0b0f19")))
            for k in sorted(kids.get(r["PID"], []), key=lambda x: x["PID"]):
                build(k, it)

        for r in sorted(roots, key=lambda x: x["PID"]):
            build(r, None)
        for i, w in enumerate((260, 70, 170, 90, 80)):
            self.tree.setColumnWidth(i, w)
        self.show_flagged()

    def show_flagged(self):
        self.tree.collapseAll()
        for it in self.flagged:
            p = it.parent()
            while p:
                p.setExpanded(True)
                p = p.parent()

    def find(self):
        text = self.search.text().lower().strip()
        if not text:
            return
        if not self.matches or self.search.property("last") != text:
            self.matches, self.mi = [], -1
            it = QTreeWidgetItemIterator(self.tree)
            while it.value():
                item = it.value()
                if text in " ".join(item.text(c) for c in range(len(self.HEAD))).lower():
                    self.matches.append(item)
                it += 1
            self.search.setProperty("last", text)
        if self.matches:
            self.mi = (self.mi + 1) % len(self.matches)
            item = self.matches[self.mi]
            p = item.parent()
            while p:
                p.setExpanded(True)
                p = p.parent()
            self.tree.setCurrentItem(item)
            self.tree.scrollToItem(item)


def make_card(title=""):
    f = QFrame()
    f.setObjectName("card")
    shadow(f)
    lay = QVBoxLayout(f)
    if title:
        t = QLabel(title)
        t.setStyleSheet("color:#9fb0d0;font-weight:700;letter-spacing:1px")
        lay.addWidget(t)
    return f, lay


class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        grid = QGridLayout(self)
        grid.setSpacing(16)

        gcard, glay = make_card("OVERALL RISK")
        self.gauge = Gauge()
        glay.addWidget(self.gauge)
        grid.addWidget(gcard, 0, 0, 2, 1)

        row = QHBoxLayout()
        self.sev_labels = {}
        for s in ("Critical", "High", "Medium", "Low"):
            c, lay = make_card(s.upper())
            num = QLabel("-")
            num.setAlignment(Qt.AlignCenter)
            num.setStyleSheet("font-size:44px;font-weight:800;color:%s" % SEV_COLORS[s])
            lay.addWidget(num)
            self.sev_labels[s] = num
            row.addWidget(c)
        grid.addLayout(row, 0, 1)

        hcard, hlay = make_card("HOST & COLLECTION")
        self.host = QLabel("Run a triage to populate host details.")
        self.host.setTextFormat(Qt.RichText)
        self.host.setWordWrap(True)
        hlay.addWidget(self.host)
        grid.addWidget(hcard, 1, 1)

        mcard, mlay = make_card("TOP MITRE ATT&CK TECHNIQUES")
        self.chart = BarChart()
        mlay.addWidget(self.chart)
        grid.addWidget(mcard, 2, 0, 1, 1)

        fcard, flay = make_card("TOP FINDINGS")
        self.top = QListWidget()
        flay.addWidget(self.top)
        grid.addWidget(fcard, 2, 1)
        grid.setColumnStretch(0, 2)
        grid.setColumnStretch(1, 3)
        grid.setRowStretch(2, 1)

    def update_data(self, data):
        s, m = data["summary"], data["meta"]
        self.gauge.set_value(s["score"], s["label"])
        for k, lbl in self.sev_labels.items():
            lbl.setText(str(s["counts"][k]))
        warn = "".join("<div style='color:#f5c542'>&#9888; %s</div>" % w for w in m.get("Warnings", []))
        self.host.setText(
            "<table cellpadding='3'>"
            "<tr><td style='color:#8892a6'>Host</td><td><b>%s</b></td><td style='color:#8892a6'>Analyst</td><td>%s</td></tr>"
            "<tr><td style='color:#8892a6'>OS</td><td>%s</td><td style='color:#8892a6'>Admin</td><td>%s</td></tr>"
            "<tr><td style='color:#8892a6'>IPs</td><td>%s</td><td style='color:#8892a6'>Boot</td><td>%s</td></tr>"
            "<tr><td style='color:#8892a6'>Records</td><td colspan='3'>%d processes, %d connections, %d persistence, %d events, %d files, %d IOCs</td></tr>"
            "<tr><td style='color:#8892a6'>Duration</td><td>%ss</td><td style='color:#8892a6'>Baseline</td><td>%s</td></tr></table>%s" % (
                m["Hostname"], m["Analyst"], m["OS"], "Yes" if m["Admin"] else "No", m["IPAddresses"], m["BootTime"],
                len(data["processes"]), len(data["network"]), len(data["persistence"]), len(data["events"]),
                len(data["files"]), len(data["iocs"]), m.get("DurationSeconds", "?"), m.get("Baseline", "none"), warn))
        self.chart.set_items(s["top_mitre"][:8])
        self.top.clear()
        for f in data["findings"][:25]:
            it = QListWidgetItem("[%s]  %s   -   %s" % (f["Severity"], f["Title"], f["Entity"]))
            it.setForeground(QColor(SEV_COLORS[f["Severity"]]))
            self.top.addItem(it)


# --------------------------------------------------------------------------- workers
class TriageWorker(QThread):
    progress = pyqtSignal(int, str)
    done = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, opts):
        super().__init__()
        self.opts, self._cancel = opts, False

    def cancel(self):
        self._cancel = True

    def run(self):
        try:
            self.done.emit(engine.run_triage(self.opts, lambda p, m: self.progress.emit(p, m), lambda: self._cancel))
        except engine.Cancelled:
            self.failed.emit("Cancelled by analyst.")
        except Exception:
            self.failed.emit(traceback.format_exc())


class VTWorker(QThread):
    progress = pyqtSignal(int, str)
    finished_all = pyqtSignal()

    def __init__(self, iocs, key):
        super().__init__()
        self.iocs, self.key = iocs, key

    def run(self):
        for i, ioc in enumerate(self.iocs):
            self.progress.emit(int(100 * i / max(1, len(self.iocs))), "VirusTotal: %s (%d/%d)" % (ioc["Value"][:48], i + 1, len(self.iocs)))
            text, mal = A.vt_lookup(ioc, self.key)
            ioc["VT"] = text
            if mal >= 5:
                ioc["Severity"] = "Critical"
            elif mal >= 1 and A.SEV_RANK[ioc["Severity"]] < 3:
                ioc["Severity"] = "High"
            if i < len(self.iocs) - 1:
                time.sleep(15.5)  # free API tier: 4 requests / minute
        self.finished_all.emit()


# --------------------------------------------------------------------------- main window
class MainWindow(QMainWindow):
    def __init__(self, auto=False):
        super().__init__()
        self.auto = auto
        self.setWindowTitle("IR Triage Toolkit v%s  |  Project 09  |  Blue Team" % VERSION)
        self.resize(1520, 920)
        self.data, self.worker, self.vt = None, None, None

        root = QWidget()
        self.setCentralWidget(root)
        lay = QVBoxLayout(root)

        # header
        header = QFrame()
        header.setObjectName("header")
        shadow(header, 24, 6)
        hl = QHBoxLayout(header)
        title = QLabel("<span style='font-size:22pt;font-weight:800'>IR TRIAGE TOOLKIT</span> <span style='font-size:11pt;color:#4cc9f0'>v1.1</span><br>"
                       "<span style='color:#9fb0d0'>Live volatile-artifact collection &middot; timeline &middot; IOC extraction &middot; MITRE ATT&amp;CK</span>")
        hl.addWidget(title, 1)
        admin = C.is_admin()
        self.badge = QLabel("\u25cf ADMINISTRATOR" if admin else "\u25cf STANDARD USER (limited coverage)")
        self.badge.setStyleSheet("font-weight:700;color:%s" % ("#3ddc97" if admin else "#f5c542"))
        hl.addWidget(self.badge)
        if not admin:
            b = QPushButton("Relaunch as Admin")
            b.clicked.connect(self.relaunch_admin)
            hl.addWidget(b)
        lay.addWidget(header)

        # controls
        ctl = QHBoxLayout()
        self.analyst = QLineEdit(getpass.getuser())
        self.analyst.setFixedWidth(160)
        self.hours, self.days = QSpinBox(), QSpinBox()
        self.hours.setRange(1, 720)
        self.hours.setValue(24)
        self.days.setRange(1, 90)
        self.days.setValue(7)
        self.chk_sig = QCheckBox("Verify signatures")
        self.chk_hash = QCheckBox("Hash dropped files")
        self.chk_evt = QCheckBox("Event logs")
        for c in (self.chk_sig, self.chk_hash, self.chk_evt):
            c.setChecked(True)
        self.btn_start = QPushButton("START TRIAGE")
        self.btn_start.setObjectName("primary")
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setObjectName("danger")
        self.btn_cancel.setEnabled(False)
        self.btn_export = QPushButton("Export Case")
        self.btn_export.setEnabled(False)
        self.btn_vt = QPushButton("VirusTotal Enrich")
        self.btn_vt.setEnabled(False)
        self.btn_base = QPushButton("Save Baseline")
        self.btn_base.setEnabled(False)
        self.btn_shots = QPushButton("Save Screenshots")
        self.btn_shots.setEnabled(False)
        for w in (QLabel("Analyst"), self.analyst, QLabel("Event window (h)"), self.hours, QLabel("File window (days)"), self.days,
                  self.chk_sig, self.chk_hash, self.chk_evt):
            ctl.addWidget(w)
        ctl.addStretch(1)
        for w in (self.btn_start, self.btn_cancel, self.btn_export, self.btn_vt, self.btn_base, self.btn_shots):
            ctl.addWidget(w)
        lay.addLayout(ctl)

        pl = QHBoxLayout()
        self.bar = QProgressBar()
        self.status = QLabel("Ready. Press START TRIAGE to collect live artifacts from this machine.")
        pl.addWidget(self.bar, 2)
        pl.addWidget(self.status, 3)
        lay.addLayout(pl)

        # tabs
        self.tabs = QTabWidget()
        self.dash = Dashboard()
        self.tabs.addTab(self.dash, "Dashboard")
        self.pages = {}
        sorts = {"findings": ("Severity", Qt.DescendingOrder), "processes": ("Severity", Qt.DescendingOrder),
                 "network": ("Severity", Qt.DescendingOrder), "persistence": ("Severity", Qt.DescendingOrder),
                 "events": ("Time", Qt.DescendingOrder), "files": ("Modified", Qt.DescendingOrder),
                 "artifacts": ("Severity", Qt.DescendingOrder), "timeline": ("Time", Qt.DescendingOrder),
                 "iocs": ("Severity", Qt.DescendingOrder)}
        for label, key in TABS:
            pg = TablePage(key, sorts[key])
            self.pages[key] = pg
            self.tabs.addTab(pg, label)
        self.tree_page = ProcessTree()
        self.tabs.insertTab(3, self.tree_page, "Process Tree")
        lay.addWidget(self.tabs, 1)

        self.btn_start.clicked.connect(self.start)
        self.btn_cancel.clicked.connect(lambda: self.worker and self.worker.cancel())
        self.btn_export.clicked.connect(self.export_case)
        self.btn_vt.clicked.connect(self.vt_enrich)
        self.btn_base.clicked.connect(self.save_baseline)
        self.btn_shots.clicked.connect(self.save_shots)
        if not auto:
            QTimer.singleShot(600, self.ask_admin)
        else:
            QTimer.singleShot(900, self.start)

    def ask_admin(self):
        if C.is_admin():
            return
        r = QMessageBox.question(self, "Administrator recommended",
                                 "Without Administrator the Security log, Prefetch and Defender exclusions are hidden.\n\nRelaunch as Administrator now?",
                                 QMessageBox.Yes | QMessageBox.No)
        if r == QMessageBox.Yes:
            self.relaunch_admin()

    def save_shots(self, quiet=False):
        """Capture the README screenshots from the live window into docs/screenshots."""
        out = os.path.join(BASE_DIR, "docs", "screenshots")
        os.makedirs(out, exist_ok=True)
        plan = [("dashboard", 0), ("findings", self.tabs.indexOf(self.pages["findings"])),
                ("process-tree", self.tabs.indexOf(self.tree_page)), ("timeline", self.tabs.indexOf(self.pages["timeline"]))]
        for name, idx in plan:
            self.tabs.setCurrentIndex(idx)
            QApplication.processEvents()
            self.repaint()
            QApplication.processEvents()
            self.grab().save(os.path.join(out, name + ".png"))
        self.tabs.setCurrentIndex(0)
        if not quiet:
            QMessageBox.information(self, "Screenshots saved", "Saved dashboard, findings, process-tree and timeline PNGs to:\n%s" % out)
        return out

    def auto_finish(self):
        print("Screenshots saved to:", self.save_shots(quiet=True))
        QApplication.quit()

    def save_baseline(self):
        if not self.data:
            return
        path = A.save_baseline(self.data)
        QMessageBox.information(self, "Baseline saved", "Known-good snapshot saved to:\n%s\n\nFuture runs will mark anything new as NEW and raise findings for new persistence, accounts, shares and listeners." % path)

    # ---- actions
    def relaunch_admin(self):
        try:
            rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, subprocess.list2cmdline(sys.argv), os.getcwd(), 1)
            if rc > 32:
                QApplication.quit()
        except Exception as e:
            QMessageBox.warning(self, "Elevation failed", str(e))

    def start(self):
        opts = {"analyst": self.analyst.text().strip(), "hours": self.hours.value(), "days": self.days.value(),
                "verify_sig": self.chk_sig.isChecked(), "hash_files": self.chk_hash.isChecked(), "events": self.chk_evt.isChecked()}
        self.btn_start.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.btn_export.setEnabled(False)
        self.btn_vt.setEnabled(False)
        self.btn_base.setEnabled(False)
        self.btn_shots.setEnabled(False)
        self.bar.setValue(0)
        self.worker = TriageWorker(opts)
        self.worker.progress.connect(lambda p, m: (self.bar.setValue(p), self.status.setText(m)))
        self.worker.done.connect(self.on_done)
        self.worker.failed.connect(self.on_failed)
        self.worker.start()

    def on_failed(self, msg):
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.status.setText("Stopped.")
        QMessageBox.critical(self, "Triage stopped", msg[-1800:])

    def on_done(self, data):
        self.data = data
        for key, pg in self.pages.items():
            pg.set_rows(data[key])
        self.tree_page.set_rows(data["processes"])
        self.dash.update_data(data)
        self.btn_base.setEnabled(True)
        self.btn_shots.setEnabled(True)
        self.tabs.setCurrentIndex(0)
        if self.auto:
            QTimer.singleShot(2500, self.auto_finish)
        s = data["summary"]
        self.status.setText("Triage complete in %ss: %d findings (%d critical, %d high), %d IOCs"
                            % (data["meta"].get("DurationSeconds", "?"), len(data["findings"]), s["counts"]["Critical"], s["counts"]["High"], len(data["iocs"])))
        self.btn_start.setEnabled(True)
        self.btn_cancel.setEnabled(False)
        self.btn_export.setEnabled(True)
        self.btn_vt.setEnabled(True)

    def export_case(self):
        if not self.data:
            return
        base = os.path.join(BASE_DIR, "cases")
        os.makedirs(base, exist_ok=True)
        try:
            path = report.export_case(self.data, base)
        except Exception as e:
            QMessageBox.critical(self, "Export failed", str(e))
            return
        box = QMessageBox(self)
        box.setWindowTitle("Case exported")
        box.setText("Case saved to:\n%s\n\nIncludes report.html, JSON, CSVs, IOC feed, chain of custody and SHA256SUMS." % path)
        open_rep, open_dir = box.addButton("Open report", QMessageBox.AcceptRole), box.addButton("Open folder", QMessageBox.ActionRole)
        box.addButton(QMessageBox.Close)
        box.exec_()
        try:
            if box.clickedButton() == open_rep:
                os.startfile(os.path.join(path, "report.html"))
            elif box.clickedButton() == open_dir:
                os.startfile(path)
        except Exception:
            pass

    def vt_enrich(self):
        if not self.data:
            return
        key = os.environ.get("VT_API_KEY", "")
        if not key:
            key, ok = QInputDialog.getText(self, "VirusTotal API key", "Paste your VirusTotal API key (kept in memory only):", QLineEdit.Password)
            if not ok or not key.strip():
                return
        limit, ok = QInputDialog.getInt(self, "VirusTotal", "How many top IOCs to check? (free API = 4 lookups/minute)", 8, 1, 60)
        if not ok:
            return
        cand = [i for i in self.data["iocs"] if i["Type"] in ("SHA256", "SHA1", "MD5", "IPv4", "Domain")]
        cand.sort(key=lambda i: (-A.SEV_RANK[i["Severity"]], i["Type"] != "SHA256"))
        self.vt = VTWorker(cand[:limit], key.strip())
        self.btn_vt.setEnabled(False)
        self.vt.progress.connect(lambda p, m: (self.bar.setValue(p), self.status.setText(m)))
        self.vt.finished_all.connect(self.vt_done)
        self.vt.start()

    def vt_done(self):
        self.pages["iocs"].set_rows(self.data["iocs"])
        self.bar.setValue(100)
        self.status.setText("VirusTotal enrichment finished. Re-export the case to include results.")
        self.btn_vt.setEnabled(True)


def run_gui(auto=False):
    if hasattr(Qt, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    win = MainWindow(auto)
    if auto:
        win.resize(1600, 960)
    win.show()
    sys.exit(app.exec_())
