import sys
import re
import os
import json
import pandas as pd
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QPushButton, QProgressBar, 
                             QFrame, QFileDialog, QMessageBox, QGridLayout, 
                             QScrollArea, QTextEdit, QTabWidget, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QLineEdit, QComboBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui import QFont, QColor
import pyqtgraph as pg
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ============================================================
# UNIVERSAL LOG PARSER ENGINE
# ============================================================
def parse_log_line(line):
    line = line.strip()
    if not line: return None

    # 1. JSON Logs (Cloud, App Logs)
    if line.startswith("{"):
        try:
            data = json.loads(line)
            return {
                "format": "JSON",
                "raw": line,
                "ip": data.get("src_ip") or data.get("ip") or data.get("client_ip") or "N/A",
                "user": data.get("user") or data.get("username") or "N/A",
                "event": data.get("event_type") or data.get("message") or "App Event",
                "severity": "High" if "fail" in line.lower() or "error" in line.lower() else "Info"
            }
        except: pass

    # 2. Linux Syslog / Auth.log
    match_linux = re.search(r"(Failed password|Invalid user|Accepted password) for (?:invalid user )?(\S+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
    if match_linux:
        event_type = match_linux.group(1)
        user = match_linux.group(2)
        ip = match_linux.group(3)
        sev = "Critical" if "root" in user else ("High" if "Failed" in event_type else "Info")
        return {"format": "Linux Auth", "raw": line, "ip": ip, "user": user, "event": event_type, "severity": sev}

    # 3. Windows Event Logs (Text format)
    match_win = re.search(r"EventID:\s*(\d+).*?Account Name:\s*(\S+).*?Source Network Address:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
    if match_win:
        return {"format": "Windows Event", "raw": line, "ip": match_win.group(3), "user": match_win.group(2), "event": f"Win Event {match_win.group(1)}", "severity": "High"}

    # 4. Web Server Logs (Apache/Nginx)
    match_web = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\"(GET|POST|PUT|DELETE) (.*?)\"", line)
    if match_web:
        ip = match_web.group(1)
        method = match_web.group(2)
        path = match_web.group(3)
        return {"format": "Web Log", "raw": line, "ip": ip, "user": "N/A", "event": f"{method} {path}", "severity": "Medium" if "admin" in path.lower() else "Info"}

    # 5. Firewall Logs (Generic)
    match_fw = re.search(r"src=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?dst=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?action=(\w+)", line)
    if match_fw:
        return {"format": "Firewall", "raw": line, "ip": match_fw.group(1), "user": "N/A", "event": f"Traffic ({match_fw.group(3)})", "severity": "High" if match_fw.group(3).lower() == "deny" else "Info"}

    # 6. Catch-all
    return {"format": "Unknown", "raw": line, "ip": "N/A", "user": "N/A", "event": "Unclassified Log", "severity": "Info"}

# ============================================================
# WATCHDOG
# ============================================================
class LogFileHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback
    def on_modified(self, event):
        if not event.is_directory and os.path.basename(event.src_path) == os.path.basename(self.callback.__self__.file_path):
            self.callback()

# ============================================================
# WORKER
# ============================================================
class LogParserWorker(QThread):
    progress = pyqtSignal(int, str)
    result = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path

    def run(self):
        try:
            self.progress.emit(10, "Parsing initial log file...")
            parsed_events = []
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for i, line in enumerate(f):
                    ev = parse_log_line(line)
                    if ev: parsed_events.append(ev)

            self.progress.emit(100, "Initial Load Complete.")
            self.result.emit(parsed_events)
        except Exception as e:
            self.error.emit(f"Error: {str(e)}")

# ============================================================
# MAIN GUI
# ============================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LogSentinel - Enterprise Universal SOC")
        self.setGeometry(100, 100, 1400, 900)
        self.setStyleSheet("""
            QMainWindow { background-color: #0d1117; }
            QLabel { color: #c9d1d9; }
            QPushButton { font-family: 'Segoe UI'; }
        """)
        
        self.observer = None
        self.file_path = None
        self.all_events = []
        self.last_read_position = 0

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # Header
        header_layout = QHBoxLayout()
        title = QLabel("🛡️ LogSentinel Enterprise")
        title.setFont(QFont("Segoe UI", 24, QFont.Bold))
        title.setStyleSheet("color: #58a6ff;")
        header_layout.addWidget(title)
        
        self.lbl_status = QLabel("Monitoring: OFF")
        self.lbl_status.setStyleSheet("color: #FF5252; font-weight: bold; font-size: 14px;")
        header_layout.addWidget(self.lbl_status, alignment=Qt.AlignRight)
        main_layout.addLayout(header_layout)

        # File Bar
        file_bar = QFrame()
        file_bar.setStyleSheet("background-color: #161b22; border-radius: 8px; padding: 10px; border: 1px solid #30363d;")
        file_layout = QHBoxLayout(file_bar)
        
        self.lbl_file = QLabel("No log file selected.")
        self.lbl_file.setStyleSheet("color: #8b949e; font-family: 'Consolas';")
        
        btn_browse = QPushButton("📁 Browse")
        btn_browse.setStyleSheet("background-color: #21262d; color: #c9d1d9; border-radius: 5px; padding: 8px; font-weight: bold; border: 1px solid #30363d;")
        btn_browse.clicked.connect(self.select_file)
        
        self.btn_monitor = QPushButton("▶ Start Monitor")
        self.btn_monitor.setEnabled(False)
        self.btn_monitor.setStyleSheet("background-color: #238636; color: white; border-radius: 5px; padding: 8px 20px; font-weight: bold;")
        self.btn_monitor.clicked.connect(self.toggle_monitoring)

        file_layout.addWidget(self.lbl_file, stretch=1)
        file_layout.addWidget(btn_browse)
        file_layout.addWidget(self.btn_monitor)
        main_layout.addWidget(file_bar)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #30363d; border-radius: 8px; background-color: #161b22; }
            QTabBar::tab { background: #0d1117; color: #8b949e; padding: 10px 20px; border: 1px solid #30363d; border-bottom: none; border-top-left-radius: 5px; border-top-right-radius: 5px; font-weight: bold; font-family: 'Segoe UI';}
            QTabBar::tab:selected { background: #161b22; color: #58a6ff; border-top: 2px solid #58a6ff;}
        """)
        
        self.tab_live = QWidget()
        self.tab_stats = QWidget()
        
        self.tabs.addTab(self.tab_live, "📡 Live Event Stream")
        self.tabs.addTab(self.tab_stats, "📊 Threat Statistics")
        
        self.setup_live_tab()
        self.setup_stats_tab()
        main_layout.addWidget(self.tabs, stretch=1)

    def setup_live_tab(self):
        layout = QVBoxLayout(self.tab_live)
        
        # Filter Bar
        filter_bar = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Search by IP, User, or Event...")
        self.search_input.setStyleSheet("background-color: #0d1117; border: 1px solid #30363d; padding: 10px; border-radius: 5px; color: white; font-family: 'Segoe UI';")
        self.search_input.textChanged.connect(self.filter_table)
        
        self.format_filter = QComboBox()
        self.format_filter.addItems(["All Formats", "Linux Auth", "Windows Event", "JSON", "Web Log", "Firewall"])
        self.format_filter.setStyleSheet("background-color: #0d1117; border: 1px solid #30363d; padding: 10px; border-radius: 5px; color: white; font-family: 'Segoe UI';")
        self.format_filter.currentTextChanged.connect(self.filter_table)
        
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["All Severities", "Critical", "High", "Medium", "Info"])
        self.severity_filter.setStyleSheet("background-color: #0d1117; border: 1px solid #30363d; padding: 10px; border-radius: 5px; color: white; font-family: 'Segoe UI';")
        self.severity_filter.currentTextChanged.connect(self.filter_table)
        
        filter_bar.addWidget(self.search_input, stretch=2)
        filter_bar.addWidget(self.format_filter, stretch=1)
        filter_bar.addWidget(self.severity_filter, stretch=1)
        layout.addLayout(filter_bar)
        
        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Format", "IP Address", "User", "Event Type", "Severity"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # TOP CLASS TABLE STYLING
        self.table.setStyleSheet("""
            QTableWidget { 
                background-color: #0d1117; 
                color: #c9d1d9; 
                border: none; 
                font-family: 'Segoe UI'; 
                font-size: 14px;
                gridline-color: #30363d;
            }
            QHeaderView::section { 
                background-color: #21262d; 
                color: #58a6ff; 
                font-weight: bold; 
                padding: 8px; 
                border: none; 
                font-size: 14px;
            }
            QTableWidget::item { padding: 8px; }
        """)
        self.table.verticalHeader().setDefaultSectionSize(35) # Even spacing
        layout.addWidget(self.table)

    def setup_stats_tab(self):
        layout = QVBoxLayout(self.tab_stats)
        
        self.stats_layout = QGridLayout()
        layout.addLayout(self.stats_layout)
        
        self.chart_widget = pg.PlotWidget()
        self.chart_widget.setMinimumHeight(400)
        self.chart_widget.setBackground('#161b22')
        self.chart_widget.showGrid(x=True, y=True, alpha=0.3)
        self.chart_widget.getAxis('left').setPen(pg.mkPen(color='#c9d1d9'))
        self.chart_widget.getAxis('bottom').setPen(pg.mkPen(color='#c9d1d9'))
        layout.addWidget(self.chart_widget)

    def select_file(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Select Log File", "", "Log Files (*.log *.json *.txt);;All Files (*)")
        if filepath:
            self.file_path = filepath
            self.lbl_file.setText(f"File: {os.path.basename(filepath)}")
            self.lbl_file.setStyleSheet("color: #58a6ff; font-weight: bold; font-family: 'Consolas';")
            self.btn_monitor.setEnabled(True)
            self.table.setRowCount(0)
            self.all_events = []
            self.chart_widget.clear()
            
            self.last_read_position = os.path.getsize(self.file_path)
            
            self.worker = LogParserWorker(self.file_path)
            self.worker.progress.connect(lambda v, m: self.lbl_status.setText(m))
            self.worker.result.connect(self.load_initial_events)
            self.worker.error.connect(lambda e: QMessageBox.critical(self, "Error", e))
            self.worker.start()

    def load_initial_events(self, events):
        self.all_events = events
        for ev in events:
            self.add_event_to_table(ev)
        self.update_stats()

    def toggle_monitoring(self):
        if self.observer is None:
            self.observer = Observer()
            event_handler = LogFileHandler(self.on_file_modified)
            self.observer.schedule(event_handler, os.path.dirname(self.file_path), recursive=False)
            self.observer.start()
            self.btn_monitor.setText("⏹ Stop Monitor")
            self.btn_monitor.setStyleSheet("background-color: #da3633; color: white; border-radius: 5px; padding: 8px 20px; font-weight: bold;")
            self.lbl_status.setText("Monitoring: ON (Real-time)")
            self.lbl_status.setStyleSheet("color: #00E676; font-weight: bold;")
        else:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            self.btn_monitor.setText("▶ Start Monitor")
            self.btn_monitor.setStyleSheet("background-color: #238636; color: white; border-radius: 5px; padding: 8px 20px; font-weight: bold;")
            self.lbl_status.setText("Monitoring: OFF")
            self.lbl_status.setStyleSheet("color: #FF5252; font-weight: bold;")

    def on_file_modified(self):
        try:
            current_size = os.path.getsize(self.file_path)
            if current_size > self.last_read_position:
                with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(self.last_read_position)
                    new_lines = f.readlines()
                    self.last_read_position = current_size
                    
                    for line in new_lines:
                        ev = parse_log_line(line)
                        if ev:
                            self.all_events.append(ev)
                            self.add_event_to_table(ev)
                self.update_stats()
        except: pass

    def add_event_to_table(self, ev):
        row = self.table.rowCount()
        self.table.insertRow(row)
        
        item_format = QTableWidgetItem(ev["format"])
        item_ip = QTableWidgetItem(ev["ip"])
        item_user = QTableWidgetItem(ev["user"])
        item_event = QTableWidgetItem(ev["event"])
        item_severity = QTableWidgetItem(ev["severity"])
        
        # COLOR CODING
        if ev["severity"] == "Critical": 
            item_severity.setForeground(QColor("#FF5252"))
            item_event.setForeground(QColor("#FF5252"))
        elif ev["severity"] == "High": 
            item_severity.setForeground(QColor("#FF9800"))
        elif ev["severity"] == "Medium": 
            item_severity.setForeground(QColor("#FFEB3B"))
        else: 
            item_severity.setForeground(QColor("#00E676"))
            
        self.table.setItem(row, 0, item_format)
        self.table.setItem(row, 1, item_ip)
        self.table.setItem(row, 2, item_user)
        self.table.setItem(row, 3, item_event)
        self.table.setItem(row, 4, item_severity)
        
        self.table.scrollToBottom()

    def filter_table(self):
        search_text = self.search_input.text().lower()
        format_text = self.format_filter.currentText()
        severity_text = self.severity_filter.currentText()
        
        for row in range(self.table.rowCount()):
            fmt = self.table.item(row, 0).text()
            ip = self.table.item(row, 1).text().lower()
            user = self.table.item(row, 2).text().lower()
            event = self.table.item(row, 3).text().lower()
            sev = self.table.item(row, 4).text()
            
            match_search = (search_text in ip) or (search_text in user) or (search_text in event)
            match_format = (format_text == "All Formats") or (fmt == format_text)
            match_sev = (severity_text == "All Severities") or (sev == severity_text)
            
            self.table.setRowHidden(row, not (match_search and match_format and match_sev))

    def update_stats(self):
        for i in reversed(range(self.stats_layout.count())): 
            self.stats_layout.itemAt(i).widget().setParent(None)
        self.chart_widget.clear()
        
        total = len(self.all_events)
        critical = sum(1 for e in self.all_events if e["severity"] == "Critical")
        high = sum(1 for e in self.all_events if e["severity"] == "High")
        unique_ips = len(set(e["ip"] for e in self.all_events if e["ip"] != "N/A"))
        
        self.stats_layout.addWidget(self.create_stat_card("Total Events", total, "#58a6ff"), 0, 0)
        self.stats_layout.addWidget(self.create_stat_card("Critical Alerts", critical, "#FF5252"), 0, 1)
        self.stats_layout.addWidget(self.create_stat_card("High Alerts", high, "#FF9800"), 0, 2)
        self.stats_layout.addWidget(self.create_stat_card("Unique IPs", unique_ips, "#00E676"), 0, 3)
        
        ip_counts = {}
        for e in self.all_events:
            if e["ip"] != "N/A":
                ip_counts[e["ip"]] = ip_counts.get(e["ip"], 0) + 1
                
        if ip_counts:
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10][::-1]
            ips = [ip for ip, count in top_ips]
            counts = [count for ip, count in top_ips]
            
            y_pos = range(len(ips))
            bargraph = pg.BarGraphItem(x=y_pos, height=counts, width=0.6, brush='#58a6ff')
            self.chart_widget.addItem(bargraph)
            
            ax = self.chart_widget.getAxis('left')
            ax.setTicks([[(i, ip) for i, ip in enumerate(ips)]])

    def create_stat_card(self, title, value, color):
        frame = QFrame()
        frame.setStyleSheet("background-color: #21262d; border-radius: 8px; padding: 20px; border: 1px solid #30363d;")
        layout = QVBoxLayout(frame)
        
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("color: #8b949e; font-size: 14px; font-weight: bold; font-family: 'Segoe UI';")
        lbl_title.setAlignment(Qt.AlignCenter)
        
        lbl_val = QLabel(str(value))
        lbl_val.setStyleSheet(f"color: {color}; font-size: 32px; font-weight: bold; font-family: 'Segoe UI';")
        lbl_val.setAlignment(Qt.AlignCenter)
        
        layout.addWidget(lbl_title)
        layout.addWidget(lbl_val)
        return frame

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.showMaximized()
    sys.exit(app.exec_())
