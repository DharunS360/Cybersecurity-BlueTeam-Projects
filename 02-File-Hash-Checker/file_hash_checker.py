import sys
import os
import hashlib
import requests
import json
import webbrowser
import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QPushButton, QProgressBar, 
                             QTextEdit, QFrame, QFileDialog, QMessageBox, QGridLayout, 
                             QScrollArea, QDialog, QLineEdit, QTabWidget, QListWidget)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QClipboard

CONFIG_FILE = "config.json"

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except: pass
    return {}

def save_config(vt_key, otx_key):
    with open(CONFIG_FILE, "w") as f:
        json.dump({"virustotal_api_key": vt_key, "otx_api_key": otx_key}, f)

def format_timestamp(ts):
    if not ts: return "N/A"
    try:
        return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except: return "N/A"

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("API Configuration")
        self.setFixedSize(450, 250)
        self.setStyleSheet("background-color: #161b22; color: #c9d1d9;")
        layout = QVBoxLayout(self)
        config = load_config()
        
        lbl = QLabel("VirusTotal API Key:")
        lbl.setStyleSheet("font-weight: bold;")
        layout.addWidget(lbl)
        self.entry_vt = QLineEdit()
        self.entry_vt.setEchoMode(QLineEdit.Password)
        self.entry_vt.setText(config.get("virustotal_api_key", ""))
        self.entry_vt.setStyleSheet("background-color: #0d1117; border: 1px solid #30363d; padding: 8px; border-radius: 5px;")
        layout.addWidget(self.entry_vt)
        
        lbl2 = QLabel("AlienVault OTX API Key:")
        lbl2.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(lbl2)
        self.entry_otx = QLineEdit()
        self.entry_otx.setEchoMode(QLineEdit.Password)
        self.entry_otx.setText(config.get("otx_api_key", ""))
        self.entry_otx.setStyleSheet("background-color: #0d1117; border: 1px solid #30363d; padding: 8px; border-radius: 5px;")
        layout.addWidget(self.entry_otx)
        
        btn_save = QPushButton("💾 Save Keys")
        btn_save.setStyleSheet("background-color: #238636; color: white; padding: 10px; border-radius: 5px; font-weight: bold; margin-top: 15px;")
        btn_save.clicked.connect(self.save_keys)
        layout.addWidget(btn_save)
        
    def save_keys(self):
        save_config(self.entry_vt.text().strip(), self.entry_otx.text().strip())
        QMessageBox.information(self, "Success", "API Keys saved successfully!")
        self.accept()

class ThreatIntelWorker(QThread):
    progress = pyqtSignal(int, str)
    result = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, input_data, vt_key, otx_key, is_hash=False):
        super().__init__()
        self.input_data = input_data
        self.vt_key = vt_key
        self.otx_key = otx_key
        self.is_hash = is_hash
        self.sha256 = ""
        self.results = {"virustotal": None, "otx": None, "malwarebazaar": None}

    def run(self):
        try:
            if self.is_hash:
                self.sha256 = self.input_data.lower()
            else:
                self.progress.emit(10, "Calculating SHA-256 hash...")
                sha256_hash = hashlib.sha256()
                with open(self.input_data, "rb") as f:
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                self.sha256 = sha256_hash.hexdigest()
            
            # VirusTotal
            if self.vt_key:
                self.progress.emit(30, "Checking VirusTotal...")
                try:
                    url = f"https://www.virustotal.com/api/v3/files/{self.sha256}"
                    resp = requests.get(url, headers={"x-apikey": self.vt_key}, timeout=10)
                    if resp.status_code == 200:
                        self.results["virustotal"] = resp.json()
                except: pass

            # AlienVault OTX
            if self.otx_key:
                self.progress.emit(60, "Checking AlienVault OTX...")
                try:
                    url = f"https://otx.alienvault.com/api/v1/indicators/file/{self.sha256}/general"
                    resp = requests.get(url, headers={"X-OTX-API-KEY": self.otx_key}, timeout=10)
                    if resp.status_code == 200:
                        self.results["otx"] = resp.json()
                except: pass

            # MalwareBazaar
            self.progress.emit(80, "Checking MalwareBazaar...")
            try:
                url = "https://mb-api.abuse.ch/api/v1/"
                data = {"query": "get_info", "hash": self.sha256}
                resp = requests.post(url, data=data, timeout=10)
                if resp.status_code == 200:
                    self.results["malwarebazaar"] = resp.json()
            except: pass

            self.progress.emit(100, "Analysis Complete!")
            self.result.emit(self.results)
        except Exception as e:
            self.error.emit(f"Error: {str(e)}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel - Multi-Source Threat Intelligence")
        self.setGeometry(100, 100, 1050, 850)
        self.setStyleSheet("background-color: #0d1117; color: #c9d1d9;")
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(30, 20, 30, 20)
        main_layout.setSpacing(15)

        header_layout = QHBoxLayout()
        title = QLabel("🛡️ Sentinel Multi-Source Intelligence")
        title.setFont(QFont("Segoe UI", 20, QFont.Bold))
        title.setStyleSheet("color: #58a6ff;")
        header_layout.addWidget(title)
        
        self.status_api = QLabel()
        self.update_api_status()
        header_layout.addWidget(self.status_api, alignment=Qt.AlignRight)
        
        btn_settings = QPushButton("⚙️ Setup API Keys")
        btn_settings.setStyleSheet("background-color: #21262d; color: #c9d1d9; border-radius: 5px; padding: 5px 10px;")
        btn_settings.clicked.connect(self.open_settings)
        header_layout.addWidget(btn_settings)
        main_layout.addLayout(header_layout)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #30363d; border-radius: 8px; }
            QTabBar::tab { background: #161b22; color: #8b949e; padding: 10px 20px; border-top-left-radius: 5px; border-top-right-radius: 5px; }
            QTabBar::tab:selected { background: #0d1117; color: #58a6ff; font-weight: bold; }
        """)
        
        self.tab_file = QWidget()
        self.setup_file_tab()
        self.tabs.addTab(self.tab_file, "📁 File Scan")
        
        self.tab_hash = QWidget()
        self.setup_hash_tab()
        self.tabs.addTab(self.tab_hash, "🔍 Hash Check")
        main_layout.addWidget(self.tabs)

        self.lbl_status = QLabel("Ready.")
        self.lbl_status.setStyleSheet("color: #8b949e; font-size: 11px;")
        main_layout.addWidget(self.lbl_status)

    def setup_file_tab(self):
        layout = QVBoxLayout(self.tab_file)
        layout.setSpacing(10)
        
        file_bar = QFrame()
        file_bar.setStyleSheet("background-color: #161b22; border-radius: 8px; padding: 5px;")
        file_layout = QHBoxLayout(file_bar)
        
        self.lbl_file = QLabel("No file selected.")
        self.lbl_file.setStyleSheet("color: #8b949e; font-family: Consolas;")
        
        btn_browse = QPushButton("📁 Browse")
        btn_browse.setStyleSheet("background-color: #21262d; color: #c9d1d9; border-radius: 5px; padding: 8px; font-weight: bold;")
        btn_browse.clicked.connect(self.select_file)
        
        self.btn_scan = QPushButton("🔍 Scan File")
        self.btn_scan.setEnabled(False)
        self.btn_scan.setStyleSheet("background-color: #238636; color: white; border-radius: 5px; padding: 8px 20px; font-weight: bold;")
        self.btn_scan.clicked.connect(lambda: self.start_scan(is_hash=False))

        file_layout.addWidget(self.lbl_file, stretch=1)
        file_layout.addWidget(btn_browse)
        file_layout.addWidget(self.btn_scan)
        layout.addWidget(file_bar)
        
        self.dash_layout_file = self.setup_dashboard_scroll(layout)

    def setup_hash_tab(self):
        layout = QVBoxLayout(self.tab_hash)
        layout.setSpacing(10)
        
        hash_bar = QFrame()
        hash_bar.setStyleSheet("background-color: #161b22; border-radius: 8px; padding: 10px;")
        hash_layout = QHBoxLayout(hash_bar)
        
        self.entry_hash = QLineEdit()
        self.entry_hash.setPlaceholderText("Paste SHA-256 Hash here...")
        self.entry_hash.setStyleSheet("background-color: #0d1117; border: 1px solid #30363d; padding: 10px; border-radius: 5px; color: white; font-family: Consolas;")
        
        btn_check_hash = QPushButton("🔍 Check Hash")
        btn_check_hash.setStyleSheet("background-color: #238636; color: white; border-radius: 5px; padding: 8px 20px; font-weight: bold;")
        btn_check_hash.clicked.connect(lambda: self.start_scan(is_hash=True))

        hash_layout.addWidget(self.entry_hash, stretch=1)
        hash_layout.addWidget(btn_check_hash)
        layout.addWidget(hash_bar)
        
        self.dash_layout_hash = self.setup_dashboard_scroll(layout)

    def setup_dashboard_scroll(self, parent_layout):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background-color: transparent; border: none;")
        scroll_content = QWidget()
        scroll_content.setStyleSheet("background-color: transparent;")
        dash_layout = QGridLayout(scroll_content)
        dash_layout.setSpacing(15)
        scroll.setWidget(scroll_content)
        parent_layout.addWidget(scroll, stretch=1)
        return dash_layout

    def update_api_status(self):
        config = load_config()
        if config.get("virustotal_api_key") and config.get("otx_api_key"):
            self.status_api.setText("🟢 All APIs Connected")
            self.status_api.setStyleSheet("color: #00E676; font-weight: bold;")
        elif config.get("virustotal_api_key"):
            self.status_api.setText("🟡 Only VirusTotal Connected")
            self.status_api.setStyleSheet("color: #FF9800; font-weight: bold;")
        else:
            self.status_api.setText("🔴 API Missing")
            self.status_api.setStyleSheet("color: #FF5252; font-weight: bold;")

    def open_settings(self):
        dialog = SettingsDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            self.update_api_status()

    def select_file(self):
        filepath, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)")
        if filepath:
            self.file_path = filepath
            self.lbl_file.setText(f"File: {os.path.basename(filepath)}")
            self.lbl_file.setStyleSheet("color: #58a6ff; font-weight: bold; font-family: Consolas;")
            self.btn_scan.setEnabled(True)
            self.clear_dashboard(self.dash_layout_file)

    def start_scan(self, is_hash=False):
        config = load_config()
        vt_key = config.get("virustotal_api_key", "")
        otx_key = config.get("otx_api_key", "")
        
        if not vt_key and not otx_key:
            QMessageBox.warning(self, "Error", "Please configure API keys.")
            return
            
        if is_hash:
            input_data = self.entry_hash.text().strip()
            if len(input_data) != 64:
                QMessageBox.warning(self, "Invalid Hash", "SHA-256 must be 64 chars.")
                return
            self.clear_dashboard(self.dash_layout_hash)
            active_layout = self.dash_layout_hash
        else:
            input_data = self.file_path
            self.btn_scan.setEnabled(False)
            self.clear_dashboard(self.dash_layout_file)
            active_layout = self.dash_layout_file
            
        self.lbl_status.setText("Scanning...")
        
        self.worker = ThreatIntelWorker(input_data, vt_key, otx_key, is_hash)
        self.worker.progress.connect(self.update_progress)
        self.worker.result.connect(lambda data: self.display_results(data, active_layout))
        self.worker.error.connect(lambda err: self.display_error(err, active_layout))
        self.worker.start()

    def update_progress(self, value, message):
        self.lbl_status.setText(message)

    def clear_dashboard(self, layout):
        for i in reversed(range(layout.count())): 
            layout.itemAt(i).widget().setParent(None)

    def display_error(self, message, layout):
        self.lbl_status.setText("Error.")
        self.btn_scan.setEnabled(True)
        lbl = QLabel(f"❌ {message}")
        lbl.setStyleSheet("color: #FF5252; font-size: 16px; font-weight: bold;")
        layout.addWidget(lbl, 0, 0)

    def copy_hash(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.worker.sha256)
        QMessageBox.information(self, "Copied", "SHA-256 copied!")

    def open_vt(self):
        webbrowser.open(f"https://www.virustotal.com/gui/file/{self.worker.sha256}")

    def display_results(self, data, layout):
        self.lbl_status.setText("Analysis Complete.")
        self.btn_scan.setEnabled(True)
        self.clear_dashboard(layout)
        
        vt_data = data.get("virustotal")
        mb_data = data.get("malwarebazaar")
        otx_data = data.get("otx")
        
        # 1. Verdict Analysis
        is_malicious = False
        reason = ""
        vt_detects = 0
        vt_total = 0
        
        if vt_data:
            stats = vt_data['data']['attributes']['last_analysis_stats']
            vt_detects = stats.get('malicious', 0) + stats.get('suspicious', 0)
            vt_total = vt_detects + stats.get('undetected', 0)
            if vt_detects > 0: 
                is_malicious = True
                reason = f"Detected by {vt_detects} VirusTotal engines."
            
        if mb_data and mb_data.get("query_status") == "ok":
            is_malicious = True
            reason = "Hash found in MalwareBazaar database."
            
        if otx_data and otx_data.get("pulse_info", {}).get("count", 0) > 0:
            is_malicious = True
            if not reason: # if VT/MB didn't flag, show OTX
                reason = f"Found in {otx_data.get('pulse_info', {}).get('count', 0)} AlienVault OTX pulses."

        # Big Verdict Box
        verdict_frame = QFrame()
        verdict_layout = QVBoxLayout(verdict_frame)
        if is_malicious:
            verdict_text, color, bg = "🚨 THREAT DETECTED", "#FF5252", "#3a1c1c"
        else:
            verdict_text, color, bg = "✅ CLEAN", "#00E676", "#1c3a24"
            
        verdict_frame.setStyleSheet(f"background-color: {bg}; border-radius: 8px; padding: 20px; border: 1px solid {color};")
        lbl_verdict = QLabel(verdict_text)
        lbl_verdict.setStyleSheet(f"color: {color}; font-size: 28px; font-weight: bold;")
        lbl_verdict.setAlignment(Qt.AlignCenter)
        verdict_layout.addWidget(lbl_verdict)
        
        if is_malicious:
            lbl_sub = QLabel(reason)
            lbl_sub.setStyleSheet(f"color: {color}; font-size: 14px;")
            lbl_sub.setAlignment(Qt.AlignCenter)
            verdict_layout.addWidget(lbl_sub)
            
        layout.addWidget(verdict_frame, 0, 0, 1, 2)

        # 2. Detailed File Info Card
        if vt_data:
            attr = vt_data['data']['attributes']
            info_frame = QFrame()
            info_frame.setStyleSheet("background-color: #161b22; border-radius: 8px; padding: 15px; border: 1px solid #30363d;")
            info_layout = QGridLayout(info_frame)
            
            # If file scan, use local file name. If hash check, use VT name.
            f_name = os.path.basename(self.file_path) if not self.worker.is_hash else attr.get('meaningful_name', 'Unknown')
            
            details = [
                ("File Name:", f_name),
                ("File Type:", attr.get('type_description', 'Unknown')),
                ("File Size:", f"{attr.get('size', 0) / 1024:.2f} KB"),
                ("First Seen:", format_timestamp(attr.get('first_submission_date'))),
                ("Last Seen:", format_timestamp(attr.get('last_analysis_date'))),
                ("SHA-256:", self.worker.sha256)
            ]
            
            for row, (k, v) in enumerate(details):
                lbl_k = QLabel(k)
                lbl_k.setStyleSheet("color: #8b949e; font-weight: bold; font-size: 13px;")
                lbl_v = QLabel(str(v))
                lbl_v.setStyleSheet("color: #c9d1d9; font-family: Consolas; font-size: 13px;")
                lbl_v.setWordWrap(True)
                info_layout.addWidget(lbl_k, row, 0)
                info_layout.addWidget(lbl_v, row, 1)
                
            btn_layout = QHBoxLayout()
            btn_copy = QPushButton("📋 Copy Hash")
            btn_copy.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px; border-radius: 5px;")
            btn_copy.clicked.connect(self.copy_hash)
            
            btn_vt = QPushButton("🌐 Open VirusTotal")
            btn_vt.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 8px; border-radius: 5px;")
            btn_vt.clicked.connect(self.open_vt)
            
            btn_layout.addWidget(btn_copy)
            btn_layout.addWidget(btn_vt)
            info_layout.addLayout(btn_layout, len(details), 0, 1, 2)
            
            layout.addWidget(info_frame, 1, 0, 1, 2)

        # 3. VirusTotal Engine List
        if vt_data:
            vt_frame = QFrame()
            vt_frame.setStyleSheet("background-color: #161b22; border-radius: 8px; padding: 10px; border: 1px solid #30363d;")
            vt_layout = QVBoxLayout(vt_frame)
            vt_title = QLabel(f"🌐 VirusTotal Engine Detections ({vt_detects} flagged)")
            vt_title.setStyleSheet("color: #58a6ff; font-weight: bold; font-size: 14px;")
            vt_layout.addWidget(vt_title)
            
            scroll_vt = QScrollArea()
            scroll_vt.setWidgetResizable(True)
            scroll_vt.setStyleSheet("background-color: transparent; border: none;")
            vt_content = QWidget()
            vt_grid = QGridLayout(vt_content)
            
            results = vt_data['data']['attributes'].get('last_analysis_results', {})
            row = 0
            for eng, res in results.items():
                if res['category'] in ['malicious', 'suspicious']:
                    lbl = QLabel(f"❌ {eng}: {res['result']}")
                    lbl.setStyleSheet("color: #FF5252; font-family: Consolas; font-size: 12px; background-color: #1c1f26; padding: 4px; border-radius: 3px;")
                    vt_grid.addWidget(lbl, row, 0)
                    row += 1
            if row == 0:
                vt_grid.addWidget(QLabel("No engines flagged this file."), 0, 0)
                
            scroll_vt.setWidget(vt_content)
            vt_layout.addWidget(scroll_vt)
            layout.addWidget(vt_frame, 2, 0, 1, 1)

        # 4. Threat Intel Sources Summary (OTX & MalwareBazaar)
        intel_frame = QFrame()
        intel_frame.setStyleSheet("background-color: #161b22; border-radius: 8px; padding: 10px; border: 1px solid #30363d;")
        intel_layout = QVBoxLayout(intel_frame)
        
        lbl_intel = QLabel("🕵️ Other Threat Intel Sources")
        lbl_intel.setStyleSheet("color: #58a6ff; font-weight: bold; font-size: 14px;")
        intel_layout.addWidget(lbl_intel)
        
        # OTX Result
        otx_count = otx_data.get("pulse_info", {}).get("count", 0) if otx_data else 0
        lbl_otx = QLabel(f"👁️ AlienVault OTX: Found in {otx_count} pulses.")
        lbl_otx.setStyleSheet(f"color: {'#FF5252' if otx_count > 0 else '#00E676'}; font-weight: bold; font-size: 13px;")
        intel_layout.addWidget(lbl_otx)
        
        if otx_count > 0:
            otx_scroll = QScrollArea()
            otx_scroll.setWidgetResizable(True)
            otx_scroll.setFixedHeight(120)
            otx_scroll.setStyleSheet("background-color: #0d1117; border: 1px solid #30363d; border-radius: 5px;")
            otx_content = QWidget()
            otx_list_layout = QVBoxLayout(otx_content)
            
            pulses = otx_data.get("pulse_info", {}).get("pulses", [])
            for pulse in pulses[:5]:
                name = pulse.get('name', 'Unknown Threat')
                tags = ", ".join(pulse.get('tags', [])[:3])
                pulse_lbl = QLabel(f"• {name} ({tags})")
                pulse_lbl.setStyleSheet("color: #FF9800; font-family: Consolas; font-size: 12px;")
                pulse_lbl.setWordWrap(True)
                otx_list_layout.addWidget(pulse_lbl)
            
            if len(pulses) > 5:
                otx_list_layout.addWidget(QLabel(f"...and {len(pulses)-5} more."))
                
            otx_scroll.setWidget(otx_content)
            intel_layout.addWidget(otx_scroll)
            
            btn_otx = QPushButton("🌐 Open Full Report in OTX")
            btn_otx.setStyleSheet("background-color: #21262d; color: #c9d1d9; padding: 5px; border-radius: 5px; font-size: 11px; margin-top: 5px;")
            btn_otx.clicked.connect(lambda: webbrowser.open(f"https://otx.alienvault.com/indicator/file/{self.worker.sha256}"))
            intel_layout.addWidget(btn_otx)
        
        # MalwareBazaar Result
        mb_found = mb_data and mb_data.get("query_status") == "ok"
        lbl_mb = QLabel(f"🦠 MalwareBazaar: {'⚠️ FOUND in database' if mb_found else 'Not found'}")
        lbl_mb.setStyleSheet(f"color: {'#FF5252' if mb_found else '#00E676'}; font-weight: bold; font-size: 13px; margin-top: 10px;")
        intel_layout.addWidget(lbl_mb)
        
        layout.addWidget(intel_frame, 2, 1, 1, 1)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
