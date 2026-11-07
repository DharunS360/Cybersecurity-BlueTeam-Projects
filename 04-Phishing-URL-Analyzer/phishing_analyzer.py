import sys
import os
import re
import json
import requests
import whois
import datetime
import base64
import socket
import ssl
import dns.resolver
import webbrowser
from urllib.parse import urlparse
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QFrame, QMessageBox, QGridLayout, QScrollArea, 
                             QSplitter)
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl
from PyQt5.QtGui import QFont, QColor

CONFIG_FILE = "config.json"

def load_api_key():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f).get("virustotal_api_key", "")
        except: pass
    return ""

class URLAnalyzerWorker(QThread):
    result = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, url, api_key):
        super().__init__()
        self.url = url
        self.api_key = api_key

    def get_dns_records(self, domain):
        records = {}
        for record_type in ['A', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, record_type, lifetime=3)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                records[record_type] = ["Not Found"]
        return records

    def check_security_headers(self):
        try:
            resp = requests.get(self.url, timeout=5, allow_redirects=True)
            headers = resp.headers
            missing = []
            if 'X-Frame-Options' not in headers: missing.append('X-Frame-Options')
            if 'Content-Security-Policy' not in headers: missing.append('CSP')
            if 'Strict-Transport-Security' not in headers: missing.append('HSTS')
            return missing
        except:
            return ["Could not connect"]

    def detect_tech(self, html, headers):
        tech = set()
        
        # Wappalyzer Style Signatures
        html_lower = html.lower()
        
        # CMS
        if 'wp-content' in html_lower or 'wordpress' in html_lower: tech.add("WordPress")
        if 'drupal' in html_lower: tech.add("Drupal")
        if 'joomla' in html_lower: tech.add("Joomla")
        
        # Frameworks (JS)
        if 'react' in html_lower or 'reactjs' in html_lower: tech.add("React.js")
        if 'vue.js' in html_lower or 'vue.min.js' in html_lower: tech.add("Vue.js")
        if 'angular' in html_lower: tech.add("Angular")
        if 'jquery' in html_lower: tech.add("jQuery")
        if 'next.js' in html_lower or '_next/static' in html_lower: tech.add("Next.js")
        
        # Server & Infra
        server = headers.get('server', '').lower()
        if 'cloudflare' in server or 'cf-ray' in headers: tech.add("Cloudflare")
        if 'nginx' in server: tech.add("Nginx")
        if 'apache' in server: tech.add("Apache")
        if 'iis' in server: tech.add("Microsoft IIS")
        
        # Analytics & Marketing
        if 'google-analytics' in html_lower or 'gtag' in html_lower: tech.add("Google Analytics")
        if 'facebook' in html_lower and 'pixel' in html_lower: tech.add("Facebook Pixel")
        if 'hotjar' in html_lower: tech.add("Hotjar")
        
        # Programming Language Hints
        if 'x-powered-by' in headers: tech.add(f"Backend: {headers['x-powered-by']}")
        if 'php' in html_lower or 'phpsessid' in html_lower: tech.add("PHP")
        if 'asp.net' in html_lower: tech.add("ASP.NET")
        
        return list(tech) if tech else ["Custom / Not Detected"]

    def run(self):
        try:
            risk_score = 0
            results = {
                "heuristics": [],
                "virustotal": "Not Checked",
                "urlscan": "Not Checked",
                "whois": "Not Checked",
                "dns": "Not Checked",
                "ssl": "Not Checked",
                "ip": "Not Checked",
                "security_headers": "Not Checked",
                "tech_stack": "Not Checked"
            }
            
            parsed = urlparse(self.url)
            domain = parsed.netloc.lower()
            
            # Heuristics
            bad_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".club"]
            if any(domain.endswith(tld) for tld in bad_tlds):
                risk_score += 20
                results["heuristics"].append("Suspicious TLD used.")

            brands = ["paypal", "google", "facebook", "amazon", "apple", "microsoft", "netflix"]
            for brand in brands:
                if brand in domain and domain != f"{brand}.com" and domain != f"www.{brand}.com":
                    risk_score += 30
                    results["heuristics"].append(f"Impersonation of '{brand}' detected.")

            # WHOIS
            try:
                w = whois.whois(domain)
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                if creation_date:
                    age_days = (datetime.datetime.now() - creation_date).days
                    results["whois"] = f"Created: {creation_date.strftime('%Y-%m-%d')}\nAge: {age_days} days\nRegistrar: {w.registrar}"
                    if age_days < 30: risk_score += 20
            except:
                results["whois"] = "WHOIS failed or restricted."

            # DNS & IP
            try:
                ip_address = socket.gethostbyname(domain)
                results["ip"] = f"Resolved IP: {ip_address}"
                dns_data = self.get_dns_records(domain)
                results["dns"] = f"A: {dns_data.get('A', ['N/A'])[0]}\nNS: {dns_data.get('NS', ['N/A'])[0]}"
            except:
                results["ip"] = "Failed to resolve."
                results["dns"] = "DNS failed."

            # SSL
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        issuer = dict(x[0] for x in cert['issuer'])
                        results["ssl"] = f"Issuer: {issuer.get('organizationName', 'Unknown')}\nValid Until: {cert['notAfter']}"
            except:
                results["ssl"] = "SSL failed or no HTTPS."
                risk_score += 10

            # Headers & Tech (Need to fetch HTML first)
            try:
                resp = requests.get(self.url, timeout=5, allow_redirects=True)
                html = resp.text
                headers = resp.headers
                
                missing_headers = []
                if 'X-Frame-Options' not in headers: missing_headers.append('X-Frame-Options')
                if 'Content-Security-Policy' not in headers: missing_headers.append('CSP')
                if 'Strict-Transport-Security' not in headers: missing_headers.append('HSTS')
                results["security_headers"] = f"Missing: {', '.join(missing_headers)}" if missing_headers else "All headers present (Good)"
                if len(missing_headers) > 2: risk_score += 10
                
                tech = self.detect_tech(html, headers)
                results["tech_stack"] = "\n".join(tech)
            except:
                results["security_headers"] = "Could not fetch headers."
                results["tech_stack"] = "Could not fetch HTML."

            # VirusTotal
            if self.api_key:
                try:
                    url_id = base64.urlsafe_b64encode(self.url.encode()).decode().strip("=")
                    resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": self.api_key}, timeout=10)
                    if resp.status_code == 200:
                        stats = resp.json()['data']['attributes']['last_analysis_stats']
                        malicious = stats.get('malicious', 0)
                        results["virustotal"] = f"Detections: {malicious} engines"
                        if malicious > 0: risk_score += 40
                    elif resp.status_code == 404:
                        results["virustotal"] = "Not found (New URL)."
                except: pass

            # URLScan.io
            try:
                search_url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}"
                resp = requests.get(search_url, timeout=10)
                if resp.status_code == 200:
                    data = resp.json()
                    total = data.get("total", 0)
                    results["urlscan"] = f"Scanned {total} times recently."
            except: pass

            # Cap score
            risk_score = min(risk_score, 100)
            
            if risk_score >= 60:
                verdict, color = "🚨 CRITICAL THREAT", "#FF5252"
            elif risk_score >= 30:
                verdict, color = "⚠️ SUSPICIOUS", "#FF9800"
            else:
                verdict, color = "✅ SAFE", "#00E676"

            self.result.emit({
                "url": self.url,
                "domain": domain,
                "risk_score": risk_score,
                "verdict": verdict,
                "color": color,
                "results": results
            })

        except Exception as e:
            self.error.emit(f"Analysis Error: {str(e)}")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PhishGuard - Enterprise Intelligence")
        self.setGeometry(100, 100, 1300, 850)
        self.setStyleSheet("background-color: #0d1117; color: #c9d1d9;")
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)

        # Header
        title = QLabel("🎣 PhishGuard - Full Domain Intelligence")
        title.setFont(QFont("Segoe UI", 24, QFont.Bold))
        title.setStyleSheet("color: #58a6ff;")
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        # Input Area
        input_frame = QFrame()
        input_frame.setStyleSheet("background-color: #161b22; border-radius: 8px; padding: 10px; border: 1px solid #30363d;")
        input_layout = QHBoxLayout(input_frame)
        
        self.entry_url = QLineEdit()
        self.entry_url.setPlaceholderText("Paste URL here...")
        self.entry_url.setStyleSheet("background-color: #0d1117; border: 1px solid #30363d; padding: 12px; border-radius: 5px; color: white; font-family: Consolas; font-size: 14px;")
        
        self.btn_analyze = QPushButton("🔍 Analyze URL")
        self.btn_analyze.setStyleSheet("background-color: #238636; color: white; border-radius: 5px; padding: 10px 25px; font-weight: bold; font-size: 14px;")
        self.btn_analyze.clicked.connect(self.start_analysis)

        input_layout.addWidget(self.entry_url, stretch=1)
        input_layout.addWidget(self.btn_analyze)
        main_layout.addWidget(input_frame)

        # Splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # Left: Results
        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setStyleSheet("background-color: transparent; border: none;")
        self.results_widget = QWidget()
        self.results_widget.setStyleSheet("background-color: transparent;")
        self.results_layout = QGridLayout(self.results_widget)
        self.results_layout.setSpacing(20)
        left_scroll.setWidget(self.results_widget)
        splitter.addWidget(left_scroll)
        
        # Right: Live Preview
        self.web_view = QWebEngineView()
        self.web_view.setUrl(QUrl("about:blank"))
        self.web_view.setStyleSheet("border: 1px solid #30363d; border-radius: 8px;")
        splitter.addWidget(self.web_view)
        
        splitter.setSizes([600, 700])
        main_layout.addWidget(splitter, stretch=1)

    def start_analysis(self):
        url = self.entry_url.text().strip()
        if not url: return
        if not url.startswith("http"): url = "http://" + url

        self.btn_analyze.setEnabled(False)
        self.btn_analyze.setText("Analyzing...")
        self.web_view.setUrl(QUrl("about:blank"))
        
        self.clear_results()
        
        api_key = load_api_key()
        self.worker = URLAnalyzerWorker(url, api_key)
        self.worker.result.connect(self.display_results)
        self.worker.error.connect(self.display_error)
        self.worker.start()

    def clear_results(self):
        for i in reversed(range(self.results_layout.count())): 
            self.results_layout.itemAt(i).widget().setParent(None)

    def display_error(self, message):
        self.btn_analyze.setEnabled(True)
        self.btn_analyze.setText("🔍 Analyze URL")
        lbl = QLabel(f"❌ {message}")
        lbl.setStyleSheet("color: #FF5252; font-size: 16px; font-weight: bold;")
        self.results_layout.addWidget(lbl, 0, 0)

    def create_source_card(self, title, content, color, btn_text=None, btn_link=None):
        frame = QFrame()
        frame.setStyleSheet("background-color: #161b22; border-radius: 8px; padding: 20px; border: 1px solid #30363d;")
        layout = QVBoxLayout(frame)
        layout.setSpacing(10)
        
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("color: #58a6ff; font-weight: bold; font-size: 16px;")
        layout.addWidget(lbl_title)
        
        lbl_content = QLabel(content)
        lbl_content.setStyleSheet(f"color: {color}; font-family: Segoe UI; font-size: 15px;")
        lbl_content.setWordWrap(True)
        layout.addWidget(lbl_content)
        
        if btn_text and btn_link:
            btn = QPushButton(btn_text)
            btn.setStyleSheet("background-color: #21262d; color: #c9d1d9; border-radius: 5px; padding: 8px; font-weight: bold; margin-top: 10px;")
            btn.clicked.connect(lambda: webbrowser.open(btn_link))
            layout.addWidget(btn)
            
        return frame

    def display_results(self, data):
        self.btn_analyze.setEnabled(True)
        self.btn_analyze.setText("🔍 Analyze URL")
        
        # 1. Verdict Box
        verdict_frame = QFrame()
        verdict_frame.setStyleSheet(f"background-color: {data['color']}22; border-radius: 8px; padding: 30px; border: 1px solid {data['color']};")
        verdict_layout = QVBoxLayout(verdict_frame)
        
        lbl_verdict = QLabel(data['verdict'])
        lbl_verdict.setStyleSheet(f"color: {data['color']}; font-size: 32px; font-weight: bold;")
        lbl_verdict.setAlignment(Qt.AlignCenter)
        
        lbl_score = QLabel(f"Overall Risk Score: {data['risk_score']} / 100")
        lbl_score.setStyleSheet(f"color: {data['color']}; font-size: 20px;")
        lbl_score.setAlignment(Qt.AlignCenter)
        
        verdict_layout.addWidget(lbl_verdict)
        verdict_layout.addWidget(lbl_score)
        self.results_layout.addWidget(verdict_frame, 0, 0, 1, 2)

        # 2. Source Cards with Buttons
        res = data["results"]
        domain = data["domain"]
        
        self.results_layout.addWidget(self.create_source_card("🌐 VirusTotal", res["virustotal"], "#00E676", "View Full Report", f"https://www.virustotal.com/gui/domain/{domain}"), 1, 0)
        self.results_layout.addWidget(self.create_source_card("🔍 URLScan.io", res["urlscan"], "#00E676", "View Full Report", f"https://urlscan.io/domain/{domain}"), 1, 1)
        self.results_layout.addWidget(self.create_source_card("📅 WHOIS Data", res["whois"], "#c9d1d9", "Check WHOIS", f"https://www.whois.com/whois/{domain}"), 2, 0)
        self.results_layout.addWidget(self.create_source_card("📡 DNS & IP", f"{res['ip']}\n{res['dns']}", "#c9d1d9", "Check DNS", f"https://dnsdumpster.com/static/map/{domain}.png"), 2, 1)
        self.results_layout.addWidget(self.create_source_card("🔒 SSL Certificate", res["ssl"], "#c9d1d9", "Check SSL", f"https://www.ssllabs.com/ssltest/analyze.html?d={domain}"), 3, 0)
        self.results_layout.addWidget(self.create_source_card("🛡️ Security Headers", res["security_headers"], "#FF9800" if "Missing" in res["security_headers"] else "#00E676", "Check Headers", f"https://securityheaders.com/?q={domain}"), 3, 1)
        self.results_layout.addWidget(self.create_source_card("💻 Technology Stack", res["tech_stack"], "#58a6ff", "Check Tech", f"https://builtwith.com/{domain}"), 4, 0, 1, 2)

        # 3. Flags
        if res["heuristics"]:
            flag_frame = QFrame()
            flag_frame.setStyleSheet("background-color: #161b22; border-radius: 8px; padding: 20px; border: 1px solid #30363d;")
            flag_layout = QVBoxLayout(flag_frame)
            lbl_flag_title = QLabel("🚩 Local Detection Flags:")
            lbl_flag_title.setStyleSheet("color: #58a6ff; font-weight: bold; font-size: 16px;")
            flag_layout.addWidget(lbl_flag_title)
            for flag in res["heuristics"]:
                lbl = QLabel(f"• {flag}")
                lbl.setStyleSheet("color: #FF9800; font-family: Segoe UI; font-size: 15px;")
                flag_layout.addWidget(lbl)
            self.results_layout.addWidget(flag_frame, 5, 0, 1, 2)

        # 4. Live Preview
        self.web_view.setUrl(QUrl(data['url']))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.showMaximized()
    sys.exit(app.exec_())
