import sys
import re
import math
import hashlib
import json
import csv
import random
import string
import requests
import threading
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QProgressBar, QTextEdit, QFrame, QFileDialog, QMessageBox)
from PyQt5.QtCore import Qt, pyqtSignal, QObject, QPropertyAnimation, QEasingCurve, pyqtProperty
from PyQt5.QtGui import QFont, QColor, QPalette, QIcon

# ============================================================
# COMMON PASSWORDS
# ============================================================
COMMON_PASSWORDS = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111",
    "1234567", "dragon", "123123", "baseball", "abc123", "football", "monkey", "letmein",
    "shadow", "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890", "michael",
    "654321", "superman", "1qaz2wsx", "7777777", "121212", "000000", "qazwsx", "123qwe",
    "killer", "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
}

# ============================================================
# CORE ANALYSIS LOGIC
# ============================================================
def calculate_entropy(password):
    charset = 0
    if re.search(r"[a-z]", password): charset += 26
    if re.search(r"[A-Z]", password): charset += 26
    if re.search(r"[0-9]", password): charset += 10
    if re.search(r"[^a-zA-Z0-9]", password): charset += 32
    if charset == 0 or len(password) == 0: return 0.0
    return round(len(password) * math.log2(charset), 2)

def detect_patterns(password):
    issues = []
    if re.search(r"(.)\1{2,}", password): issues.append("Repeated characters")
    lower = password.lower()
    for seq in ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop"]:
        for i in range(len(seq) - 2):
            if seq[i:i+3] in lower:
                issues.append(f"Sequential pattern ('{seq[i:i+3]}')")
                break
    leet_map = {"@": "a", "0": "o", "1": "i", "3": "e", "$": "s", "5": "s"}
    deleet = password
    for k, v in leet_map.items(): deleet = deleet.replace(k, v)
    if deleet != password: issues.append("Leet substitution detected")
    types = sum([bool(re.search(r"[a-z]", password)), bool(re.search(r"[A-Z]", password)), bool(re.search(r"[0-9]", password)), bool(re.search(r"[^a-zA-Z0-9]", password))])
    if types == 1: issues.append("Only one character type used")
    if len(password) < 8: issues.append("Too short (< 8 chars)")
    return issues

def check_breach(password):
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=10)
        if response.status_code != 200: return None
        for line in response.text.splitlines():
            h, count = line.split(":")
            if h == suffix: return int(count)
        return 0
    except:
        return None

def calculate_score(password, entropy, patterns, breach_count):
    score = 0
    length = len(password)
    if length >= 16: score += 30
    elif length >= 12: score += 25
    elif length >= 8: score += 15
    else: score += 5
    
    if entropy >= 80: score += 30
    elif entropy >= 60: score += 22
    elif entropy >= 40: score += 14
    else: score += 5
    
    types = sum([bool(re.search(r"[a-z]", password)), bool(re.search(r"[A-Z]", password)), bool(re.search(r"[0-9]", password)), bool(re.search(r"[^a-zA-Z0-9]", password))])
    score += types * 5
    score -= len(patterns) * 8
    if password.lower() in COMMON_PASSWORDS: score -= 50
    if breach_count and breach_count > 0: score -= 40
    return max(0, min(100, score))

def get_verdict(score):
    if score >= 80: return "STRONG", "#00E676"
    elif score >= 60: return "GOOD", "#FFEB3B"
    elif score >= 40: return "WEAK", "#FF9800"
    else: return "VERY WEAK", "#FF5252"

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(length))

# ============================================================
# THREADING SIGNALS
# ============================================================
class WorkerSignals(QObject):
    finished = pyqtSignal(int)

class BreachChecker(threading.Thread):
    def __init__(self, password):
        super().__init__()
        self.password = password
        self.signals = WorkerSignals()

    def run(self):
        count = check_breach(self.password)
        self.signals.finished.emit(count if count is not None else -1)

# ============================================================
# MODERN PYQT5 GUI
# ============================================================
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel - Password Security Dashboard")
        self.setGeometry(100, 100, 900, 750)
        self.setStyleSheet("background-color: #0d1117; color: #c9d1d9;")
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(40, 30, 40, 30)
        main_layout.setSpacing(20)

        # --- Header ---
        title = QLabel("🛡️ Sentinel Security")
        title.setFont(QFont("Segoe UI", 24, QFont.Bold))
        title.setStyleSheet("color: #58a6ff;")
        title.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title)

        subtitle = QLabel("Real-time Password Strength & Breach Analysis")
        subtitle.setFont(QFont("Segoe UI", 12))
        subtitle.setStyleSheet("color: #8b949e;")
        subtitle.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(subtitle)

        # --- Input Section ---
        input_frame = QFrame()
        input_frame.setStyleSheet("background-color: #161b22; border-radius: 10px; padding: 15px;")
        input_layout = QVBoxLayout(input_frame)
        
        lbl_input = QLabel("Enter Password:")
        lbl_input.setStyleSheet("color: #8b949e; font-size: 14px;")
        input_layout.addWidget(lbl_input)
        
        self.entry_pwd = QLineEdit()
        self.entry_pwd.setEchoMode(QLineEdit.Password)
        self.entry_pwd.setPlaceholderText("Type a password to analyze...")
        self.entry_pwd.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117; color: #c9d1d9; 
                border: 2px solid #30363d; border-radius: 5px; 
                padding: 10px; font-size: 16px; font-family: Consolas;
            }
            QLineEdit:focus { border: 2px solid #58a6ff; }
        """)
        self.entry_pwd.textChanged.connect(self.analyze_password)
        input_layout.addWidget(self.entry_pwd)
        main_layout.addWidget(input_frame)

        # --- Metrics Cards ---
        cards_layout = QHBoxLayout()
        self.card_entropy = self.create_card("ENTROPY", "0.0 bits", "#58a6ff")
        self.card_length = self.create_card("LENGTH", "0", "#58a6ff")
        self.card_breach = self.create_card("BREACH STATUS", "Waiting...", "#8b949e")
        
        cards_layout.addWidget(self.card_entropy[0])
        cards_layout.addWidget(self.card_length[0])
        cards_layout.addWidget(self.card_breach[0])
        main_layout.addLayout(cards_layout)

        # --- Score & Progress ---
        score_frame = QFrame()
        score_frame.setStyleSheet("background-color: #161b22; border-radius: 10px; padding: 20px;")
        score_layout = QVBoxLayout(score_frame)
        
        self.lbl_score = QLabel("Score: 0/100")
        self.lbl_score.setFont(QFont("Segoe UI", 18, QFont.Bold))
        self.lbl_score.setAlignment(Qt.AlignCenter)
        score_layout.addWidget(self.lbl_score)

        self.progress = QProgressBar()
        self.progress.setFixedHeight(15)
        self.progress.setTextVisible(False)
        self.progress.setStyleSheet("""
            QProgressBar { background-color: #0d1117; border-radius: 7px; }
            QProgressBar::chunk { background-color: #30363d; border-radius: 7px; }
        """)
        score_layout.addWidget(self.progress)

        self.lbl_verdict = QLabel("WAITING")
        self.lbl_verdict.setFont(QFont("Segoe UI", 20, QFont.Bold))
        self.lbl_verdict.setAlignment(Qt.AlignCenter)
        self.lbl_verdict.setStyleSheet("color: #8b949e;")
        score_layout.addWidget(self.lbl_verdict)
        
        main_layout.addWidget(score_frame)

        # --- Vulnerability Details ---
        self.details_box = QTextEdit()
        self.details_box.setReadOnly(True)
        self.details_box.setStyleSheet("""
            QTextEdit {
                background-color: #161b22; color: #c9d1d9; 
                border: 1px solid #30363d; border-radius: 10px; 
                padding: 15px; font-size: 14px; font-family: Consolas;
            }
        """)
        main_layout.addWidget(self.details_box)

        # --- Buttons ---
        btn_layout = QHBoxLayout()
        btn_style = """
            QPushButton {
                background-color: #21262d; color: #c9d1d9; 
                border: 1px solid #30363d; border-radius: 5px; 
                padding: 10px; font-size: 14px; font-weight: bold;
            }
            QPushButton:hover { background-color: #30363d; }
        """
        
        btn_gen = QPushButton("🔐 Generate Password")
        btn_gen.setStyleSheet(btn_style)
        btn_gen.clicked.connect(self.generate_and_fill)
        
        btn_csv = QPushButton("📁 Bulk Analyze (CSV)")
        btn_csv.setStyleSheet(btn_style)
        btn_csv.clicked.connect(self.bulk_analyze_csv)
        
        btn_json = QPushButton("📄 Export Report (JSON)")
        btn_json.setStyleSheet(btn_style)
        btn_json.clicked.connect(self.export_json)

        btn_layout.addWidget(btn_gen)
        btn_layout.addWidget(btn_csv)
        btn_layout.addWidget(btn_json)
        main_layout.addLayout(btn_layout)

    def create_card(self, title, initial_val, color):
        frame = QFrame()
        frame.setStyleSheet("background-color: #161b22; border-radius: 10px; padding: 15px; border: 1px solid #30363d;")
        layout = QVBoxLayout(frame)
        
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: bold;")
        lbl_title.setAlignment(Qt.AlignCenter)
        
        lbl_val = QLabel(initial_val)
        lbl_val.setStyleSheet(f"color: {color}; font-size: 20px; font-weight: bold;")
        lbl_val.setAlignment(Qt.AlignCenter)
        
        layout.addWidget(lbl_title)
        layout.addWidget(lbl_val)
        return frame, lbl_val

    def analyze_password(self):
        pwd = self.entry_pwd.text()
        
        if not pwd:
            self.card_entropy[1].setText("0.0 bits")
            self.card_length[1].setText("0")
            self.card_breach[1].setText("Waiting...")
            self.card_breach[1].setStyleSheet("color: #8b949e; font-size: 20px; font-weight: bold;")
            self.lbl_score.setText("Score: 0/100")
            self.progress.setValue(0)
            self.progress.setStyleSheet("QProgressBar::chunk { background-color: #30363d; }")
            self.lbl_verdict.setText("WAITING")
            self.lbl_verdict.setStyleSheet("color: #8b949e;")
            self.details_box.clear()
            return

        entropy = calculate_entropy(pwd)
        patterns = detect_patterns(pwd)
        
        self.card_entropy[1].setText(f"{entropy} bits")
        self.card_length[1].setText(str(len(pwd)))
        
        self.card_breach[1].setText("Checking...")
        self.card_breach[1].setStyleSheet("color: #FFEB3B; font-size: 20px; font-weight: bold;")
        self.details_box.setText("Analyzing... Please wait.")

        # Run API in background
        self.worker = BreachChecker(pwd)
        self.worker.signals.finished.connect(lambda count: self.update_ui(pwd, entropy, patterns, count))
        self.worker.start()

    def update_ui(self, pwd, entropy, patterns, breach_count):
        # If password changed while waiting for API, ignore result
        if pwd != self.entry_pwd.text():
            return

        if breach_count == -1:
            self.card_breach[1].setText("Offline")
            self.card_breach[1].setStyleSheet("color: #FF9800; font-size: 20px; font-weight: bold;")
            breach_count = 0
        elif breach_count > 0:
            self.card_breach[1].setText(f"PWNED ({breach_count:,})")
            self.card_breach[1].setStyleSheet("color: #FF5252; font-size: 20px; font-weight: bold;")
        else:
            self.card_breach[1].setText("SAFE (0)")
            self.card_breach[1].setStyleSheet("color: #00E676; font-size: 20px; font-weight: bold;")

        score = calculate_score(pwd, entropy, patterns, breach_count)
        verdict, color = get_verdict(score)

        # Animate progress bar
        self.animate_progress(score, color)
        
        self.lbl_score.setText(f"Score: {score}/100")
        self.lbl_verdict.setText(verdict)
        self.lbl_verdict.setStyleSheet(f"color: {color}; font-size: 20px; font-weight: bold;")

        self.details_box.clear()
        if patterns:
            self.details_box.setTextColor(QColor("#FF5252"))
            self.details_box.append("⚠️ VULNERABILITIES DETECTED:\n")
            self.details_box.setTextColor(QColor("#c9d1d9"))
            for p in patterns:
                self.details_box.append(f"  • {p}")
        else:
            self.details_box.setTextColor(QColor("#00E676"))
            self.details_box.append("✅ No obvious vulnerabilities detected.")
            
        if breach_count > 0:
            self.details_box.append("\n🚨 WARNING: This password has appeared in known data breaches.")
            self.details_box.append("   Change it immediately and enable 2FA.")
        elif breach_count == 0:
            self.details_box.setTextColor(QColor("#00E676"))
            self.details_box.append("\n✅ Not found in known data breaches.")

    def animate_progress(self, target_value, color):
        self.progress.setStyleSheet(f"""
            QProgressBar {{ background-color: #0d1117; border-radius: 7px; }}
            QProgressBar::chunk {{ background-color: {color}; border-radius: 7px; }}
        """)
        self.anim = QPropertyAnimation(self.progress, b"value")
        self.anim.setDuration(500)
        self.anim.setStartValue(self.progress.value())
        self.anim.setEndValue(target_value)
        self.anim.setEasingCurve(QEasingCurve.OutCubic)
        self.anim.start()

    def generate_and_fill(self):
        pwd = generate_password()
        self.entry_pwd.setText(pwd)
        # Make it visible for a brief moment so they can copy it
        self.entry_pwd.setEchoMode(QLineEdit.Normal)
        
    def export_json(self):
        pwd = self.entry_pwd.text()
        if not pwd:
            QMessageBox.warning(self, "Warning", "No password to export.")
            return
        
        entropy = calculate_entropy(pwd)
        patterns = detect_patterns(pwd)
        breach_count = check_breach(pwd) or 0
        score = calculate_score(pwd, entropy, patterns, breach_count)
        verdict, _ = get_verdict(score)
        
        data = {
            "password_length": len(pwd),
            "score": score,
            "verdict": verdict,
            "entropy": entropy,
            "weaknesses": patterns,
            "breach_count": breach_count
        }
        
        options = QFileDialog.Options()
        filename, _ = QFileDialog.getSaveFileName(self, "Save Report", "", "JSON Files (*.json)", options=options)
        if filename:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
            QMessageBox.information(self, "Success", "Report exported successfully!")

    def bulk_analyze_csv(self):
        options = QFileDialog.Options()
        filepath, _ = QFileDialog.getOpenFileName(self, "Open CSV", "", "CSV Files (*.csv)", options=options)
        if not filepath: return
        
        results = []
        try:
            with open(filepath, mode='r') as f:
                reader = csv.reader(f)
                for row in reader:
                    if not row: continue
                    pwd = row[0]
                    entropy = calculate_entropy(pwd)
                    patterns = detect_patterns(pwd)
                    breach_count = check_breach(pwd) or 0
                    score = calculate_score(pwd, entropy, patterns, breach_count)
                    verdict, _ = get_verdict(score)
                    results.append({"password": pwd, "score": score, "verdict": verdict})
            
            out_path, _ = QFileDialog.getSaveFileName(self, "Save Results", "", "CSV Files (*.csv)", options=options)
            if out_path:
                with open(out_path, mode='w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=["password", "score", "verdict"])
                    writer.writeheader()
                    writer.writerows(results)
                QMessageBox.information(self, "Success", f"Analyzed {len(results)} passwords and saved to CSV.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to process CSV: {e}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
