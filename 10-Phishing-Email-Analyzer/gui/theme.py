"""Dark 'depth' theme: gradients, bevels and shadows for a 3D feel."""
BG, PANEL, PANEL2, BORDER = "#0b0f1a", "#121a2b", "#17213a", "#26334f"
TEXT, MUTED, ACCENT, ACCENT2 = "#e6ecff", "#8b9bbf", "#4da3ff", "#7c5cff"
GOOD, WARN, ORANGE, BAD = "#2ecc71", "#f5b942", "#ff8a3d", "#ff4d5e"

SEV_COLOR = {"critical": BAD, "high": ORANGE, "medium": WARN, "low": ACCENT, "info": MUTED, "good": GOOD}
RESULT_COLOR = {"pass": GOOD, "fail": BAD, "softfail": WARN, "neutral": WARN, "none": WARN,
                "permerror": BAD, "temperror": MUTED}

_STYLE = """
* { font-family: 'Segoe UI', 'Inter', Arial; font-size: 13px; color: @TEXT@; }
QMainWindow, QDialog { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #0e1424, stop:1 #080b14); }
QWidget#root { background: transparent; }
QLabel { background: transparent; }
QLabel#title { font-size: 22px; font-weight: 800; color: white; }
QLabel#subtitle { color: @MUTED@; }
QLabel#cardTitle { color: @MUTED@; font-size: 11px; font-weight: 700; letter-spacing: 1px; }
QLabel#verdict { font-size: 15px; font-weight: 800; letter-spacing: 1px; }
QFrame#header { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #16224a, stop:1 #1c1740);
    border: 1px solid #2f3f6d; border-bottom: 3px solid #0a0f1f; border-radius: 14px; }
QFrame#card { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #1c2849, stop:1 #111a2e);
    border: 1px solid #2b3a5e; border-top: 1px solid #44578a; border-bottom: 3px solid #090d18; border-radius: 14px; }
QPushButton { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #4f8dff, stop:1 #2c5fd0);
    border: 1px solid #6aa2ff; border-bottom: 4px solid #1a3b8a; border-radius: 9px; padding: 8px 16px;
    font-weight: 700; color: white; }
QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #6aa2ff, stop:1 #3a70e6); }
QPushButton:pressed { border-bottom: 1px solid #1a3b8a; padding-top: 11px; padding-bottom: 5px; }
QPushButton#ghost { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #26365f, stop:1 #1a2547);
    border: 1px solid #3a4d82; border-bottom: 4px solid #0e1630; }
QPushButton:disabled { background: #232c44; border-color: #2c3656; color: #6b7794; }
QTabWidget::pane { border: 1px solid @BORDER@; border-radius: 12px; background: #0f1627; top: -1px; }
QTabBar::tab { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #1d2a4a, stop:1 #141d35);
    border: 1px solid #2b3a5e; border-bottom: none; border-top-left-radius: 9px; border-top-right-radius: 9px;
    padding: 9px 26px; margin-right: 3px; color: @MUTED@; }
QTabBar::tab:selected { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #3a6fe0, stop:1 #25489c); color: white; }
QTabBar::tab:hover:!selected { color: white; }
QTableWidget { background: #0f1627; alternate-background-color: #121b30; border: none; gridline-color: #1c2745;
    selection-background-color: #25489c; selection-color: white; }
QTableWidget::item { padding: 5px 7px; border-bottom: 1px solid #18223c; }
QHeaderView::section { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #22305a, stop:1 #182246);
    color: #b8c8ee; padding: 7px; border: none; border-right: 1px solid #0d1426; font-weight: 700; }
QPlainTextEdit, QTextBrowser, QLineEdit { background: #0c1222; border: 1px solid @BORDER@; border-radius: 8px;
    font-family: Consolas, 'Cascadia Mono', monospace; padding: 6px; selection-background-color: #25489c; }
QTextBrowser { font-family: 'Segoe UI'; }
QProgressBar { background: #0c1222; border: 1px solid @BORDER@; border-radius: 8px; height: 16px; text-align: center; color: white; }
QProgressBar::chunk { border-radius: 7px; background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #4da3ff, stop:1 #7c5cff); }
QCheckBox { spacing: 8px; }
QScrollBar:vertical { background: #0c1222; width: 12px; margin: 0; }
QScrollBar::handle:vertical { background: #2e4073; border-radius: 6px; min-height: 30px; }
QScrollBar:horizontal { background: #0c1222; height: 12px; }
QScrollBar::handle:horizontal { background: #2e4073; border-radius: 6px; min-width: 30px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QToolTip { background: #17213a; color: white; border: 1px solid #3a4d82; }
"""


def stylesheet():
    s = _STYLE
    for k, v in (("@TEXT@", TEXT), ("@MUTED@", MUTED), ("@BORDER@", BORDER)):
        s = s.replace(k, v)
    return s
