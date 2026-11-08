"""Reusable widgets: shadowed Card, animated 3D Gauge, Chip, table helpers."""
from PyQt5.QtCore import Qt, QRectF, QEasingCurve, QVariantAnimation
from PyQt5.QtGui import QColor, QPainter, QPen, QRadialGradient, QLinearGradient, QFont
from PyQt5.QtWidgets import (QFrame, QVBoxLayout, QLabel, QWidget, QGraphicsDropShadowEffect, QTableWidget,
                             QTableWidgetItem, QAbstractItemView)

from . import theme


def apply_shadow(w, blur=34, dy=10, alpha=170):
    fx = QGraphicsDropShadowEffect(w)
    fx.setBlurRadius(blur)
    fx.setOffset(0, dy)
    fx.setColor(QColor(0, 0, 0, alpha))
    w.setGraphicsEffect(fx)


class Card(QFrame):
    def __init__(self, title="", parent=None):
        super().__init__(parent)
        self.setObjectName("card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(16, 14, 16, 16)
        self.lay.setSpacing(8)
        if title:
            t = QLabel(title.upper())
            t.setObjectName("cardTitle")
            self.lay.addWidget(t)
        apply_shadow(self)


class Chip(QLabel):
    def __init__(self, label, parent=None):
        super().__init__(parent)
        self.label = label
        self.setAlignment(Qt.AlignCenter)
        self.set_result("-", theme.MUTED)

    def set_result(self, text, color):
        c = QColor(color)
        self.setText(f"{self.label}: {str(text).upper()}")
        self.setStyleSheet(
            f"background: rgba({c.red()},{c.green()},{c.blue()},45); border: 1px solid {color};"
            f"border-bottom: 3px solid {color}; color: {color}; border-radius: 10px; padding: 6px 8px; font-weight: 800;")


class Gauge(QWidget):
    """Animated dial with bevelled bezel, glow arc and domed centre."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(250, 250)
        self._v, self._label, self._color = 0.0, "AWAITING EMAIL", QColor(theme.MUTED)
        self._target = 0
        self.anim = QVariantAnimation(self)
        self.anim.setDuration(1200)
        self.anim.setEasingCurve(QEasingCurve.OutCubic)
        self.anim.valueChanged.connect(self._tick)

    def _tick(self, v):
        self._v = float(v)
        self.update()

    def set_score(self, score, label, color):
        self._label, self._color, self._target = label, QColor(color), score
        self.anim.stop()
        self.anim.setStartValue(self._v)
        self.anim.setEndValue(float(score))
        self.anim.start()

    def reset(self):
        self.anim.stop()
        self._v, self._label, self._color = 0.0, "ANALYZING...", QColor(theme.ACCENT)
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        side = min(self.width(), self.height()) - 16
        rect = QRectF((self.width() - side) / 2, (self.height() - side) / 2, side, side)
        # bezel
        bez = QLinearGradient(rect.topLeft(), rect.bottomRight())
        bez.setColorAt(0, QColor("#3a4c7c"))
        bez.setColorAt(1, QColor("#0a0f1d"))
        p.setPen(Qt.NoPen)
        p.setBrush(bez)
        p.drawEllipse(rect)
        face = rect.adjusted(7, 7, -7, -7)
        fg = QRadialGradient(face.center().x(), face.top() + face.height() * 0.25, face.width() * 0.8)
        fg.setColorAt(0, QColor("#1a2646"))
        fg.setColorAt(1, QColor("#0a0f1d"))
        p.setBrush(fg)
        p.drawEllipse(face)
        arc = face.adjusted(20, 20, -20, -20)
        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(QColor("#18233f"), 16, Qt.SolidLine, Qt.RoundCap))
        p.drawArc(arc, 225 * 16, -270 * 16)
        span = int(-270 * 16 * self._v / 100.0)
        if span:
            glow = QColor(self._color)
            glow.setAlpha(55)
            p.setPen(QPen(glow, 28, Qt.SolidLine, Qt.RoundCap))
            p.drawArc(arc, 225 * 16, span)
            p.setPen(QPen(self._color, 16, Qt.SolidLine, Qt.RoundCap))
            p.drawArc(arc, 225 * 16, span)
        # dome
        inner = arc.adjusted(26, 26, -26, -26)
        dg = QRadialGradient(inner.center().x(), inner.top() + inner.height() * 0.28, inner.width() * 0.75)
        dg.setColorAt(0, QColor("#2b3d68"))
        dg.setColorAt(1, QColor("#0e1530"))
        p.setPen(QPen(QColor("#33466f"), 1))
        p.setBrush(dg)
        p.drawEllipse(inner)
        # text
        f = QFont("Segoe UI", max(18, int(inner.width() * 0.26)), QFont.Black)
        p.setFont(f)
        p.setPen(self._color)
        p.drawText(QRectF(inner.left(), inner.top() + inner.height() * 0.12, inner.width(), inner.height() * 0.5),
                   Qt.AlignCenter, str(int(round(self._v))))
        p.setFont(QFont("Segoe UI", 8, QFont.Bold))
        p.setPen(QColor(theme.MUTED))
        p.drawText(QRectF(inner.left(), inner.top() + inner.height() * 0.55, inner.width(), 20), Qt.AlignCenter, "RISK SCORE / 100")


def mk_table(cols, widths=None):
    t = QTableWidget(0, len(cols))
    t.setHorizontalHeaderLabels(cols)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setAlternatingRowColors(True)
    t.verticalHeader().setVisible(False)
    t.setWordWrap(True)
    t.setShowGrid(False)
    t.setTextElideMode(Qt.ElideRight)
    h = t.horizontalHeader()
    h.setStretchLastSection(True)
    h.setHighlightSections(False)
    for i, w in enumerate(widths or []):
        if w:
            t.setColumnWidth(i, w)
    return t


def fill_table(t, rows):
    t.setRowCount(0)
    t.setRowCount(len(rows))
    for r, row in enumerate(rows):
        for c, cell in enumerate(row):
            txt, col = cell if isinstance(cell, tuple) else (cell, None)
            it = QTableWidgetItem("" if txt is None else str(txt))
            it.setToolTip(it.text())
            if col:
                it.setForeground(QColor(col))
                f = it.font()
                f.setBold(True)
                it.setFont(f)
            t.setItem(r, c, it)
    t.resizeRowsToContents()
