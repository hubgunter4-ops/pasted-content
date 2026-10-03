from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QFrame, QLabel, QListWidget, QListWidgetItem, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget


PALETTE = {
    "bg": "#0B1020", "panel": "#141D2F", "panel2": "#1C2940", "console": "#070B14",
    "line": "#33496B", "text": "#F3F7FF", "text2": "#C4D2E6", "muted": "#8EA3BC",
    "accent": "#38D9C5", "blue": "#5DA9FF", "violet": "#9B8CFF",
    "success": "#6FE3A1", "warn": "#FFD166", "danger": "#FF6B8A",
}


def apply_ops_mono(app) -> None:
    app.setStyle("Fusion")
    app.setFont(QFont("DejaVu Sans Mono", 10))
    app.setStyleSheet(f"""
        QWidget {{ background: {PALETTE['bg']}; color: {PALETTE['text']}; font-family: 'DejaVu Sans Mono'; }}
        QMenuBar {{ background: #0D1116; color: {PALETTE['muted']}; padding: 3px 8px; }}
        QMenuBar::item {{ padding: 4px 9px; }} QMenuBar::item:selected {{ background: {PALETTE['panel2']}; color: {PALETTE['text']}; }}
        QToolBar {{ background: #121A2A; border: 0; spacing: 10px; padding: 8px 16px; }}
        QToolButton {{ background: #223451; color: {PALETTE['text']}; border: 1px solid {PALETTE['line']}; border-radius: 5px; padding: 8px 16px; min-width: 42px; }}
        QToolButton:hover {{ border-color: {PALETTE['accent']}; color: {PALETTE['accent']}; }}
        QStatusBar {{ background: #0D1116; color: {PALETTE['muted']}; border-top: 1px solid {PALETTE['line']}; padding: 4px 10px; }}
        QFrame#panel, QListWidget, QPlainTextEdit {{ background: {PALETTE['panel']}; border: 1px solid {PALETTE['line']}; border-radius: 6px; }}
        QFrame#card {{ background: {PALETTE['panel2']}; border: 1px solid {PALETTE['line']}; border-radius: 5px; }}
        QLabel#muted {{ color: {PALETTE['muted']}; }}
        QLabel#accent {{ color: {PALETTE['accent']}; }}
        QPushButton {{ background: {PALETTE['panel2']}; color: {PALETTE['text']}; border: 1px solid {PALETTE['line']}; border-radius: 5px; padding: 7px 12px; }}
        QPushButton:hover {{ border-color: {PALETTE['accent']}; color: {PALETTE['accent']}; }}
        QPushButton:disabled {{ color: {PALETTE['muted']}; }}
        QListWidget::item {{ padding: 8px; }} QListWidget::item:selected {{ background: #173832; color: {PALETTE['accent']}; }}
    """)


def panel(title: str) -> tuple[QFrame, QVBoxLayout]:
    frame = QFrame(); frame.setObjectName("panel")
    layout = QVBoxLayout(frame); layout.setContentsMargins(14, 12, 14, 12); layout.setSpacing(8)
    heading = QLabel(title); heading.setStyleSheet(f"font-size: 14px; font-weight: bold; color: {PALETTE['text']};")
    layout.addWidget(heading)
    return frame, layout


def status_label(text: str, color: str = PALETTE["muted"]) -> QLabel:
    label = QLabel(text); label.setStyleSheet(f"color: {color}; font-weight: bold;"); return label
