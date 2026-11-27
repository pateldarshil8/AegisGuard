"""Shared building blocks for the UI pages: worker thread, password prompt, headers, stat tiles, card lists."""
from __future__ import annotations

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMessageBox, QPushButton,
                               QScrollArea, QVBoxLayout, QWidget)

from ..core import admin
from ..core.models import ScanResult
from ..modules import fixer, firewall, health, history, netmon, processes, reports, scanner
from . import theme

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False


class Worker(QThread):
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        try:
            self.done.emit(self.fn())
        except Exception as e:  # surface any error in the UI instead of crashing the thread
            self.failed.emit(f"{type(e).__name__}: {e}")


def require_admin(parent) -> bool:
    """Ask for the administrator password when one is set and the session is locked."""
    if admin.authorized():
        return True
    while True:
        wait = admin.locked_out_seconds()
        if wait:
            QMessageBox.warning(parent, "Administrator password", f"Too many wrong attempts. Try again in {wait} seconds.")
            return False
        pw, ok = QInputDialog.getText(parent, "Administrator password",
                                      "This action needs the AegisGuard administrator password:", QLineEdit.Password)
        if not ok:
            return False
        good, msg = admin.unlock(pw)
        if good:
            return True
        QMessageBox.warning(parent, "Administrator password", msg)


def full_check() -> ScanResult:
    merged = reports.merge([health.run(), scanner.run(), processes.run(), firewall.run(), fixer.run(), netmon.run()])
    reports.write(merged)
    _, prev = history.record(merged)
    merged.meta["prev_score"] = prev.score if prev else None
    return merged


def heading(text: str, sub: str = "") -> QWidget:
    return page_header(text, sub)


def button(text: str, handler=None, kind: str = "") -> QPushButton:
    b = QPushButton(text)
    if kind:
        b.setObjectName(kind)
    if handler:
        b.clicked.connect(lambda _=False: handler())
    return b


def page_header(title: str, sub: str = "", action: QWidget | None = None) -> QWidget:
    w = QWidget()
    row = QHBoxLayout(w)
    row.setContentsMargins(0, 0, 0, 0)
    row.setSpacing(16)
    col = QVBoxLayout()
    col.setSpacing(6)
    t = QLabel(title)
    t.setObjectName("h1")
    col.addWidget(t)
    if sub:
        s = QLabel(sub)
        s.setObjectName("sub")
        s.setWordWrap(True)
        col.addWidget(s)
    row.addLayout(col, 1)
    if action is not None:
        row.addWidget(action, alignment=Qt.AlignTop)
    return w


def chip(severity: str) -> QLabel:
    fg, bg = theme.sev_colors(severity)
    lab = QLabel(severity.upper())
    lab.setAlignment(Qt.AlignCenter)
    lab.setFixedSize(64, 22)
    lab.setStyleSheet(f"background:{bg};color:{fg};border-radius:6px;font-size:11px;font-weight:700;")
    return lab


def route(f: dict) -> tuple[str, int | None]:
    """Which page (and tab) is the best place to deal with a finding."""
    module, title = f.get("module", ""), f.get("title", "").lower()
    if module == "health":
        return ("cleanup", None) if "disk" in title else ("history", 0)
    return {"scanner": ("scan", 0), "processes": ("scan", 1), "netmon": ("network", 0),
            "firewall": ("network", 1), "fixer": ("fixes", None)}.get(module, ("alerts", None))


def panel(title: str = "") -> tuple[QFrame, QVBoxLayout]:
    box = QFrame()
    box.setObjectName("card")
    lay = QVBoxLayout(box)
    lay.setContentsMargins(20, 16, 20, 16)
    lay.setSpacing(10)
    if title:
        t = QLabel(title)
        t.setObjectName("cardtitle")
        lay.addWidget(t)
    return box, lay


def note_label(text: str, kind: str = "sub") -> QLabel:
    lab = QLabel(text)
    lab.setObjectName(kind)
    lab.setWordWrap(True)
    return lab


class StatRow(QWidget):
    """A row of small number tiles: (label, value, note)."""

    def __init__(self, items: list[tuple[str, str, str]]):
        super().__init__()
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(14)
        self._values: list[QLabel] = []
        self._notes: list[QLabel] = []
        for label, value, note in items:
            box = QFrame()
            box.setObjectName("card")
            v = QVBoxLayout(box)
            v.setContentsMargins(18, 12, 18, 12)
            v.setSpacing(2)
            cap = QLabel(label.upper())
            cap.setObjectName("caps")
            val = QLabel(value)
            val.setObjectName("stat")
            nt = QLabel(note)
            nt.setObjectName("mute")
            for w in (cap, val, nt):
                v.addWidget(w)
            row.addWidget(box, 1)
            self._values.append(val)
            self._notes.append(nt)

    def set(self, i: int, value: str, note: str | None = None):
        self._values[i].setText(value)
        if note is not None:
            self._notes[i].setText(note)


class CardList(QScrollArea):
    """A scrolling column of cards, with a message shown when it is empty."""

    def __init__(self, empty: str = ""):
        super().__init__()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        body = QWidget()
        self._lay = QVBoxLayout(body)
        self._lay.setContentsMargins(0, 0, 6, 0)
        self._lay.setSpacing(10)
        self._empty = note_label(empty)
        self._lay.addWidget(self._empty)
        self._lay.addStretch(1)
        self.setWidget(body)

    def clear(self):
        while self._lay.count() > 2:
            item = self._lay.takeAt(1)
            if item.widget():
                item.widget().deleteLater()
        self._empty.setVisible(True)

    def add(self, widget: QWidget, top: bool = False):
        self._lay.insertWidget(1 if top else self._lay.count() - 1, widget)
        self._empty.setVisible(False)

    def count(self) -> int:
        return self._lay.count() - 2

    def set_empty(self, text: str):
        self._empty.setText(text)
        self._empty.setVisible(self.count() == 0)

    def drop(self, widget: QWidget):
        self._lay.removeWidget(widget)
        widget.setParent(None)
        widget.deleteLater()
        self._empty.setVisible(self.count() == 0)


def finding_card(f: dict, buttons: list[QPushButton], extra: str = "") -> QFrame:
    """A card for one finding: severity chip, title, where/what, and action buttons on the right."""
    box = QFrame()
    box.setObjectName("card")
    h = QHBoxLayout(box)
    h.setContentsMargins(18, 14, 18, 14)
    h.setSpacing(16)
    info = QVBoxLayout()
    info.setSpacing(4)
    top = QHBoxLayout()
    top.setSpacing(10)
    top.addWidget(chip(f["severity"]))
    title = QLabel(f["title"])
    title.setObjectName("cardtitle")
    title.setWordWrap(True)
    top.addWidget(title, 1)
    info.addLayout(top)
    where = f.get("path") or f.get("detail") or ""
    if where:
        info.addWidget(note_label(where))
    if f.get("path") and f.get("detail"):
        info.addWidget(note_label(f["detail"], "mute"))
    if extra:
        info.addWidget(note_label(extra, "mute"))
    h.addLayout(info, 1)
    if buttons:
        col = QVBoxLayout()
        col.setSpacing(8)
        for b in buttons:
            col.addWidget(b)
        col.addStretch(1)
        h.addLayout(col)
    return box


def apply_fix(parent, fx: fixer.Fix) -> bool:
    """Show the exact commands, ask, then run an approved fix. True when it ran successfully."""
    if not require_admin(parent):
        return False
    admin_note = "" if is_admin() or not fx.needs_admin else "\n\nNote: this needs administrator rights; run AegisGuard as administrator."
    cmds = "\n".join(" ".join(c) for c in [fx.command, *fx.extra_commands])
    msg = f"{fx.finding.title}\n\nThis will run:\n{cmds}{admin_note}\n\nApply this fix?"
    if QMessageBox.question(parent, "Apply fix?", msg) != QMessageBox.Yes:
        return False
    ok, out = fixer.apply(fx, approved=True)
    (QMessageBox.information if ok else QMessageBox.warning)(parent, "Fix applied" if ok else "Fix failed", out)
    return ok
