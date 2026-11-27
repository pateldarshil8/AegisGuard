"""AegisGuard desktop UI (PySide6).

Every action that changes the system (applying a fix, quarantining, deleting) asks for confirmation first.
Long-running checks run on worker threads so the window never freezes.
"""
from __future__ import annotations

import sys
from pathlib import Path

import psutil
from PySide6.QtCore import QByteArray, QLockFile, QObject, QPointF, QRectF, QSize, QThread, QTimer, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QIcon, QPainter, QPen, QPixmap, QPolygonF
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QButtonGroup, QFrame, QHBoxLayout, QHeaderView, QInputDialog, QLabel,
                               QLineEdit, QListWidget, QSpinBox,
                               QMainWindow, QMenu, QMessageBox, QProgressBar, QPushButton, QStackedWidget,
                               QSystemTrayIcon,
                               QTableWidget, QTableWidgetItem, QTextEdit, QToolButton, QVBoxLayout, QWidget)

from .. import __version__
from datetime import datetime

from ..core import admin, config, settings
from ..core.models import Finding, ScanResult
from ..core.scoring import security_score
from . import theme
from ..modules import (cleanup, firewall, fixer, health, history, monitor, netmon, processes, quarantine, remediation,
                       reports, scanner, updater)


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


def make_table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setEditTriggers(QAbstractItemView.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectRows)
    t.setSelectionMode(QAbstractItemView.SingleSelection)
    t.verticalHeader().setVisible(False)
    t.horizontalHeader().setStretchLastSection(True)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    return t


def fill_findings(t: QTableWidget, findings: list[Finding]) -> None:
    t.setRowCount(len(findings))
    for r, f in enumerate(findings):
        sev = QTableWidgetItem(f.severity.value.upper())
        sev.setForeground(QColor(theme.sev_color(f.severity.value)))
        for c, item in enumerate([sev, QTableWidgetItem(f.module), QTableWidgetItem(f.title),
                                  QTableWidgetItem(f.detail or f.path or "")]):
            t.setItem(r, c, item)
    t.setColumnWidth(0, 80)
    t.setColumnWidth(1, 90)
    t.setColumnWidth(2, 380)


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


def heading(text: str, sub: str = "") -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 6)
    h = QLabel(text)
    h.setObjectName("h1")
    lay.addWidget(h)
    if sub:
        s = QLabel(sub)
        s.setObjectName("sub")
        s.setWordWrap(True)
        lay.addWidget(s)
    return w


def full_check() -> ScanResult:
    merged = reports.merge([health.run(), scanner.run(), processes.run(), firewall.run(), fixer.run(), netmon.run()])
    reports.write(merged)
    _, prev = history.record(merged)
    merged.meta["prev_score"] = prev.score if prev else None
    return merged


def make_icon() -> QIcon:
    pm = QPixmap(64, 64)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QColor("#3dd6c3"))
    p.setPen(Qt.NoPen)
    p.drawPolygon(QPolygonF([QPointF(32, 4), QPointF(58, 14), QPointF(54, 40), QPointF(32, 60),
                             QPointF(10, 40), QPointF(6, 14)]))
    p.setBrush(QColor("#0a0d12"))
    p.drawPolygon(QPolygonF([QPointF(32, 16), QPointF(46, 22), QPointF(44, 38), QPointF(32, 48),
                             QPointF(20, 38), QPointF(18, 22)]))
    p.end()
    return QIcon(pm)


class TrendWidget(QWidget):
    """Small line chart of security scores over time (oldest on the left)."""

    def __init__(self):
        super().__init__()
        self.scores: list[int] = []
        self.setMinimumHeight(150)

    def set_scores(self, scores: list[int]):
        self.scores = scores
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h, m = self.width(), self.height(), 26
        pal = theme.current()
        p.fillRect(self.rect(), QColor(pal["inset"]))
        p.setPen(QColor(pal["line"]))
        for v in (0, 50, 100):
            y = int(h - m - (h - 2 * m) * v / 100)
            p.drawLine(m, y, w - m, y)
            p.setPen(QColor(pal["sub"]))
            p.drawText(2, y + 4, str(v))
            p.setPen(QColor(pal["line"]))
        if not self.scores:
            p.setPen(QColor(pal["sub"]))
            p.drawText(self.rect(), Qt.AlignCenter, "No full checks recorded yet")
            p.end()
            return
        n = len(self.scores)
        pts = [QPointF(m + (w - 2 * m) * (i / (n - 1) if n > 1 else 0.5), h - m - (h - 2 * m) * s / 100)
               for i, s in enumerate(self.scores)]
        p.setPen(QPen(QColor(pal["accent"]), 2))
        for a, b in zip(pts, pts[1:]):
            p.drawLine(a, b)
        p.setBrush(QColor(pal["accent"]))
        for pt in pts:
            p.drawEllipse(pt, 3, 3)
        p.end()


class HistoryPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.addWidget(heading("History", "Security score from each full check, and what changed since the one before."))
        self.trend = TrendWidget()
        lay.addWidget(self.trend)
        self.status = QLabel("")
        self.status.setWordWrap(True)
        lay.addWidget(self.status)
        self.table = make_table(["When", "Score", "Critical", "High", "Medium", "Low", "Files scanned"])
        lay.addWidget(self.table, 1)
        self.refresh()

    def refresh(self):
        runs = history.recent(30)
        self.trend.set_scores([r.score for r in reversed(runs)])
        self.table.setRowCount(len(runs))
        for r, run in enumerate(runs):
            c = run.counts
            for col, v in enumerate((run.started, run.score, c["critical"], c["high"], c["medium"], c["low"],
                                     run.files_scanned)):
                self.table.setItem(r, col, QTableWidgetItem(str(v)))
        self.table.setColumnWidth(0, 170)
        if len(runs) >= 2:
            new, resolved = history.changes(runs[1], runs[0])
            bits = [f"Since the previous check: {len(new)} new, {len(resolved)} resolved."]
            bits += [f"+ {d['title']}" for d in new[:3]] + [f"- {d['title']}" for d in resolved[:3]]
            self.status.setText("\n".join(bits))
        elif runs:
            self.status.setText("Run another full check to see what changed since this one.")
        else:
            self.status.setText("Run a full check from the Dashboard to start your history.")


class DownloadWorker(QThread):
    progress = Signal(int, int)
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, info):
        super().__init__()
        self.info = info

    def run(self):
        try:
            self.done.emit(updater.download(self.info, progress=lambda a, b: self.progress.emit(a, b)))
        except Exception as e:
            self.failed.emit(str(e) if isinstance(e, updater.UpdateError) else f"{type(e).__name__}: {e}")


class UpdatesPage(QWidget):
    found = Signal(object, str)   # (UpdateInfo, "manual" | "startup" | "background")
    skipped = Signal()
    install_started = Signal()

    def __init__(self):
        super().__init__()
        self.info = None
        lay = QVBoxLayout(self)
        lay.addWidget(heading("Updates", f"You have version {__version__}. New versions are published on GitHub and "
                                         "checked against a published checksum before anything is installed."))
        row = QHBoxLayout()
        self.check_btn = QPushButton("Check for updates")
        self.check_btn.clicked.connect(lambda: self.check("manual"))
        self.install_btn = QPushButton("Install update")
        self.install_btn.setEnabled(False)
        self.install_btn.clicked.connect(lambda: self.install(True))
        self.skip_btn = QPushButton("Skip this version")
        self.skip_btn.setEnabled(False)
        self.skip_btn.clicked.connect(self.skip)
        for b in (self.check_btn, self.install_btn, self.skip_btn):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        self.status = QLabel("")
        lay.addWidget(self.status)
        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.hide()
        lay.addWidget(self.bar)
        self.notes = QTextEdit()
        self.notes.setReadOnly(True)
        self.notes.setPlaceholderText("Release notes appear here when an update is available.")
        lay.addWidget(self.notes, 1)

    def check(self, mode: str = "manual"):
        self.check_btn.setEnabled(False)
        if mode == "manual":
            self.status.setText("Checking GitHub for updates...")
        self.worker = Worker(updater.check)
        self.worker.done.connect(lambda info, m=mode: self._checked(info, m))
        self.worker.failed.connect(lambda msg, m=mode: self._check_failed(msg, m))
        self.worker.start()

    def _checked(self, info, mode: str):
        self.check_btn.setEnabled(True)
        if info is None:
            if mode == "manual":
                self.status.setText(f"You're up to date (version {__version__}).")
            return
        self.info = info
        self.status.setText(f"Version {info.version} is available (you have {__version__}).")
        self.notes.setPlainText(info.notes or "No release notes.")
        self.install_btn.setEnabled(True)
        self.skip_btn.setEnabled(True)
        self.found.emit(info, mode)

    def _check_failed(self, msg: str, mode: str):
        self.check_btn.setEnabled(True)
        if mode == "manual":
            self.status.setText(msg)

    def install(self, confirm: bool = True):
        if not self.info or not require_admin(self):
            return
        if confirm and QMessageBox.question(
                self, "Install update?",
                f"Download and install AegisGuard {self.info.version}?\n\nAegisGuard will close, Windows will ask for "
                "administrator permission, and AegisGuard restarts when the update finishes.") != QMessageBox.Yes:
            return
        for b in (self.check_btn, self.install_btn, self.skip_btn):
            b.setEnabled(False)
        self.bar.setValue(0)
        self.bar.show()
        self.status.setText("Downloading and verifying...")
        self.dl = DownloadWorker(self.info)
        self.dl.progress.connect(lambda a, t: self.bar.setValue(a * 100 // t if t else 0))
        self.dl.done.connect(self._downloaded)
        self.dl.failed.connect(self._download_failed)
        self.dl.start()

    def _download_failed(self, msg: str):
        self.bar.hide()
        self.status.setText(msg)
        self.check_btn.setEnabled(True)
        self.install_btn.setEnabled(True)
        self.skip_btn.setEnabled(True)

    def _downloaded(self, d):
        try:
            updater.launch_installer(d)
        except updater.UpdateError as e:
            self._download_failed(str(e))
            return
        self.status.setText("Installer started. AegisGuard will close now and restart when the update finishes.")
        self.install_started.emit()

    def skip(self):
        if self.info:
            updater.skip_version(self.info.version)
            self.status.setText(f"Version {self.info.version} skipped. You'll be told about newer versions.")
            self.install_btn.setEnabled(False)
            self.skip_btn.setEnabled(False)
            self.skipped.emit()


class AlertBridge(QObject):
    """Lets the monitor thread hand alerts to the UI thread safely."""
    alert = Signal(object)


class AlertsPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.addWidget(heading("Alerts", "Live alerts from background protection (newest first). Also saved to data\\alerts.log."))
        self.table = make_table(["Time", "Severity", "Finding", "Detail"])
        lay.addWidget(self.table, 1)

    def add(self, f: Finding):
        self.table.insertRow(0)
        sev = QTableWidgetItem(f.severity.value.upper())
        sev.setForeground(QColor(theme.sev_color(f.severity.value)))
        for c, item in enumerate([QTableWidgetItem(datetime.now().strftime("%H:%M:%S")), sev,
                                  QTableWidgetItem(f.title), QTableWidgetItem(f.detail or f.path or "")]):
            self.table.setItem(0, c, item)
        self.table.setColumnWidth(0, 80)
        self.table.setColumnWidth(1, 80)
        self.table.setColumnWidth(2, 380)


class CleanupPage(QWidget):
    def __init__(self):
        super().__init__()
        self.cands: list[cleanup.Candidate] = []
        lay = QVBoxLayout(self)
        lay.addWidget(heading("Disk Cleanup", "Frees space from old temp files, crash dumps and web cache only. "
                                              "Your documents and downloads are never touched."))
        row = QHBoxLayout()
        self.find_btn = QPushButton("Find reclaimable space")
        self.find_btn.clicked.connect(self.find)
        self.clean_btn = QPushButton("Delete these files")
        self.clean_btn.setObjectName("danger")
        self.clean_btn.setEnabled(False)
        self.clean_btn.clicked.connect(self.clean)
        self.space_btn = QPushButton("Where is my space going?")
        self.space_btn.clicked.connect(self.space)
        for b in (self.find_btn, self.clean_btn, self.space_btn):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        self.status = QLabel("")
        lay.addWidget(self.status)
        self.table = make_table(["Category / folder", "Files", "Size"])
        lay.addWidget(self.table, 1)

    def _show(self, rows):
        self.table.setRowCount(len(rows))
        for r, vals in enumerate(rows):
            for c, v in enumerate(vals):
                self.table.setItem(r, c, QTableWidgetItem(v))
        self.table.setColumnWidth(0, 520)

    def find(self):
        self.find_btn.setEnabled(False)
        self.status.setText("Looking for old temp files...")
        self.worker = Worker(cleanup.scan_cleanup)
        self.worker.done.connect(self._found)
        self.worker.failed.connect(lambda m: (self.status.setText(m), self.find_btn.setEnabled(True)))
        self.worker.start()

    def _found(self, cands):
        self.cands = cands
        summary = cleanup.summarize(cands)
        self._show([(cat, str(n), cleanup.human(b)) for cat, (n, b) in summary.items()])
        total = sum(b for _, b in summary.values())
        self.status.setText(f"{cleanup.human(total)} can be freed from {len(cands)} file(s)." if cands
                            else "Nothing to clean.")
        self.clean_btn.setEnabled(bool(cands))
        self.find_btn.setEnabled(True)

    def clean(self):
        if not require_admin(self):
            return
        total = sum(c.size for c in self.cands)
        if QMessageBox.question(self, "Delete files?",
                                f"Permanently delete {len(self.cands)} temp/cache file(s) ({cleanup.human(total)})?\n"
                                "Files that are in use will be skipped. This cannot be undone.") != QMessageBox.Yes:
            return
        freed, deleted, failed = cleanup.clean(self.cands, approved=True)
        self.status.setText(f"Freed {cleanup.human(freed)} ({deleted} deleted, {failed} skipped).")
        self.cands = []
        self.clean_btn.setEnabled(False)
        self._show([])

    def space(self):
        self.space_btn.setEnabled(False)
        self.status.setText("Measuring your user folder (up to 45 seconds)...")
        self.worker = Worker(lambda: cleanup.largest_items(Path.home()))
        self.worker.done.connect(self._space_done)
        self.worker.failed.connect(lambda m: (self.status.setText(m), self.space_btn.setEnabled(True)))
        self.worker.start()

    def _space_done(self, result):
        items, complete = result
        self._show([(p, "", cleanup.human(s)) for p, s in items])
        self.status.setText("Biggest items in your user folder." + ("" if complete else " (Stopped at time limit; sizes may be low.)"))
        self.space_btn.setEnabled(True)


SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


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


class DashboardPage(QWidget):
    """Home: a short list of what needs the user, the score, and live system meters."""
    navigate = Signal(str, object)   # (page key, tab index or None)

    def __init__(self):
        super().__init__()
        self._last = None
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(28)
        left = QVBoxLayout()
        left.setSpacing(12)
        self.eyebrow = QLabel()
        self.eyebrow.setObjectName("sub")
        self.headline = QLabel("Run a full check to see what needs you.")
        self.headline.setObjectName("h1")
        self.headline.setWordWrap(True)
        self.subline = QLabel("Nothing changes on your PC until you approve it.")
        self.subline.setObjectName("sub")
        self.subline.setWordWrap(True)
        for w in (self.eyebrow, self.headline, self.subline):
            left.addWidget(w)
        self.todo = QVBoxLayout()
        self.todo.setSpacing(10)
        left.addLayout(self.todo)
        left.addStretch(1)
        self.status = QLabel("")
        self.status.setObjectName("sub")
        self.status.setWordWrap(True)
        left.addWidget(self.status)
        tiles = QHBoxLayout()
        tiles.setSpacing(10)
        watched = ", ".join(Path(d).name for d in settings.load().watch_dirs) or "your folders"
        for name, note in (("Files", f"Watching {watched}"), ("Programs", "Checked every minute"),
                           ("Network", "Checked every minute"), ("Signatures", "Refreshed every 6 hours")):
            tile = QFrame()
            tile.setObjectName("inset")
            tv = QVBoxLayout(tile)
            tv.setContentsMargins(12, 10, 12, 10)
            tv.setSpacing(2)
            t = QLabel("●  " + name)
            t.setObjectName("cardtitle")
            n = QLabel(note)
            n.setObjectName("mute")
            n.setWordWrap(True)
            tv.addWidget(t)
            tv.addWidget(n)
            tiles.addWidget(tile)
        left.addLayout(tiles)

        right = QVBoxLayout()
        right.setSpacing(14)
        sc = QFrame()
        sc.setObjectName("card")
        sv = QVBoxLayout(sc)
        sv.setContentsMargins(20, 18, 20, 18)
        sv.setSpacing(4)
        cap = QLabel("SECURITY SCORE")
        cap.setObjectName("caps")
        self.score = QLabel("--")
        self.score.setObjectName("score")
        self.score_caption = QLabel("No full check yet")
        self.score_caption.setObjectName("sub")
        self.score_caption.setWordWrap(True)
        self.btn = QPushButton("Run full check")
        self.btn.clicked.connect(self.run_check)
        for w in (cap, self.score, self.score_caption):
            sv.addWidget(w)
        sv.addSpacing(8)
        sv.addWidget(self.btn)
        right.addWidget(sc)

        pc = QFrame()
        pc.setObjectName("card")
        pv = QVBoxLayout(pc)
        pv.setContentsMargins(20, 16, 20, 16)
        pv.setSpacing(6)
        title = QLabel("This PC")
        title.setObjectName("cardtitle")
        pv.addWidget(title)
        self.bars, self.vals = {}, {}
        for name in ("CPU", "Memory", "Disk"):
            row = QHBoxLayout()
            lab = QLabel(name)
            lab.setObjectName("sub")
            val = QLabel("--")
            val.setAlignment(Qt.AlignRight)
            row.addWidget(lab)
            row.addWidget(val)
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setTextVisible(False)
            pv.addLayout(row)
            pv.addWidget(bar)
            self.bars[name], self.vals[name] = bar, val
        self.admin_lbl = QLabel("Administrator: " + ("yes" if is_admin() else "no (some checks and fixes need it)"))
        self.admin_lbl.setObjectName("mute")
        self.admin_lbl.setWordWrap(True)
        pv.addWidget(self.admin_lbl)
        right.addWidget(pc)
        right.addStretch(1)
        outer.addLayout(left, 7)
        outer.addLayout(right, 3)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(2000)
        psutil.cpu_percent(None)
        self.tick()
        self._load_last()

    def _set_bar(self, name: str, pct: int):
        bar = self.bars[name]
        bar.setValue(pct)
        self.vals[name].setText(f"{pct}%")
        level = "warn" if (name == "Disk" and pct >= 90) or pct >= 95 else ""
        if bar.property("level") != level:
            bar.setProperty("level", level)
            bar.style().unpolish(bar)
            bar.style().polish(bar)

    def tick(self):
        self._set_bar("CPU", int(psutil.cpu_percent(None)))
        self._set_bar("Memory", int(psutil.virtual_memory().percent))
        try:
            self._set_bar("Disk", int(psutil.disk_usage(config.ROOT.anchor or "/").percent))
        except OSError:
            pass

    def _load_last(self):
        runs = history.recent(2)
        if not runs:
            self.eyebrow.setText(datetime.now().strftime("%A %d %B"))
            return
        try:
            when = datetime.fromisoformat(runs[0].started).strftime("%d %b %H:%M")
        except ValueError:
            when = runs[0].started
        self._show(runs[0].score, runs[1].score if len(runs) > 1 else None, runs[0].findings, when)

    def retheme(self):
        if self._last:
            self._show(*self._last)

    def _show(self, score: int, prev, findings: list[dict], when: str | None):
        self._last = (score, prev, findings, when)
        pal = theme.current()
        color = pal["accent"] if score >= 85 else pal["medFg"] if score >= 60 else pal["highFg"]
        self.score.setText(str(score))
        self.score.setStyleSheet(f"color:{color};")
        delta = f" ({score - prev:+d} since the check before)" if prev is not None else ""
        self.score_caption.setText(f"out of 100{delta}")
        self.eyebrow.setText(datetime.now().strftime("%A %d %B") + (f" · last full check {when}" if when else ""))
        shown = sorted((f for f in findings if f["severity"] != "info"), key=lambda f: SEV_RANK.get(f["severity"], 9))
        urgent = [f for f in shown if f["severity"] in ("critical", "high")]
        if urgent:
            n = len(urgent)
            self.headline.setText("One thing needs you." if n == 1 else f"{n} things need you.")
            self.subline.setText("Review it below. Nothing changes on your PC until you approve it.")
        elif shown:
            self.headline.setText("Nothing urgent.")
            self.subline.setText(f"{len(shown)} smaller thing(s) are worth a look.")
        else:
            self.headline.setText("All clear.")
            self.subline.setText("The last full check found nothing to act on.")
        while self.todo.count():
            item = self.todo.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        for f in shown[:3]:
            self.todo.addWidget(self._card(f))
        if len(shown) > 3:
            more = QLabel(f"{len(shown) - 3} more in History.")
            more.setObjectName("sub")
            self.todo.addWidget(more)

    def _card(self, f: dict) -> QFrame:
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
        detail = f.get("detail") or f.get("path") or ""
        if detail:
            d = QLabel(detail)
            d.setObjectName("sub")
            d.setWordWrap(True)
            info.addWidget(d)
        if f.get("remediation"):
            r = QLabel(f["remediation"])
            r.setObjectName("mute")
            r.setWordWrap(True)
            info.addWidget(r)
        h.addLayout(info, 1)
        btn = QPushButton("Review")
        btn.clicked.connect(lambda _=False, fd=f: self.navigate.emit(*route(fd)))
        h.addWidget(btn, alignment=Qt.AlignVCenter)
        return box

    def run_check(self):
        self.btn.setEnabled(False)
        self.status.setText("Running full check (scanning files, firewall, settings, network)...")
        self.worker = Worker(full_check)
        self.worker.done.connect(self.finish)
        self.worker.failed.connect(self.fail)
        self.worker.start()

    def finish(self, res: ScanResult):
        s = security_score(res.findings)
        self._show(s, res.meta.get("prev_score"), [f.to_dict() for f in res.findings], datetime.now().strftime("%H:%M"))
        self.status.setText(f"Done. Files scanned: {res.meta.get('files_scanned', 0)}. Report saved.")
        self.btn.setEnabled(True)

    def fail(self, msg: str):
        self.status.setText(f"Check failed: {msg}")
        self.btn.setEnabled(True)


class ModulePage(QWidget):
    """Runs one module and lists its findings. Optionally lets the user quarantine a flagged file."""

    def __init__(self, title: str, blurb: str, runner, button_text: str, allow_quarantine: bool = False):
        super().__init__()
        self.runner, self.findings = runner, []
        lay = QVBoxLayout(self)
        lay.addWidget(heading(title, blurb))
        row = QHBoxLayout()
        self.btn = QPushButton(button_text)
        self.btn.clicked.connect(self.start)
        row.addWidget(self.btn)
        if allow_quarantine:
            self.qbtn = QPushButton("Quarantine selected file")
            self.qbtn.clicked.connect(self.quarantine_selected)
            row.addWidget(self.qbtn)
        row.addStretch(1)
        lay.addLayout(row)
        self.status = QLabel("")
        lay.addWidget(self.status)
        self.table = make_table(["Severity", "Module", "Finding", "Detail"])
        lay.addWidget(self.table, 1)

    def start(self):
        self.btn.setEnabled(False)
        self.status.setText("Running...")
        self.worker = Worker(self.runner)
        self.worker.done.connect(self.finish)
        self.worker.failed.connect(self.fail)
        self.worker.start()

    def finish(self, res: ScanResult):
        self.findings = res.findings
        fill_findings(self.table, self.findings)
        extra = f" Files scanned: {res.meta['files_scanned']}." if "files_scanned" in res.meta else ""
        self.status.setText(f"{len(self.findings)} finding(s).{extra}" if self.findings else f"No issues found.{extra}")
        self.btn.setEnabled(True)

    def fail(self, msg: str):
        self.status.setText(f"Failed: {msg}")
        self.btn.setEnabled(True)

    def quarantine_selected(self):
        r = self.table.currentRow()
        if r < 0 or r >= len(self.findings) or not self.findings[r].path:
            QMessageBox.information(self, "Quarantine", "Select a finding that has a file path.")
            return
        f = self.findings[r]
        if not require_admin(self):
            return
        if QMessageBox.question(self, "Quarantine file?",
                                f"Move this file to quarantine?\n\n{f.path}\n\nYou can restore it later.") != QMessageBox.Yes:
            return
        try:
            quarantine.quarantine_file(f.path, f.title)
            QMessageBox.information(self, "Quarantine", "File quarantined.")
        except quarantine.QuarantineError as e:
            QMessageBox.warning(self, "Quarantine", str(e))


class FixesPage(QWidget):
    def __init__(self):
        super().__init__()
        self.fixes: list[fixer.Fix] = []
        lay = QVBoxLayout(self)
        lay.addWidget(heading("Fixes", "Risky settings we can correct. Nothing changes until you review and approve each fix."))
        self.btn = QPushButton("Check for fixes")
        self.btn.clicked.connect(self.start)
        lay.addWidget(self.btn, alignment=Qt.AlignLeft)
        self.status = QLabel("")
        lay.addWidget(self.status)
        self.table = make_table(["Severity", "Issue", "Proposed fix", ""])
        lay.addWidget(self.table, 1)

    def start(self):
        self.btn.setEnabled(False)
        self.status.setText("Checking...")
        self.worker = Worker(remediation.propose_all)
        self.worker.done.connect(self.finish)
        self.worker.failed.connect(lambda m: (self.status.setText(m), self.btn.setEnabled(True)))
        self.worker.start()

    def finish(self, result):
        res, self.fixes = result
        by_finding = {id(fx.finding): fx for fx in self.fixes}
        self.table.setRowCount(len(res.findings))
        for r, f in enumerate(res.findings):
            sev = QTableWidgetItem(f.severity.value.upper())
            sev.setForeground(QColor(theme.sev_color(f.severity.value)))
            self.table.setItem(r, 0, sev)
            self.table.setItem(r, 1, QTableWidgetItem(f.title))
            self.table.setItem(r, 2, QTableWidgetItem(f.remediation))
            fx = by_finding.get(id(f))
            if fx:
                b = QPushButton("Review && apply")
                b.clicked.connect(lambda _=False, x=fx: self.apply(x))
                self.table.setCellWidget(r, 3, b)
        self.table.setColumnWidth(1, 320)
        self.table.setColumnWidth(2, 380)
        self.status.setText(f"{len(res.findings)} issue(s), {len(self.fixes)} auto-fixable." if res.findings
                            else "No issues found.")
        self.btn.setEnabled(True)

    def apply(self, fx: fixer.Fix):
        if not require_admin(self):
            return
        admin_note = "" if is_admin() or not fx.needs_admin else "\n\nNote: this needs administrator rights; run AegisGuard as administrator."
        cmds = "\n".join(' '.join(c) for c in [fx.command, *fx.extra_commands])
        msg = f"{fx.finding.title}\n\nThis will run:\n{cmds}{admin_note}\n\nApply this fix?"
        if QMessageBox.question(self, "Apply fix?", msg) != QMessageBox.Yes:
            return
        ok, out = fixer.apply(fx, approved=True)
        (QMessageBox.information if ok else QMessageBox.warning)(self, "Fix applied" if ok else "Fix failed", out)


class QuarantinePage(QWidget):
    def __init__(self):
        super().__init__()
        self.items: list[quarantine.Item] = []
        lay = QVBoxLayout(self)
        lay.addWidget(heading("Quarantine", "Files moved here are renamed and inert. Restore them or delete them permanently."))
        row = QHBoxLayout()
        for text, fn, name in (("Refresh", self.refresh, ""), ("Restore", self.restore, ""),
                               ("Delete permanently", self.delete, "danger")):
            b = QPushButton(text)
            if name:
                b.setObjectName(name)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        self.table = make_table(["When", "Original location", "Reason"])
        lay.addWidget(self.table, 1)
        self.refresh()

    def refresh(self):
        self.items = quarantine.list_items()
        self.table.setRowCount(len(self.items))
        for r, i in enumerate(self.items):
            for c, v in enumerate((i.quarantined_at, i.original_path, i.reason)):
                self.table.setItem(r, c, QTableWidgetItem(v))
        self.table.setColumnWidth(0, 170)
        self.table.setColumnWidth(1, 460)

    def _selected(self):
        r = self.table.currentRow()
        return self.items[r] if 0 <= r < len(self.items) else None

    def restore(self):
        i = self._selected()
        if not i or not require_admin(self):
            return
        try:
            dest = quarantine.restore(i.id)
            QMessageBox.information(self, "Restored", f"Restored to {dest}")
        except quarantine.QuarantineError as e:
            QMessageBox.warning(self, "Restore", str(e))
        self.refresh()

    def delete(self):
        i = self._selected()
        if not i or not require_admin(self):
            return
        if QMessageBox.question(self, "Delete permanently?",
                                f"Permanently delete the quarantined copy of\n{i.original_path}?\nThis cannot be undone.") != QMessageBox.Yes:
            return
        quarantine.delete(i.id)
        self.refresh()


class ReportsPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.addWidget(heading("Reports", "Saved reports. Double-click one to open it."))
        row = QHBoxLayout()
        self.gen = QPushButton("Generate full report")
        self.gen.clicked.connect(self.generate)
        ref = QPushButton("Refresh")
        ref.clicked.connect(self.refresh)
        row.addWidget(self.gen)
        row.addWidget(ref)
        row.addStretch(1)
        lay.addLayout(row)
        self.list = QListWidget()
        self.list.itemDoubleClicked.connect(self.open_item)
        lay.addWidget(self.list, 1)
        self.refresh()

    def refresh(self):
        self.list.clear()
        config.ensure_dirs()
        for p in sorted(config.REPORTS_DIR.glob("report-*.md"), reverse=True):
            self.list.addItem(p.name)

    def open_item(self, item):
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(config.REPORTS_DIR / item.text())))

    def generate(self):
        self.gen.setEnabled(False)
        self.worker = Worker(full_check)
        self.worker.done.connect(lambda _: (self.refresh(), self.gen.setEnabled(True)))
        self.worker.failed.connect(lambda m: (QMessageBox.warning(self, "Report", m), self.gen.setEnabled(True)))
        self.worker.start()


class AdminPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.addWidget(heading("Administrator", "Protect AegisGuard's own actions with a password: applying fixes, quarantine "
                                               "restore/delete, disk cleanup, installing updates, pausing or quitting protection. "
                                               "This locks the app itself; it does not replace a Windows account password."))
        self.status = QLabel("")
        lay.addWidget(self.status)
        row = QHBoxLayout()
        self.set_btn = QPushButton("Set password")
        self.set_btn.clicked.connect(self.set_password)
        self.remove_btn = QPushButton("Remove password")
        self.remove_btn.setObjectName("danger")
        self.remove_btn.clicked.connect(self.remove_password)
        self.lock_btn = QPushButton("Lock now")
        self.lock_btn.clicked.connect(self.lock_now)
        for b in (self.set_btn, self.remove_btn, self.lock_btn):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Lock again after"))
        self.minutes = QSpinBox()
        self.minutes.setRange(1, 120)
        self.minutes.setSuffix(" min")
        self.minutes.setValue(admin.autolock_minutes())
        self.minutes.editingFinished.connect(lambda: admin.set_autolock_minutes(self.minutes.value()))
        row2.addWidget(self.minutes)
        row2.addStretch(1)
        lay.addLayout(row2)
        lay.addStretch(1)
        self.refresh()

    def refresh(self):
        has = admin.is_set()
        self.set_btn.setText("Change password" if has else "Set password")
        self.remove_btn.setEnabled(has)
        self.lock_btn.setEnabled(has and admin.is_unlocked())
        if not has:
            self.status.setText("No administrator password is set. Anyone using this window can apply fixes and delete files (each still asks to confirm).")
        else:
            self.status.setText("Unlocked for this session." if admin.is_unlocked() else "Locked. Protected actions ask for the password.")

    def _ask(self, label: str) -> str | None:
        text, ok = QInputDialog.getText(self, "Administrator password", label, QLineEdit.Password)
        return text if ok else None

    def set_password(self):
        current = ""
        if admin.is_set():
            current = self._ask("Current password:")
            if current is None:
                return
        new = self._ask(f"New password (at least {admin.MIN_LENGTH} characters):")
        if new is None:
            return
        again = self._ask("Type the new password again:")
        if again is None:
            return
        if new != again:
            QMessageBox.warning(self, "Administrator password", "The two passwords do not match.")
            return
        ok, msg = admin.set_password(new, current)
        (QMessageBox.information if ok else QMessageBox.warning)(self, "Administrator password", msg)
        self.refresh()

    def remove_password(self):
        current = self._ask("Current password:")
        if current is None:
            return
        ok, msg = admin.clear_password(current)
        (QMessageBox.information if ok else QMessageBox.warning)(self, "Administrator password", msg)
        self.refresh()

    def lock_now(self):
        admin.lock()
        self.refresh()


NAV_ICONS = {
    "home": "M4 11 12 4l8 7v9H4z",
    "scan": "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zm9 16-4-4",
    "network": "M12 5v4m0 6v4M5 12h4m6 0h4M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6z",
    "fixes": "M5 19 15 9m-3-5 8 8-3 3-8-8z",
    "vault": "M5 8h14v11H5zM9 8V5h6v3",
    "cleanup": "M6 7h12l-1 12H7zM9 7V4h6v3",
    "alerts": "M12 4a5 5 0 0 0-5 5v4l-2 3h14l-2-3V9a5 5 0 0 0-5-5zm-2 14a2 2 0 0 0 4 0",
    "history": "M12 6v6l4 2M4 12a8 8 0 1 0 2.5-5.8",
    "settings": "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM12 3v18",
}


def svg_icon(path_data: str, idle: str, active: str) -> QIcon:
    """A line icon drawn in two colors: idle, and active (used when the button is checked)."""
    icon = QIcon()
    for color, state in ((idle, QIcon.Off), (active, QIcon.On)):
        svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="%s" stroke-width="1.8" '
               'stroke-linecap="round" stroke-linejoin="round"><path d="%s"/></svg>' % (color, path_data))
        renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
        pm = QPixmap(44, 44)
        pm.fill(Qt.transparent)
        pm.setDevicePixelRatio(2)
        painter = QPainter(pm)
        renderer.render(painter, QRectF(0, 0, 22, 22))
        painter.end()
        icon.addPixmap(pm, QIcon.Normal, state)
    return icon


class Rail(QFrame):
    """Narrow icon navigation on the left. Settings sits at the bottom."""
    selected = Signal(str)

    def __init__(self, items: list[tuple[str, str]]):
        super().__init__()
        self.setObjectName("rail")
        self.setFixedWidth(88)
        self._items = items
        self.buttons: dict[str, QToolButton] = {}
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 16, 10, 16)
        lay.setSpacing(4)
        self.logo = QLabel()
        self.logo.setAlignment(Qt.AlignCenter)
        lay.addWidget(self.logo)
        lay.addSpacing(10)
        for key, label in items:
            if key == "settings":
                lay.addStretch(1)
            b = QToolButton()
            b.setObjectName("railbtn")
            b.setCheckable(True)
            b.setText(label)
            b.setToolTip(label)
            b.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
            b.setIconSize(QSize(22, 22))
            b.setFixedSize(68, 58)
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda _=False, k=key: self.selected.emit(k))
            self.group.addButton(b)
            lay.addWidget(b, alignment=Qt.AlignHCenter)
            self.buttons[key] = b
        self.retheme()

    def retheme(self):
        pal = theme.current()
        for key, _ in self._items:
            self.buttons[key].setIcon(svg_icon(NAV_ICONS[key], pal["idle"], pal["activeFg"]))
        self.logo.setPixmap(make_icon().pixmap(30, 30))

    def select(self, key: str):
        self.buttons[key].setChecked(True)

    def set_badge(self, key: str, on: bool):
        label = next(l for k, l in self._items if k == key)
        self.buttons[key].setText(label + (" ●" if on else ""))


class SectionPage(QWidget):
    """A page with a row of tabs on top (for example Malware scan / Processes)."""

    def __init__(self, tabs: list[tuple[str, QWidget]]):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(10)
        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.names = [n for n, _ in tabs]
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self.stack = QStackedWidget()
        self.buttons: list[QPushButton] = []
        for i, (name, widget) in enumerate(tabs):
            b = QPushButton(name)
            b.setObjectName("tab")
            b.setCheckable(True)
            b.setCursor(Qt.PointingHandCursor)
            self.group.addButton(b, i)
            bar.addWidget(b)
            self.stack.addWidget(widget)
            self.buttons.append(b)
        bar.addStretch(1)
        self.group.idClicked.connect(self.show_tab)
        lay.addLayout(bar)
        lay.addWidget(self.stack, 1)
        self.show_tab(0)

    def show_tab(self, i: int):
        self.stack.setCurrentIndex(i)
        self.buttons[i].setChecked(True)
        self.refresh_current()

    def refresh_current(self):
        w = self.stack.currentWidget()
        if isinstance(w, (QuarantinePage, HistoryPage, AdminPage)):
            w.refresh()

    def set_badge(self, i: int, on: bool):
        self.buttons[i].setText(self.names[i] + ("  ●" if on else ""))


class AppearancePage(QWidget):
    """Pick System, Light or Dark. System follows the Windows app mode."""
    chosen = Signal(str)
    OPTIONS = (("system", "System", "Matches Windows and switches with it."),
               ("light", "Light", "Bright background, best in daylight."),
               ("dark", "Dark", "Easy on the eyes at night."))

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.addWidget(heading("Appearance", "Choose how AegisGuard looks. System follows your Windows app mode."))
        row = QHBoxLayout()
        row.setSpacing(16)
        self.group = QButtonGroup(self)
        self.group.setExclusive(True)
        self.buttons = {}
        for key, title, text in self.OPTIONS:
            b = QPushButton(f"{title}\n{text}")
            b.setObjectName("optioncard")
            b.setCheckable(True)
            b.setMinimumHeight(96)
            b.setCursor(Qt.PointingHandCursor)
            b.clicked.connect(lambda _=False, k=key: self.chosen.emit(k))
            self.group.addButton(b)
            row.addWidget(b)
            self.buttons[key] = b
        lay.addLayout(row)
        self.note = QLabel("")
        self.note.setObjectName("sub")
        lay.addWidget(self.note)
        lay.addStretch(1)
        self.set_current(theme.normalize(settings.load().theme))

    def set_current(self, choice: str):
        self.buttons[choice].setChecked(True)
        shown = theme.current_mode()
        self.note.setText(f"Showing the {shown} theme" + (" (Windows is set to " + shown + ")." if choice == "system" else "."))


class MainWindow(QMainWindow):
    ORDER = ("home", "scan", "network", "fixes", "vault", "cleanup", "alerts", "history", "settings")
    LABELS = {"home": "Home", "scan": "Scan", "network": "Network", "fixes": "Fixes", "vault": "Vault",
              "cleanup": "Cleanup", "alerts": "Alerts", "history": "History", "settings": "Settings"}

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"AegisGuard {__version__}")
        self.resize(1180, 740)
        root = QWidget()
        self.setCentralWidget(root)
        lay = QHBoxLayout(root)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        self.alerts_page = AlertsPage()
        self.updates_page = UpdatesPage()
        self.dashboard = DashboardPage()
        self.appearance = AppearancePage()
        self.pages = {
            "home": self.dashboard,
            "scan": SectionPage([
                ("Malware scan", ModulePage("Malware Scan", "Scans your Downloads and Temp folders for known threats and disguised executables.",
                                            scanner.run, "Run quick scan", allow_quarantine=True)),
                ("Processes", ModulePage("Processes", "Running programs checked for masquerading, look-alike names and suspicious PowerShell (read-only).",
                                         processes.run, "Check processes"))]),
            "network": SectionPage([
                ("Connections", ModulePage("Network", "Open ports and suspicious connections (read-only).", netmon.run, "Check network")),
                ("Firewall", ModulePage("Firewall", "Windows Firewall profile status.", firewall.run, "Audit firewall"))]),
            "fixes": FixesPage(),
            "vault": QuarantinePage(),
            "cleanup": CleanupPage(),
            "alerts": self.alerts_page,
            "history": SectionPage([("History", HistoryPage()), ("Reports", ReportsPage())]),
            "settings": SectionPage([("Appearance", self.appearance), ("Administrator", AdminPage()),
                                     ("Updates", self.updates_page)]),
        }
        self.UPDATES_TAB = 2
        self.stack = QStackedWidget()
        for key in self.ORDER:
            self.stack.addWidget(self.pages[key])
        self.rail = Rail([(k, self.LABELS[k]) for k in self.ORDER])
        self.rail.selected.connect(self.go)
        self.dashboard.navigate.connect(self.go)
        self.appearance.chosen.connect(self.set_theme)
        lay.addWidget(self.rail)
        body = QVBoxLayout()
        body.setContentsMargins(28, 24, 28, 20)
        body.addWidget(self.stack)
        lay.addLayout(body, 1)
        self._theme_choice = theme.normalize(settings.load().theme)
        self._theme_timer = QTimer(self)
        self._theme_timer.timeout.connect(self._follow_system)
        self._theme_timer.start(3000)
        self._setup_protection()
        self._setup_updates()
        self.go("home")

    # ---- navigation + theme -------------------------------------------------------------
    def go(self, key: str, tab=None):
        page = self.pages[key]
        self.stack.setCurrentWidget(page)
        self.rail.select(key)
        if isinstance(page, SectionPage):
            if tab is not None:
                page.show_tab(tab)
            else:
                page.refresh_current()
        elif isinstance(page, (QuarantinePage, HistoryPage, AdminPage)):
            page.refresh()

    def set_theme(self, choice: str):
        self._theme_choice = theme.normalize(choice)
        s = settings.load()
        s.theme = self._theme_choice
        settings.save(s)
        theme.apply(QApplication.instance(), self._theme_choice)
        self._retheme()

    def _follow_system(self):
        if self._theme_choice == "system" and theme.resolve("system") != theme.current_mode():
            theme.apply(QApplication.instance(), "system")
            self._retheme()

    def _retheme(self):
        self.rail.retheme()
        self.dashboard.retheme()
        for w in self.findChildren(TrendWidget):
            w.update()
        self.appearance.set_current(self._theme_choice)

    # ---- updates ------------------------------------------------------------------------
    def _setup_updates(self):
        self.pending_update = None
        self._last_toast_update = False
        self.updates_page.found.connect(self._update_found)
        self.updates_page.skipped.connect(self._clear_update_badge)
        self.updates_page.install_started.connect(self._quit)
        if self.tray:
            self.tray.messageClicked.connect(self._on_toast_clicked)
        if updater.enabled():
            QTimer.singleShot(4000, lambda: self._auto_check("startup", 900))
            self.update_timer = QTimer(self)
            self.update_timer.timeout.connect(lambda: self._auto_check("background", 6 * 3600 - 60))
            self.update_timer.start(6 * 3600 * 1000)

    def _auto_check(self, mode: str, min_interval: float):
        if updater.due(min_interval):
            self.updates_page.check(mode)

    def _update_found(self, info, mode: str):
        if mode != "manual" and updater.is_skipped(info.version):
            return
        self.pending_update = info
        self._set_update_badge(True)
        if mode == "startup" and self.isVisible():
            self._update_dialog(info)
        elif mode != "manual" and self.tray:
            self._last_toast_update = True
            self.tray.showMessage("AegisGuard update available",
                                  f"Version {info.version} is ready. Open the Updates tab to install it.",
                                  QSystemTrayIcon.Information, 10000)

    def _update_dialog(self, info):
        box = QMessageBox(self)
        box.setWindowTitle("Update available")
        box.setText(f"AegisGuard {info.version} is available (you have {__version__}).")
        box.setInformativeText("Install it now? AegisGuard will restart when the update finishes.")
        install = box.addButton("Install now", QMessageBox.AcceptRole)
        box.addButton("Later", QMessageBox.RejectRole)
        skip = box.addButton("Skip this version", QMessageBox.DestructiveRole)
        box.exec()
        clicked = box.clickedButton()
        if clicked is install:
            self.go("settings", self.UPDATES_TAB)
            self.updates_page.install(confirm=False)
        elif clicked is skip:
            updater.skip_version(info.version)
            self._clear_update_badge()
        else:
            self.go("settings", self.UPDATES_TAB)

    def _set_update_badge(self, on: bool):
        self.rail.set_badge("settings", on)
        self.pages["settings"].set_badge(self.UPDATES_TAB, on)

    def _clear_update_badge(self):
        self.pending_update = None
        self._set_update_badge(False)

    def _on_toast_clicked(self):
        self._show_window()
        if self._last_toast_update:
            self.go("settings", self.UPDATES_TAB)
        self._last_toast_update = False

    # ---- background protection + tray -------------------------------------------------
    def _setup_protection(self):
        self._quitting = False
        self.bridge = AlertBridge()
        self.bridge.alert.connect(self._on_alert)
        self.monitor = monitor.Monitor(settings.load(), on_alert=self.bridge.alert.emit)
        self.tray = None
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = QSystemTrayIcon(make_icon(), self)
            self.setWindowIcon(make_icon())
            self.tray_menu = QMenu()
            self.tray_menu.addAction("Open AegisGuard").triggered.connect(self._show_window)
            self.toggle_action = self.tray_menu.addAction("Pause protection")
            self.toggle_action.triggered.connect(self._toggle_protection)
            self.tray_menu.addSeparator()
            self.tray_menu.addAction("Quit AegisGuard").triggered.connect(self._request_quit)
            self.tray.setContextMenu(self.tray_menu)
            self.tray.activated.connect(lambda r: self._show_window() if r == QSystemTrayIcon.Trigger else None)
            self.tray.show()
        self.monitor.start()

    def _on_alert(self, f: Finding):
        self._last_toast_update = False
        self.alerts_page.add(f)
        if self.tray:
            self.tray.showMessage(f"AegisGuard - {f.severity.value.upper()}",
                                  f"{f.title}\n{f.detail or f.path or ''}"[:250], QSystemTrayIcon.Warning, 8000)

    def _show_window(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _toggle_protection(self):
        if self.monitor.running:
            if not require_admin(self):
                return
            self.monitor.stop()
            self.toggle_action.setText("Resume protection")
        else:
            self.monitor.start()
            self.toggle_action.setText("Pause protection")

    def _request_quit(self):
        if require_admin(self):
            self._quit()

    def _quit(self):
        self._quitting = True
        self.monitor.stop()
        QApplication.quit()

    def closeEvent(self, e):
        if self._quitting or not (self.tray and self.tray.isVisible() and self.monitor.running):
            self.monitor.stop()
            e.accept()
            QApplication.quit()
            return
        e.ignore()
        self.hide()
        self.tray.showMessage("AegisGuard is still protecting your PC",
                              "Right-click the tray icon to open or quit.", QSystemTrayIcon.Information, 4000)


def launch(start_hidden: bool = False) -> None:
    """Open the app. start_hidden=True (used at sign-in) leaves it in the system tray with protection running."""
    config.ensure_dirs()
    app = QApplication.instance() or QApplication(sys.argv)
    theme.apply(app, settings.load().theme)
    app.setQuitOnLastWindowClosed(False)
    lock = QLockFile(str(config.DATA_DIR / "ui.lock"))  # one running copy at a time (two monitors would double-alert)
    if not lock.tryLock(300):
        QMessageBox.information(None, "AegisGuard", "AegisGuard is already running.\nLook for the shield icon in the system tray.")
        return
    win = MainWindow()
    if not (start_hidden and win.tray):
        win.show()
    app.exec()
    lock.unlock()
