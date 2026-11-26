"""AegisGuard desktop UI (PySide6).

Every action that changes the system (applying a fix, quarantining, deleting) asks for confirmation first.
Long-running checks run on worker threads so the window never freezes.
"""
from __future__ import annotations

import sys
from pathlib import Path

import psutil
from PySide6.QtCore import QLockFile, QObject, QPointF, QThread, QTimer, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont, QIcon, QPainter, QPen, QPixmap, QPolygonF
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QHBoxLayout, QHeaderView, QLabel, QListWidget,
                               QMainWindow, QMenu, QMessageBox, QProgressBar, QPushButton, QStackedWidget,
                               QSystemTrayIcon,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from .. import __version__
from datetime import datetime

from ..core import config, settings
from ..core.models import Finding, ScanResult
from ..core.scoring import security_score
from ..modules import (cleanup, firewall, fixer, health, history, monitor, netmon, processes, quarantine, remediation,
                       reports, scanner)

SEV_COLORS = {"critical": "#ff5370", "high": "#ff8a65", "medium": "#ffcb6b", "low": "#82aaff", "info": "#9aa5b1"}

STYLE = """
QMainWindow, QWidget { background: #14181f; color: #e6e9ef; font-family: 'Segoe UI'; font-size: 13px; }
QListWidget { background: #0f1319; border: none; padding: 8px; font-size: 14px; }
QListWidget::item { padding: 10px 12px; border-radius: 6px; }
QListWidget::item:selected { background: #243049; color: #ffffff; }
QPushButton { background: #2f6fed; color: white; border: none; padding: 8px 16px; border-radius: 6px; }
QPushButton:hover { background: #4a84f5; }
QPushButton:disabled { background: #2a3140; color: #7b8494; }
QPushButton#danger { background: #c0392b; }
QTableWidget { background: #0f1319; gridline-color: #232a36; border: 1px solid #232a36; }
QHeaderView::section { background: #1b2230; color: #aab3c2; border: none; padding: 6px; }
QProgressBar { background: #0f1319; border: none; border-radius: 4px; height: 10px; text-align: center; }
QProgressBar::chunk { background: #2f6fed; border-radius: 4px; }
"""


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
        sev.setForeground(QColor(SEV_COLORS[f.severity.value]))
        for c, item in enumerate([sev, QTableWidgetItem(f.module), QTableWidgetItem(f.title),
                                  QTableWidgetItem(f.detail or f.path or "")]):
            t.setItem(r, c, item)
    t.setColumnWidth(0, 80)
    t.setColumnWidth(1, 90)
    t.setColumnWidth(2, 380)


def heading(text: str, sub: str = "") -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 6)
    h = QLabel(text)
    h.setFont(QFont("Segoe UI", 18, QFont.Bold))
    lay.addWidget(h)
    if sub:
        s = QLabel(sub)
        s.setStyleSheet("color:#9aa5b1")
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
    p.setBrush(QColor("#2f6fed"))
    p.setPen(Qt.NoPen)
    p.drawPolygon(QPolygonF([QPointF(32, 4), QPointF(58, 14), QPointF(54, 40), QPointF(32, 60),
                             QPointF(10, 40), QPointF(6, 14)]))
    p.setBrush(QColor("#ffffff"))
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
        p.fillRect(self.rect(), QColor("#0f1319"))
        p.setPen(QColor("#232a36"))
        for v in (0, 50, 100):
            y = int(h - m - (h - 2 * m) * v / 100)
            p.drawLine(m, y, w - m, y)
            p.setPen(QColor("#9aa5b1"))
            p.drawText(2, y + 4, str(v))
            p.setPen(QColor("#232a36"))
        if not self.scores:
            p.setPen(QColor("#9aa5b1"))
            p.drawText(self.rect(), Qt.AlignCenter, "No full checks recorded yet")
            p.end()
            return
        n = len(self.scores)
        pts = [QPointF(m + (w - 2 * m) * (i / (n - 1) if n > 1 else 0.5), h - m - (h - 2 * m) * s / 100)
               for i, s in enumerate(self.scores)]
        p.setPen(QPen(QColor("#2f6fed"), 2))
        for a, b in zip(pts, pts[1:]):
            p.drawLine(a, b)
        p.setBrush(QColor("#2f6fed"))
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
        else:
            self.status.setText("Run a full check from the Dashboard to start your history.")


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
        sev.setForeground(QColor(SEV_COLORS[f.severity.value]))
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


class DashboardPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.addWidget(heading("Dashboard", "Live system health and your overall security score."))
        top = QHBoxLayout()
        self.score = QLabel("--")
        self.score.setFont(QFont("Segoe UI", 54, QFont.Bold))
        self.score.setAlignment(Qt.AlignCenter)
        self.score_caption = QLabel("Run a full check to get your score")
        self.score_caption.setStyleSheet("color:#9aa5b1")
        sc = QVBoxLayout()
        sc.addWidget(self.score)
        sc.addWidget(self.score_caption, alignment=Qt.AlignCenter)
        top.addLayout(sc, 1)
        gauges = QVBoxLayout()
        self.bars = {}
        for name in ("CPU", "Memory", "Disk"):
            row = QHBoxLayout()
            lab = QLabel(name)
            lab.setFixedWidth(60)
            bar = QProgressBar()
            bar.setRange(0, 100)
            row.addWidget(lab)
            row.addWidget(bar)
            gauges.addLayout(row)
            self.bars[name] = bar
        self.admin_lbl = QLabel("Administrator: " + ("yes" if is_admin() else "no (some checks and fixes need it)"))
        self.admin_lbl.setStyleSheet("color:#9aa5b1")
        gauges.addWidget(self.admin_lbl)
        top.addLayout(gauges, 2)
        lay.addLayout(top)
        self.btn = QPushButton("Run full check")
        self.btn.clicked.connect(self.run_check)
        self.status = QLabel("")
        lay.addWidget(self.btn, alignment=Qt.AlignLeft)
        lay.addWidget(self.status)
        self.table = make_table(["Severity", "Module", "Finding", "Detail"])
        lay.addWidget(self.table, 1)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(2000)
        psutil.cpu_percent(None)
        self.tick()

    def tick(self):
        self.bars["CPU"].setValue(int(psutil.cpu_percent(None)))
        self.bars["Memory"].setValue(int(psutil.virtual_memory().percent))
        try:
            self.bars["Disk"].setValue(int(psutil.disk_usage(config.ROOT.anchor or "/").percent))
        except OSError:
            pass

    def run_check(self):
        self.btn.setEnabled(False)
        self.status.setText("Running full check (scanning files, firewall, settings, network)...")
        self.worker = Worker(full_check)
        self.worker.done.connect(self.finish)
        self.worker.failed.connect(self.fail)
        self.worker.start()

    def finish(self, res: ScanResult):
        s = security_score(res.findings)
        self.score.setText(str(s))
        color = "#4cd964" if s >= 85 else "#ffcb6b" if s >= 60 else "#ff5370"
        self.score.setStyleSheet(f"color:{color}")
        prev = res.meta.get("prev_score")
        delta = f" ({s - prev:+d} vs last check)" if prev is not None else ""
        self.score_caption.setText(f"Security score{delta} - {len(res.findings)} finding(s)")
        fill_findings(self.table, res.findings)
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
            sev.setForeground(QColor(SEV_COLORS[f.severity.value]))
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
        if not i:
            return
        try:
            dest = quarantine.restore(i.id)
            QMessageBox.information(self, "Restored", f"Restored to {dest}")
        except quarantine.QuarantineError as e:
            QMessageBox.warning(self, "Restore", str(e))
        self.refresh()

    def delete(self):
        i = self._selected()
        if not i:
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


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"AegisGuard AI {__version__}")
        self.resize(1050, 680)
        root = QWidget()
        self.setCentralWidget(root)
        lay = QHBoxLayout(root)
        lay.setContentsMargins(0, 0, 0, 0)
        self.nav = QListWidget()
        self.nav.setFixedWidth(190)
        self.stack = QStackedWidget()
        self.alerts_page = AlertsPage()
        pages = [
            ("Dashboard", DashboardPage()),
            ("Malware Scan", ModulePage("Malware Scan", "Scans your Downloads and Temp folders for known threats and disguised executables.",
                                        scanner.run, "Run quick scan", allow_quarantine=True)),
            ("Processes", ModulePage("Processes", "Running programs checked for masquerading, look-alike names and suspicious PowerShell (read-only).",
                                     processes.run, "Check processes")),
            ("Network", ModulePage("Network", "Open ports and suspicious connections (read-only).", netmon.run, "Check network")),
            ("Firewall", ModulePage("Firewall", "Windows Firewall profile status.", firewall.run, "Audit firewall")),
            ("Fixes", FixesPage()),
            ("Quarantine", QuarantinePage()),
            ("Disk Cleanup", CleanupPage()),
            ("Alerts", self.alerts_page),
            ("History", HistoryPage()),
            ("Reports", ReportsPage()),
        ]
        for name, page in pages:
            self.nav.addItem(name)
            self.stack.addWidget(page)
        self.nav.currentRowChanged.connect(self._switch)
        self.nav.setCurrentRow(0)
        lay.addWidget(self.nav)
        body = QVBoxLayout()
        body.setContentsMargins(18, 14, 18, 14)
        body.addWidget(self.stack)
        lay.addLayout(body, 1)
        self._setup_protection()

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
            self.tray_menu.addAction("Quit AegisGuard").triggered.connect(self._quit)
            self.tray.setContextMenu(self.tray_menu)
            self.tray.activated.connect(lambda r: self._show_window() if r == QSystemTrayIcon.Trigger else None)
            self.tray.show()
        self.monitor.start()

    def _on_alert(self, f: Finding):
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
            self.monitor.stop()
            self.toggle_action.setText("Resume protection")
        else:
            self.monitor.start()
            self.toggle_action.setText("Pause protection")

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

    def _switch(self, row: int):
        self.stack.setCurrentIndex(row)
        w = self.stack.currentWidget()
        if isinstance(w, (QuarantinePage, HistoryPage)):
            w.refresh()


def launch(start_hidden: bool = False) -> None:
    """Open the app. start_hidden=True (used at sign-in) leaves it in the system tray with protection running."""
    config.ensure_dirs()
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(STYLE)
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
