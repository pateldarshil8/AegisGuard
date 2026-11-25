"""AegisGuard desktop UI (PySide6).

Every action that changes the system (applying a fix, quarantining, deleting) asks for confirmation first.
Long-running checks run on worker threads so the window never freezes.
"""
from __future__ import annotations

import sys

import psutil
from PySide6.QtCore import QThread, QTimer, Qt, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QFont
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QHBoxLayout, QHeaderView, QLabel, QListWidget,
                               QMainWindow, QMessageBox, QProgressBar, QPushButton, QStackedWidget,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from .. import __version__
from ..core import config
from ..core.models import Finding, ScanResult
from ..modules import firewall, fixer, health, netmon, quarantine, reports, scanner

SEV_COLORS = {"critical": "#ff5370", "high": "#ff8a65", "medium": "#ffcb6b", "low": "#82aaff", "info": "#9aa5b1"}
SEV_WEIGHT = {"critical": 30, "high": 15, "medium": 7, "low": 2, "info": 0}

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


def security_score(findings: list[Finding]) -> int:
    return max(0, 100 - sum(SEV_WEIGHT[f.severity.value] for f in findings))


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
    merged = reports.merge([health.run(), scanner.run(), firewall.run(), fixer.run(), netmon.run()])
    reports.write(merged)
    return merged


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
        self.score_caption.setText(f"Security score - {len(res.findings)} finding(s)")
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
        self.worker = Worker(fixer.propose)
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
        msg = f"{fx.finding.title}\n\nThis will run:\n{' '.join(fx.command)}{admin_note}\n\nApply this fix?"
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
        pages = [
            ("Dashboard", DashboardPage()),
            ("Malware Scan", ModulePage("Malware Scan", "Scans your Downloads and Temp folders for known threats and disguised executables.",
                                        scanner.run, "Run quick scan", allow_quarantine=True)),
            ("Network", ModulePage("Network", "Open ports and suspicious connections (read-only).", netmon.run, "Check network")),
            ("Firewall", ModulePage("Firewall", "Windows Firewall profile status.", firewall.run, "Audit firewall")),
            ("Fixes", FixesPage()),
            ("Quarantine", QuarantinePage()),
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

    def _switch(self, row: int):
        self.stack.setCurrentIndex(row)
        w = self.stack.currentWidget()
        if isinstance(w, QuarantinePage):
            w.refresh()


def launch() -> None:
    config.ensure_dirs()
    app = QApplication.instance() or QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    win = MainWindow()
    win.show()
    app.exec()
