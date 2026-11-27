"""Every page of the app except Home, Settings and Updates. Each page loads its data on a worker thread and shows
results as cards. Anything that changes the system asks for the administrator password (if set) and confirms first."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import psutil
from PySide6.QtCore import QPointF, Qt, QThread, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QPainter, QPen
from PySide6.QtWidgets import (QCheckBox, QFileDialog, QFrame, QHBoxLayout, QLabel, QListWidget, QMessageBox, QProgressBar,
                               QPushButton, QTextEdit, QVBoxLayout, QWidget)

from ..core import config, settings
from ..core.models import Finding, ScanResult, Severity
from ..modules import cleanup, firewall, fixer, fwrules, history, netmon, processes, quarantine, remediation, scanner
from . import theme
from .common import (CardList, StatRow, Worker, apply_fix, button, finding_card, full_check, note_label,
                     page_header, panel, require_admin, SEV_RANK)


def _sev_summary(findings: list[Finding]) -> str:
    counts = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    parts = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if counts.get(s)]
    return ", ".join(parts) or "nothing to act on"


def _bars(layout: QVBoxLayout, rows: list[tuple[str, str, int]]):
    """Label + value on one line, a thin bar below. rows: (name, value text, percent)."""
    for name, value, pct in rows:
        line = QHBoxLayout()
        line.addWidget(QLabel(name))
        v = note_label(value)
        v.setAlignment(Qt.AlignRight)
        line.addWidget(v)
        layout.addLayout(line)
        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(pct)
        bar.setTextVisible(False)
        layout.addWidget(bar)


def _clear(layout):
    while layout.count():
        item = layout.takeAt(0)
        if item.widget():
            item.widget().deleteLater()
        elif item.layout():
            _clear(item.layout())


class ScanWorker(QThread):
    """Runs a scan off the UI thread, reporting progress and honouring a stop request."""
    progress = Signal(int, str)
    done = Signal(object)
    failed = Signal(str)

    def __init__(self, mode: str, dirs: list[Path] | None):
        super().__init__()
        self.mode, self.dirs, self._stop = mode, dirs, False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            self.done.emit(scanner.run(self.dirs, self.mode, lambda n, p: self.progress.emit(n, p), lambda: self._stop))
        except Exception as e:
            self.failed.emit(f"{type(e).__name__}: {e}")


class ScanPage(QWidget):
    """Malware scan: choose Quick / Full / Deep / Custom, then review findings as cards."""
    OPTIONS = (
        ("quick", "Quick scan", "Downloads, Desktop, Temp and startup folders. Usually a minute or two."),
        ("full", "Full scan", "Every file on every local drive. Can take an hour or more."),
        ("deep", "Deep scan", "A full scan plus stricter checks: more file types, bigger files, system files. Slowest."),
        ("custom", "Custom scan", "Pick the folders to scan."),
    )

    def __init__(self):
        super().__init__()
        self.mode = "quick"
        self.custom: list[Path] = []
        self.worker: ScanWorker | None = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        self.btn = button("Run scan", self.start)
        self.stop_btn = button("Stop", self.stop, "secondary")
        self.stop_btn.setVisible(False)
        actions = QWidget()
        ah = QHBoxLayout(actions)
        ah.setContentsMargins(0, 0, 0, 0)
        ah.addWidget(self.stop_btn)
        ah.addWidget(self.btn)
        lay.addWidget(page_header("Malware scan", "Looks for known threats, disguised programs and risky scripts. Files "
                                                  "are only read, never changed.", actions))
        opts = QHBoxLayout()
        opts.setSpacing(12)
        self.cards: dict[str, QPushButton] = {}
        for key, title, text in self.OPTIONS:
            b = QPushButton(f"{title}\n{text}")
            b.setObjectName("optioncard")
            b.setCheckable(True)
            b.setMinimumHeight(86)
            b.clicked.connect(lambda _=False, k=key: self.pick(k))
            opts.addWidget(b, 1)
            self.cards[key] = b
        lay.addLayout(opts)
        self.folder_row = QWidget()
        fr = QHBoxLayout(self.folder_row)
        fr.setContentsMargins(0, 0, 0, 0)
        self.folder_label = note_label("No folders chosen.")
        fr.addWidget(self.folder_label, 1)
        fr.addWidget(button("Add folder", self.add_folder, "secondary"))
        fr.addWidget(button("Clear", self.clear_folders, "secondary"))
        lay.addWidget(self.folder_row)
        self.bar = QProgressBar()
        self.bar.setRange(0, 0)
        self.bar.setTextVisible(False)
        self.bar.setVisible(False)
        lay.addWidget(self.bar)
        self.stats = StatRow([("Files scanned", "--", ""), ("Findings", "--", ""), ("Last scan", "--", "")])
        lay.addWidget(self.stats)
        body = QHBoxLayout()
        body.setSpacing(18)
        self.list = CardList("Choose a scan type and press Run scan.")
        body.addWidget(self.list, 2)
        side, self.side_lay = panel("What gets scanned")
        self.side_text = note_label("")
        self.side_lay.addWidget(self.side_text)
        self.side_lay.addStretch(1)
        self.side_lay.addWidget(note_label("The quarantine folder and your exclusions are always skipped. Quarantining "
                                           "asks first and can be undone.", "mute"))
        body.addWidget(side, 1)
        lay.addLayout(body, 1)
        self.pick("quick")

    def pick(self, mode: str):
        self.mode = mode
        for k, b in self.cards.items():
            b.setChecked(k == mode)
        self.folder_row.setVisible(mode == "custom")
        self._describe()

    def _describe(self):
        if self.mode == "quick":
            lines = [str(d) for d in config.QUICK_SCAN_DIRS]
        elif self.mode == "custom":
            lines = [str(d) for d in self.custom] or ["Add at least one folder."]
        else:
            lines = [str(d) for d in scanner.fixed_drives()]
            if self.mode == "full":
                lines.append("(Windows\\WinSxS is left out; the deep scan includes it.)")
        self.side_text.setText("\n".join("\u25cf  " + x if not x.startswith("(") else x for x in lines))
        excl = len(settings.load().exclusions)
        self.stats._notes[0].setText(f"{excl} exclusion(s)")

    def add_folder(self):
        d = QFileDialog.getExistingDirectory(self, "Choose a folder to scan")
        if d and Path(d) not in self.custom:
            self.custom.append(Path(d))
            self.folder_label.setText("; ".join(str(c) for c in self.custom))
            self._describe()

    def clear_folders(self):
        self.custom = []
        self.folder_label.setText("No folders chosen.")
        self._describe()

    def start(self):
        if self.mode == "custom" and not self.custom:
            QMessageBox.information(self, "Custom scan", "Add at least one folder first.")
            return
        if self.mode in ("full", "deep") and QMessageBox.question(
                self, "Start scan?", f"A {self.mode} scan reads every file on your drives and can take a long time. "
                "You can keep using AegisGuard and press Stop at any time.\n\nStart now?") != QMessageBox.Yes:
            return
        self._busy(True)
        self.list.clear()
        self.list.set_empty("Scanning...")
        self.worker = ScanWorker(self.mode, self.custom if self.mode == "custom" else None)
        self.worker.progress.connect(self.on_progress)
        self.worker.done.connect(self.finish)
        self.worker.failed.connect(self.fail)
        self.worker.start()

    def stop(self):
        if self.worker:
            self.worker.stop()
            self.stop_btn.setEnabled(False)
            self.stop_btn.setText("Stopping...")

    def _busy(self, on: bool):
        self.btn.setEnabled(not on)
        self.stop_btn.setVisible(on)
        self.stop_btn.setEnabled(True)
        self.stop_btn.setText("Stop")
        self.bar.setVisible(on)
        for b in self.cards.values():
            b.setEnabled(not on)

    def on_progress(self, n: int, path: str):
        self.stats.set(0, f"{n:,}", path[-60:] if path else "")

    def finish(self, res: ScanResult):
        self._busy(False)
        self.list.clear()
        for f in sorted(res.findings, key=lambda f: SEV_RANK[f.severity.value]):
            ref = [None]
            btns = []
            if f.path:
                btns.append(button("Quarantine", lambda f=f, ref=ref: self._quarantine(f, ref[0])))
            btns.append(button("Ignore", lambda ref=ref: self.list.drop(ref[0]), "secondary"))
            ref[0] = finding_card(f.to_dict(), btns)
            self.list.add(ref[0])
        stopped = res.meta.get("stopped")
        self.list.set_empty("Scan stopped before any threats were found." if stopped else "No threats found.")
        self.stats.set(0, f"{res.meta.get('files_scanned', 0):,}", "stopped early" if stopped else "complete")
        self.stats.set(1, str(len(res.findings)), _sev_summary(res.findings))
        self.stats.set(2, datetime.now().strftime("%H:%M"), scanner.MODES.get(res.meta.get("mode", ""), ""))

    def fail(self, msg: str):
        self._busy(False)
        self.list.clear()
        self.list.set_empty(f"Scan failed: {msg}")

    def _quarantine(self, f: Finding, card: QFrame):
        if not require_admin(self):
            return
        if QMessageBox.question(self, "Quarantine file?",
                                f"Move this file to quarantine?\n\n{f.path}\n\nYou can restore it later.") != QMessageBox.Yes:
            return
        try:
            quarantine.quarantine_file(f.path, f.title)
        except quarantine.QuarantineError as e:
            QMessageBox.warning(self, "Quarantine", str(e))
            return
        self.list.drop(card)
        QMessageBox.information(self, "Quarantine", "File quarantined. You can restore it from Vault.")


class ProcessesPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        self.btn = button("Check processes", self.start)
        lay.addWidget(page_header("Processes", "Running programs checked for fake system names, look-alike names, "
                                               "programs started from Temp, and suspicious PowerShell. Read-only.", self.btn))
        self.stats = StatRow([("Programs running", "--", ""), ("Flagged", "--", ""), ("Highest", "--", "")])
        lay.addWidget(self.stats)
        body = QHBoxLayout()
        body.setSpacing(18)
        self.list = CardList("Press Check processes to look at what is running now.")
        body.addWidget(self.list, 2)
        side, self.side_lay = panel("Busiest programs")
        self.side_lay.addStretch(1)
        body.addWidget(side, 1)
        lay.addLayout(body, 1)

    @staticmethod
    def _collect():
        res = processes.run()
        mem: dict[str, int] = {}
        for p in psutil.process_iter(["name", "memory_info"]):
            try:
                mi = p.info["memory_info"]
                name = p.info["name"] or "?"
                mem[name] = mem.get(name, 0) + (mi.rss if mi else 0)
            except (psutil.Error, OSError):
                continue
        busy = sorted(mem.items(), key=lambda kv: kv[1], reverse=True)[:5]
        return res, busy, len(psutil.pids())

    def start(self):
        self.btn.setEnabled(False)
        self.list.clear()
        self.list.set_empty("Checking...")
        self.worker = Worker(self._collect)
        self.worker.done.connect(self.finish)
        self.worker.failed.connect(lambda m: (self.list.set_empty(f"Failed: {m}"), self.btn.setEnabled(True)))
        self.worker.start()

    def finish(self, result):
        res, busy, total = result
        self.list.clear()
        for f in sorted(res.findings, key=lambda f: SEV_RANK[f.severity.value]):
            d = f.to_dict()
            self.list.add(finding_card(d, [button("Details", lambda d=d: self._details(d), "secondary")]))
        self.list.set_empty("No suspicious programs found.")
        top = min(res.findings, key=lambda f: SEV_RANK[f.severity.value]).severity.value if res.findings else "none"
        self.stats.set(0, str(total), "running now")
        self.stats.set(1, str(len(res.findings)), _sev_summary(res.findings))
        self.stats.set(2, top.capitalize(), "")
        _clear(self.side_lay)
        title = QLabel("Busiest programs")
        title.setObjectName("cardtitle")
        self.side_lay.addWidget(title)
        peak = max((b for _, b in busy), default=1) or 1
        _bars(self.side_lay, [(n, cleanup.human(b), int(b * 100 / peak)) for n, b in busy])
        self.side_lay.addStretch(1)
        self.btn.setEnabled(True)

    def _details(self, d: dict):
        QMessageBox.information(self, d["title"], "\n\n".join(x for x in (d.get("detail"), d.get("path"), d.get("remediation")) if x))


class NetworkPage(QWidget):
    navigate = Signal(str, object)

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        self.btn = button("Check network", self.start)
        lay.addWidget(page_header("Network", "Open ports and connections, with the program behind each one. Read-only: a "
                                             "block is only suggested when a program from Temp reaches the internet.", self.btn))
        self.stats = StatRow([("Open ports", "--", "listening"), ("Connections", "--", "established"), ("Flagged", "--", "")])
        lay.addWidget(self.stats)
        body = QHBoxLayout()
        body.setSpacing(18)
        self.list = CardList("Press Check network to list open ports.")
        body.addWidget(self.list, 2)
        side, self.side_lay = panel("Outbound watch")
        self.side_lay.addWidget(note_label("Nothing checked yet."))
        self.side_lay.addStretch(1)
        link = button("Open firewall rules", lambda: self.navigate.emit("network", 1), "secondary")
        self.side_lay.addWidget(link)
        body.addWidget(side, 1)
        lay.addLayout(body, 1)

    @staticmethod
    def _collect():
        conns = netmon.collect()
        return netmon.analyze(conns), conns

    def start(self):
        self.btn.setEnabled(False)
        self.list.clear()
        self.list.set_empty("Checking...")
        self.worker = Worker(self._collect)
        self.worker.done.connect(self.finish)
        self.worker.failed.connect(lambda m: (self.list.set_empty(f"Failed: {m}"), self.btn.setEnabled(True)))
        self.worker.start()

    @staticmethod
    def _risk(port: int, proc: str) -> str:
        if port not in netmon.RISKY_LISTEN_PORTS:
            return "info"
        return "low" if (port, proc.lower()) in netmon.DEFAULT_WINDOWS_LISTENERS else "medium"

    def finish(self, result):
        res, conns = result
        listeners: dict[tuple[int, str], str] = {}
        for c in conns:
            if c.status == "LISTEN":
                listeners.setdefault((c.laddr_port, c.proc or "System"), c.laddr_ip)
        rows = sorted(listeners.items(), key=lambda kv: (SEV_RANK[self._risk(kv[0][0], kv[0][1])], kv[0][0]))
        self.list.clear()
        for (port, proc), ip in rows[:30]:
            risk = self._risk(port, proc)
            reach = "This PC only" if ip in ("127.0.0.1", "::1") else "Local network and beyond"
            what = netmon.RISKY_LISTEN_PORTS.get(port, "")
            d = {"severity": risk, "title": f"Port {port}  ·  {proc}", "detail": f"{what + '  ·  ' if what else ''}{reach}"}
            self.list.add(finding_card(d, []))
        self.list.set_empty("No open ports.")
        established = sum(1 for c in conns if c.status == "ESTABLISHED")
        self.stats.set(0, str(len(listeners)))
        self.stats.set(1, str(established))
        self.stats.set(2, str(len(res.findings)), _sev_summary(res.findings))
        _clear(self.side_lay)
        title = QLabel("Outbound watch")
        title.setObjectName("cardtitle")
        self.side_lay.addWidget(title)
        high = [f for f in res.findings if f.severity == Severity.HIGH]
        if high:
            for f in high[:4]:
                self.side_lay.addWidget(note_label("●  " + f.title + (f"\n    {f.path}" if f.path else "")))
        else:
            self.side_lay.addWidget(note_label("●  No program from Temp or Downloads talks to the internet."))
        self.side_lay.addWidget(note_label("●  Listening ports are rated from the Windows defaults. Low means a normal "
                                           "Windows service."))
        self.side_lay.addStretch(1)
        self.side_lay.addWidget(button("Open firewall rules", lambda: self.navigate.emit("network", 1), "secondary"))
        self.btn.setEnabled(True)


class FirewallPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        self.btn = button("Audit firewall", self.load)
        lay.addWidget(page_header("Firewall", "Windows Firewall status and the rules AegisGuard has added. Blocks are only "
                                              "created after you approve them.", self.btn))
        self.stats = StatRow([("Domain", "--", "work or school"), ("Private", "--", "home"), ("Public", "--", "cafes, airports")])
        lay.addWidget(self.stats)
        body = QHBoxLayout()
        body.setSpacing(18)
        left, self.rules_lay = panel("Blocked by AegisGuard")
        self.rules_lay.addWidget(note_label("Press Audit firewall to load."))
        self.rules_lay.addStretch(1)
        right, self.sugg_lay = panel("Suggested blocks")
        self.sugg_lay.addWidget(note_label("Press Audit firewall to load."))
        self.sugg_lay.addStretch(1)
        body.addWidget(left, 3)
        body.addWidget(right, 2)
        lay.addLayout(body, 1)

    @staticmethod
    def _collect():
        return firewall.profile_states(), fwrules.list_rules(), fwrules.propose_blocks(netmon.run().findings)

    def load(self):
        self.btn.setEnabled(False)
        self.worker = Worker(self._collect)
        self.worker.done.connect(self.finish)
        self.worker.failed.connect(lambda m: (self.stats.set(0, "?", m), self.btn.setEnabled(True)))
        self.worker.start()

    def finish(self, result):
        states, rules, proposals = result
        pal = theme.current()
        for i, name in enumerate(("Domain", "Private", "Public")):
            s = (states or {}).get(name)
            self.stats.set(i, "On" if s and s.upper() == "ON" else "Off" if s else "Unknown")
            self.stats._values[i].setStyleSheet("" if s and s.upper() == "ON" else f"color:{pal['warn']};")
        _clear(self.rules_lay)
        title = QLabel("Blocked by AegisGuard")
        title.setObjectName("cardtitle")
        self.rules_lay.addWidget(title)
        if not rules:
            self.rules_lay.addWidget(note_label("No AegisGuard block rules are active."))
        for name in rules:
            self.rules_lay.addWidget(self._row(name, [button("Remove", lambda n=name: self._remove(n), "secondary")]))
        self.rules_lay.addStretch(1)
        self.rules_lay.addWidget(note_label("Only rules named AegisGuard Block can be removed here. Your other rules are never touched.", "mute"))
        _clear(self.sugg_lay)
        title2 = QLabel("Suggested blocks")
        title2.setObjectName("cardtitle")
        self.sugg_lay.addWidget(title2)
        if not proposals:
            self.sugg_lay.addWidget(note_label("Nothing to suggest right now. A block is suggested when a program running "
                                               "from Temp connects to the public internet."))
        for fx in proposals:
            self.sugg_lay.addWidget(self._row(fx.finding.path or fx.finding.title,
                                              [button("Review and apply", lambda fx=fx: self._apply(fx))]))
        self.sugg_lay.addStretch(1)
        self.btn.setEnabled(True)

    @staticmethod
    def _row(text: str, buttons: list[QPushButton]) -> QFrame:
        box = QFrame()
        box.setObjectName("inset")
        h = QHBoxLayout(box)
        h.setContentsMargins(12, 8, 12, 8)
        h.addWidget(note_label(text, "sub"), 1)
        for b in buttons:
            h.addWidget(b)
        return box

    def _apply(self, fx):
        if apply_fix(self, fx):
            self.load()

    def _remove(self, name: str):
        if not require_admin(self):
            return
        try:
            cmd = fwrules.remove_command(name)
        except fwrules.RuleError as e:
            QMessageBox.warning(self, "Firewall", str(e))
            return
        if QMessageBox.question(self, "Remove rule?", f"Remove this firewall rule?\n\n{name}") != QMessageBox.Yes:
            return
        fx = fixer.Fix(Finding("firewall", f"Remove {name}", Severity.INFO), "Remove an AegisGuard block rule.", cmd, True)
        ok, out = fixer.apply(fx, approved=True)
        (QMessageBox.information if ok else QMessageBox.warning)(self, "Firewall", "Rule removed." if ok else out)
        self.load()


class FixesPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        self.btn = button("Re-check settings", self.start)
        lay.addWidget(page_header("Fixes", "Risky Windows settings AegisGuard can correct. Nothing changes until you read "
                                           "the exact command and approve it.", self.btn))
        banner = QFrame()
        banner.setObjectName("inset")
        bl = QHBoxLayout(banner)
        bl.setContentsMargins(16, 10, 16, 10)
        bl.addWidget(note_label("Applying a fix asks for your AegisGuard administrator password (if one is set), then "
                                "Windows asks for permission."))
        lay.addWidget(banner)
        self.list = CardList("Press Re-check settings to look for fixable problems.")
        lay.addWidget(self.list, 1)

    def start(self):
        self.btn.setEnabled(False)
        self.list.clear()
        self.list.set_empty("Checking...")
        self.worker = Worker(remediation.propose_all)
        self.worker.done.connect(self.finish)
        self.worker.failed.connect(lambda m: (self.list.set_empty(f"Failed: {m}"), self.btn.setEnabled(True)))
        self.worker.start()

    def finish(self, result):
        res, fixes = result
        by_finding = {id(fx.finding): fx for fx in fixes}
        self.list.clear()
        for f in sorted(res.findings, key=lambda f: SEV_RANK[f.severity.value]):
            fx = by_finding.get(id(f))
            ref = [None]
            btns = []
            if fx:
                btns.append(button("Review and apply", lambda fx=fx: apply_fix(self, fx)))
            btns.append(button("Skip", lambda ref=ref: self.list.drop(ref[0]), "secondary"))
            box = finding_card(f.to_dict(), btns, f.remediation)
            ref[0] = box
            if fx:
                code = QLabel(" ".join(fx.command) + ("   (+%d more)" % len(fx.extra_commands) if fx.extra_commands else ""))
                code.setObjectName("code")
                code.setWordWrap(True)
                code.setTextInteractionFlags(Qt.TextSelectableByMouse)
                box.layout().itemAt(0).layout().addWidget(code)
            self.list.add(box)
        self.list.set_empty("No issues found.")
        self.btn.setEnabled(True)


class QuarantinePage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        lay.addWidget(page_header("Vault", "Files AegisGuard moved aside. They cannot run from here. Restore one if it was "
                                           "safe, or delete it for good.", button("Refresh", self.refresh, "secondary")))
        body = QHBoxLayout()
        body.setSpacing(18)
        self.list = CardList("Nothing is in quarantine.")
        body.addWidget(self.list, 2)
        side, sv = panel("How it works")
        for t in ("The file is renamed and moved, so it cannot start.", "Restore puts it back exactly where it was.",
                  "Delete forever cannot be undone, so it asks you to confirm.", "Windows and Program Files are never quarantined."):
            sv.addWidget(note_label("●  " + t))
        sv.addStretch(1)
        body.addWidget(side, 1)
        lay.addLayout(body, 1)
        self.refresh()

    def refresh(self):
        self.list.clear()
        for i in quarantine.list_items():
            box = QFrame()
            box.setObjectName("card")
            h = QHBoxLayout(box)
            h.setContentsMargins(18, 14, 18, 14)
            h.setSpacing(16)
            info = QVBoxLayout()
            info.setSpacing(4)
            name = QLabel(Path(i.original_path).name or i.original_path)
            name.setObjectName("cardtitle")
            info.addWidget(name)
            info.addWidget(note_label("Was in " + str(Path(i.original_path).parent)))
            info.addWidget(note_label(f"{i.quarantined_at}  ·  {i.reason}", "mute"))
            h.addLayout(info, 1)
            h.addWidget(button("Restore", lambda i=i: self.restore(i), "secondary"))
            h.addWidget(button("Delete forever", lambda i=i: self.delete(i), "danger"))
            self.list.add(box)
        self.list.set_empty("Nothing is in quarantine.")

    def restore(self, i):
        if not require_admin(self):
            return
        try:
            dest = quarantine.restore(i.id)
            QMessageBox.information(self, "Restored", f"Restored to {dest}")
        except quarantine.QuarantineError as e:
            QMessageBox.warning(self, "Restore", str(e))
        self.refresh()

    def delete(self, i):
        if not require_admin(self):
            return
        if QMessageBox.question(self, "Delete permanently?",
                                f"Permanently delete the quarantined copy of\n{i.original_path}?\nThis cannot be undone.") != QMessageBox.Yes:
            return
        quarantine.delete(i.id)
        self.refresh()


class CleanupPage(QWidget):
    def __init__(self):
        super().__init__()
        self.cands: list[cleanup.Candidate] = []
        self.checks: dict[str, QCheckBox] = {}
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        self.find_btn = button("Find files to clean", self.find)
        lay.addWidget(page_header("Disk cleanup", "Frees space by removing temporary files Windows does not need. You see "
                                                  "the list and the total before anything is deleted.", self.find_btn))
        body = QHBoxLayout()
        body.setSpacing(18)
        left, lv = panel("Safe to remove")
        self.rows = QVBoxLayout()
        self.rows.setSpacing(8)
        self.rows.addWidget(note_label("Press Find files to clean."))
        lv.addLayout(self.rows)
        lv.addStretch(1)
        self.status = note_label("")
        lv.addWidget(self.status)
        self.clean_btn = button("Delete selected", self.clean, "danger")
        self.clean_btn.setEnabled(False)
        lv.addWidget(self.clean_btn, alignment=Qt.AlignRight)
        body.addWidget(left, 3)
        right, rv = panel("Drive C:")
        self.pct = QLabel("--")
        self.pct.setObjectName("stat")
        self.disk_note = note_label("")
        self.disk_bar = QProgressBar()
        self.disk_bar.setRange(0, 100)
        self.disk_bar.setTextVisible(False)
        rv.addWidget(self.pct)
        rv.addWidget(self.disk_bar)
        rv.addWidget(self.disk_note)
        cap = QLabel("BIGGEST FOLDERS")
        cap.setObjectName("caps")
        rv.addSpacing(6)
        rv.addWidget(cap)
        self.big = QVBoxLayout()
        self.big.addWidget(note_label("Press the button below to measure your user folder."))
        rv.addLayout(self.big)
        rv.addStretch(1)
        self.space_btn = button("Where is my space going?", self.space, "secondary")
        rv.addWidget(self.space_btn)
        body.addWidget(right, 2)
        lay.addLayout(body, 1)
        self._disk()

    def _disk(self):
        try:
            u = psutil.disk_usage(config.ROOT.anchor or "/")
        except OSError:
            return
        p = int(u.percent)
        self.pct.setText(f"{p}%")
        self.disk_bar.setValue(p)
        level = "warn" if p >= 90 else ""
        self.disk_bar.setProperty("level", level)
        self.disk_bar.style().unpolish(self.disk_bar)
        self.disk_bar.style().polish(self.disk_bar)
        self.disk_note.setText(f"{cleanup.human(u.used)} used of {cleanup.human(u.total)}")

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
        _clear(self.rows)
        self.checks = {}
        for cat, (n, b) in summary.items():
            row = QFrame()
            row.setObjectName("inset")
            h = QHBoxLayout(row)
            h.setContentsMargins(12, 8, 12, 8)
            cb = QCheckBox(f"{cat}  ·  {n} file(s)")
            cb.setChecked(True)
            cb.stateChanged.connect(lambda _=0: self._update_total())
            h.addWidget(cb, 1)
            h.addWidget(QLabel(cleanup.human(b)))
            self.rows.addWidget(row)
            self.checks[cat] = cb
        if not cands:
            self.rows.addWidget(note_label("Nothing to clean."))
        self._summary = summary
        self._update_total()
        self.find_btn.setEnabled(True)

    def _selected(self) -> list[cleanup.Candidate]:
        keep = {c for c, cb in self.checks.items() if cb.isChecked()}
        return [c for c in self.cands if c.category in keep]

    def _update_total(self):
        chosen = self._selected()
        total = sum(c.size for c in chosen)
        self.status.setText(f"{cleanup.human(total)} selected from {len(chosen)} file(s). Files in use are skipped. "
                            "Deleted files do not go to the Recycle Bin." if self.cands else "")
        self.clean_btn.setText(f"Delete {cleanup.human(total)}" if chosen else "Delete selected")
        self.clean_btn.setEnabled(bool(chosen))

    def clean(self):
        if not require_admin(self):
            return
        chosen = self._selected()
        total = sum(c.size for c in chosen)
        if QMessageBox.question(self, "Delete files?",
                                f"Permanently delete {len(chosen)} temp/cache file(s) ({cleanup.human(total)})?\n"
                                "Files that are in use will be skipped. This cannot be undone.") != QMessageBox.Yes:
            return
        freed, deleted, failed = cleanup.clean(chosen, approved=True)
        self.cands = []
        _clear(self.rows)
        self.rows.addWidget(note_label(f"Freed {cleanup.human(freed)} ({deleted} deleted, {failed} skipped)."))
        self.status.setText("")
        self.clean_btn.setEnabled(False)
        self.clean_btn.setText("Delete selected")
        self._disk()

    def space(self):
        self.space_btn.setEnabled(False)
        _clear(self.big)
        self.big.addWidget(note_label("Measuring your user folder (up to 45 seconds)..."))
        self.worker2 = Worker(lambda: cleanup.largest_items(Path.home()))
        self.worker2.done.connect(self._space_done)
        self.worker2.failed.connect(lambda m: (_clear(self.big), self.big.addWidget(note_label(m)), self.space_btn.setEnabled(True)))
        self.worker2.start()

    def _space_done(self, result):
        items, complete = result
        _clear(self.big)
        peak = max((s for _, s in items), default=1) or 1
        _bars(self.big, [(Path(p).name or p, cleanup.human(s), int(s * 100 / peak)) for p, s in items[:5]])
        if not complete:
            self.big.addWidget(note_label("Stopped at the time limit; sizes may be low.", "mute"))
        self.space_btn.setEnabled(True)


class AlertsPage(QWidget):
    """Live alerts from the background monitor, newest first."""
    FILTERS = (("all", "All"), ("high", "High"), ("medium", "Medium"), ("low", "Low"))

    def __init__(self):
        super().__init__()
        self.entries: list[tuple[dict, QFrame]] = []
        self.mode = "all"
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        lay.addWidget(page_header("Alerts", "Live alerts from background protection while AegisGuard is running. It only "
                                            "watches and tells you; it never changes anything on its own. Also saved to "
                                            "data\\alerts.log."))
        bar = QHBoxLayout()
        bar.setSpacing(6)
        self.filter_btns: dict[str, QPushButton] = {}
        for key, label in self.FILTERS:
            b = QPushButton(label)
            b.setObjectName("tab")
            b.setCheckable(True)
            b.clicked.connect(lambda _=False, k=key: self._set_filter(k))
            bar.addWidget(b)
            self.filter_btns[key] = b
        bar.addStretch(1)
        lay.addLayout(bar)
        body = QHBoxLayout()
        body.setSpacing(18)
        self.list = CardList("No alerts yet. Protection is watching in the background.")
        body.addWidget(self.list, 2)
        side, sv = panel("Protection")
        s = settings.load()
        for name, every in (("New files", f"every {s.file_poll_seconds} s"), ("Running programs", f"every {s.process_seconds} s"),
                            ("Network", f"every {s.network_seconds} s"), ("Threat signatures", "every 6 h")):
            row = QHBoxLayout()
            row.addWidget(note_label(name))
            v = QLabel(every)
            v.setAlignment(Qt.AlignRight)
            row.addWidget(v)
            sv.addLayout(row)
        sv.addStretch(1)
        sv.addWidget(note_label(f"Alerts show at {s.min_alert_severity} and above.", "mute"))
        body.addWidget(side, 1)
        lay.addLayout(body, 1)
        self._set_filter("all")

    def _matches(self, sev: str) -> bool:
        return self.mode == "all" or (self.mode == "high" and sev in ("critical", "high")) or sev == self.mode

    def _set_filter(self, key: str):
        self.mode = key
        for k, b in self.filter_btns.items():
            b.setChecked(k == key)
        for d, box in self.entries:
            box.setVisible(self._matches(d["severity"]))
        self._counts()

    def _counts(self):
        for key, label in self.FILTERS:
            n = sum(1 for d, _ in self.entries if key == "all" or (key == "high" and d["severity"] in ("critical", "high"))
                    or d["severity"] == key)
            self.filter_btns[key].setText(f"{label} {n}" if n else label)

    def add(self, f: Finding):
        d = f.to_dict()
        box = finding_card(d, [], datetime.now().strftime("%H:%M:%S"))
        self.list.add(box, top=True)
        self.entries.insert(0, (d, box))
        box.setVisible(self._matches(d["severity"]))
        if len(self.entries) > 200:
            _, old = self.entries.pop()
            self.list.drop(old)
        self._counts()


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
        pal = theme.current()
        w, h, m = self.width(), self.height(), 26
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
        p.setPen(QPen(QColor(pal["accent"]), 3))
        for a, b in zip(pts, pts[1:]):
            p.drawLine(a, b)
        p.setBrush(QColor(pal["accent"]))
        for pt in pts:
            p.drawEllipse(pt, 4, 4)
        p.end()


class HistoryPage(QWidget):
    run_requested = Signal()

    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        lay.addWidget(page_header("History", "Your security score over time, and what changed since the last check.",
                                  button("Run full check", self.run_requested.emit)))
        top = QHBoxLayout()
        top.setSpacing(18)
        chart, cv = panel("Security score")
        self.trend = TrendWidget()
        cv.addWidget(self.trend)
        top.addWidget(chart, 2)
        side, self.changes = panel("Since last check")
        top.addWidget(side, 1)
        lay.addLayout(top)
        self.list = CardList("Run a full check from Home to start your history.")
        lay.addWidget(self.list, 1)
        self.refresh()

    def refresh(self):
        runs = history.recent(30)
        self.trend.set_scores([r.score for r in reversed(runs)])
        _clear(self.changes)
        title = QLabel("Since last check")
        title.setObjectName("cardtitle")
        self.changes.addWidget(title)
        if len(runs) >= 2:
            new, resolved = history.changes(runs[1], runs[0])
            self.changes.addWidget(note_label(f"Score: {runs[0].score} ({runs[0].score - runs[1].score:+d})"))
            self.changes.addWidget(note_label(f"New findings: {len(new)}"))
            self.changes.addWidget(note_label(f"Resolved: {len(resolved)}"))
            for d in new[:2]:
                self.changes.addWidget(note_label("+ " + d["title"], "mute"))
            for d in resolved[:2]:
                self.changes.addWidget(note_label("- " + d["title"], "mute"))
        elif runs:
            self.changes.addWidget(note_label("Run another full check to see what changed."))
        else:
            self.changes.addWidget(note_label("No checks yet."))
        self.changes.addStretch(1)
        self.list.clear()
        for i, run in enumerate(runs[:30]):
            box = QFrame()
            box.setObjectName("inset")
            h = QHBoxLayout(box)
            h.setContentsMargins(16, 10, 16, 10)
            c = run.counts
            when = QLabel(run.started.replace("T", "  "))
            score = QLabel(str(run.score))
            score.setObjectName("cardtitle")
            counts = note_label(f"{c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low")
            nxt = runs[i + 1].score if i + 1 < len(runs) else None
            delta = QLabel("" if nxt is None else f"{run.score - nxt:+d}")
            delta.setAlignment(Qt.AlignRight)
            h.addWidget(when, 3)
            h.addWidget(score, 1)
            h.addWidget(counts, 4)
            h.addWidget(delta, 1)
            self.list.add(box)
        self.list.set_empty("Run a full check from Home to start your history.")


class ReportsPage(QWidget):
    def __init__(self):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        self.gen = button("Generate report", self.generate)
        lay.addWidget(page_header("Reports", "Every full check can be saved as a readable report and a data file. Reports "
                                             "stay on this PC.", self.gen))
        body = QHBoxLayout()
        body.setSpacing(18)
        self.list = QListWidget()
        self.list.currentTextChanged.connect(self._show)
        body.addWidget(self.list, 1)
        right, rv = panel()
        top = QHBoxLayout()
        self.title = QLabel("")
        self.title.setObjectName("cardtitle")
        top.addWidget(self.title, 1)
        top.addWidget(button("Open file", self.open_current, "secondary"))
        top.addWidget(button("Open folder", lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(config.REPORTS_DIR))), "secondary"))
        rv.addLayout(top)
        self.preview = QTextEdit()
        self.preview.setObjectName("preview")
        self.preview.setReadOnly(True)
        self.preview.setPlaceholderText("Pick a report on the left.")
        rv.addWidget(self.preview, 1)
        body.addWidget(right, 2)
        lay.addLayout(body, 1)
        self.refresh()

    def refresh(self):
        self.list.clear()
        config.ensure_dirs()
        for p in sorted(config.REPORTS_DIR.glob("report-*.md"), reverse=True):
            self.list.addItem(p.name)
        if self.list.count():
            self.list.setCurrentRow(0)

    def _show(self, name: str):
        if not name:
            return
        self.title.setText(name)
        try:
            self.preview.setPlainText((config.REPORTS_DIR / name).read_text(encoding="utf-8")[:30000])
        except OSError as e:
            self.preview.setPlainText(str(e))

    def open_current(self):
        item = self.list.currentItem()
        if item:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(config.REPORTS_DIR / item.text())))

    def generate(self):
        self.gen.setEnabled(False)
        self.worker = Worker(full_check)
        self.worker.done.connect(lambda _: (self.refresh(), self.gen.setEnabled(True)))
        self.worker.failed.connect(lambda m: (QMessageBox.warning(self, "Report", m), self.gen.setEnabled(True)))
        self.worker.start()
