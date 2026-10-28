"""Hauptfenster: Drop-Zone („Magic Box“), Auftragsliste, Doku-Vorschau, Live-Protokoll."""

from __future__ import annotations

import itertools
from pathlib import Path

from PySide6.QtCore import QSize, Qt, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QFont, QFontDatabase
from PySide6.QtWidgets import (
    QFileDialog, QFrame, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QMainWindow, QMessageBox,
    QPlainTextEdit, QProgressBar, QPushButton, QSplitter, QTabWidget, QTextBrowser, QVBoxLayout, QWidget,
)

from magicbox import __version__
from magicbox.config import Settings
from magicbox.llm.client import LLMClient
from magicbox.report.builder import build_qt_html

from .settings_dialog import SettingsDialog
from .workers import FuncWorker, Job, JobWorker

STATUS_ICON = {"wartet": "⏳", "läuft": "⚙️", "fertig": "✅", "fehler": "❌", "abgebrochen": "⛔"}

WELCOME = """
<h2>Willkommen bei der Magic Box 🪄</h2>
<p>Zieh eine Datei oder einen Ordner auf die Box links – oder klick drauf.</p>
<ol>
<li><b>Statische Analyse</b>: Dateityp, Header, Imports/Exports, Strings, Archive (rekursiv),
Disassembly/Pseudocode, Quelltext-Struktur. Die Datei wird <i>niemals ausgeführt</i>.</li>
<li><b>KI-Dokumentation</b>: Die Fakten gehen an dein lokales LLM (z.&nbsp;B. Ollama auf dem R640) –
nichts verlässt dein Netzwerk.</li>
<li><b>Bericht</b>: Verständliche Doku + technischer Anhang als HTML, Markdown und JSON.</li>
</ol>
<p>Unterstützt u.&nbsp;a.: Windows EXE/DLL/SYS (.NET erkannt), Linux ELF, macOS Mach-O, Java .class/.jar,
Android APK, ZIP/TAR/GZ/XZ/BZ2, Office-Dokumente, PDF sowie Quelltext/Skripte (Python, JS, PowerShell, C, …).</p>
"""


class DropZone(QFrame):
    dropped = Signal(list)
    clicked = Signal()

    def __init__(self):
        super().__init__()
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(190)
        lay = QVBoxLayout(self)
        lay.setAlignment(Qt.AlignCenter)
        icon = QLabel("🪄📦")
        icon.setAlignment(Qt.AlignCenter)
        icon.setStyleSheet("font-size: 46px; background: transparent;")
        title = QLabel("Datei hier reinwerfen")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 17px; font-weight: 600; background: transparent;")
        hint = QLabel("oder klicken zum Auswählen\nEXE · DLL · ELF · APK · JAR · ZIP · Skripte · Ordner …")
        hint.setAlignment(Qt.AlignCenter)
        hint.setStyleSheet("color: #7c7a99; background: transparent;")
        for w in (icon, title, hint):
            lay.addWidget(w)

    def _highlight(self, on: bool) -> None:
        self.setProperty("hover", on)
        self.style().unpolish(self)
        self.style().polish(self)

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._highlight(True)

    def dragLeaveEvent(self, e):
        self._highlight(False)

    def dropEvent(self, e):
        self._highlight(False)
        paths = [Path(u.toLocalFile()) for u in e.mimeData().urls() if u.isLocalFile()]
        if paths:
            self.dropped.emit(paths)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.LeftButton:
            self.clicked.emit()


class MainWindow(QMainWindow):
    def __init__(self, settings: Settings):
        super().__init__()
        self.settings = settings
        self.jobs: dict[int, Job] = {}
        self.queue: list[int] = []
        self.worker: JobWorker | None = None
        self._ids = itertools.count(1)
        self._check_worker: FuncWorker | None = None
        self.setWindowTitle(f"Magic Box {__version__} – Reverse Engineering → Doku")
        self.resize(1320, 840)
        self.setAcceptDrops(True)
        self._build()
        self._refresh_llm_label()
        self.check_connection(silent=True)

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        # Linke Spalte: Drop-Zone, Aufträge, Knöpfe
        self.drop = DropZone()
        self.drop.dropped.connect(self.add_paths)
        self.drop.clicked.connect(self.choose_files)

        self.job_list = QListWidget()
        self.job_list.setIconSize(QSize(16, 16))
        self.job_list.currentItemChanged.connect(self._show_selected)

        btn_files = QPushButton("📄 Dateien …")
        btn_dir = QPushButton("📁 Ordner …")
        btn_files.clicked.connect(self.choose_files)
        btn_dir.clicked.connect(self.choose_dir)
        pick = QHBoxLayout()
        pick.addWidget(btn_files)
        pick.addWidget(btn_dir)

        self.llm_label = QLabel()
        self.llm_label.setWordWrap(True)
        self.llm_label.setObjectName("LlmLabel")
        btn_settings = QPushButton("⚙️ Einstellungen")
        btn_settings.clicked.connect(self.open_settings)
        btn_check = QPushButton("🔌 Verbindung testen")
        btn_check.clicked.connect(lambda: self.check_connection(silent=False))
        cfg = QHBoxLayout()
        cfg.addWidget(btn_settings)
        cfg.addWidget(btn_check)

        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(12, 12, 6, 12)
        ll.addWidget(self.drop)
        ll.addLayout(pick)
        jobs_title = QLabel("Aufträge")
        jobs_title.setObjectName("SectionTitle")
        ll.addWidget(jobs_title)
        ll.addWidget(self.job_list, 1)
        ll.addWidget(self.llm_label)
        ll.addLayout(cfg)

        # Rechte Seite: Tabs
        self.doc_view = QTextBrowser()
        self.doc_view.setOpenExternalLinks(True)
        self.doc_view.setHtml(WELCOME)
        mono = QFontDatabase.systemFont(QFontDatabase.FixedFont)
        self.log_view = QPlainTextEdit(readOnly=True)
        self.log_view.setFont(mono)
        self.log_view.setMaximumBlockCount(20000)
        self.ai_view = QPlainTextEdit(readOnly=True)
        self.ai_view.setFont(mono)
        self.tabs = QTabWidget()
        self.tabs.addTab(self.doc_view, "📖 Dokumentation")
        self.tabs.addTab(self.ai_view, "🤖 KI live")
        self.tabs.addTab(self.log_view, "🧾 Protokoll")

        self.stage = QLabel("Bereit.")
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(8)
        self.btn_cancel = QPushButton("⛔ Abbrechen")
        self.btn_cancel.setEnabled(False)
        self.btn_cancel.clicked.connect(self.cancel)
        self.btn_browser = QPushButton("🌐 Im Browser öffnen")
        self.btn_folder = QPushButton("📂 Berichtsordner")
        self.btn_browser.setEnabled(False)
        self.btn_folder.setEnabled(False)
        self.btn_browser.clicked.connect(self.open_in_browser)
        self.btn_folder.clicked.connect(self.open_folder)
        bar = QHBoxLayout()
        bar.addWidget(self.stage, 1)
        bar.addWidget(self.btn_cancel)
        bar.addWidget(self.btn_browser)
        bar.addWidget(self.btn_folder)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(6, 12, 12, 12)
        rl.addWidget(self.tabs, 1)
        rl.addWidget(self.progress)
        rl.addLayout(bar)

        split = QSplitter()
        split.addWidget(left)
        split.addWidget(right)
        split.setStretchFactor(1, 1)
        split.setSizes([360, 960])
        self.setCentralWidget(split)
        self.statusBar().showMessage("Statische Analyse – Dateien werden nie ausgeführt.")

    # ------------------------------------------------------------------ Drag & Drop aufs ganze Fenster
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        paths = [Path(u.toLocalFile()) for u in e.mimeData().urls() if u.isLocalFile()]
        self.add_paths(paths)

    # ------------------------------------------------------------------ Aufträge
    def choose_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Dateien zur Analyse wählen")
        self.add_paths([Path(f) for f in files])

    def choose_dir(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Ordner zur Analyse wählen")
        if d:
            self.add_paths([Path(d)])

    def add_paths(self, paths: list[Path]) -> None:
        for p in paths:
            job = Job(next(self._ids), p)
            self.jobs[job.id] = job
            item = QListWidgetItem()
            item.setData(Qt.UserRole, job.id)
            self.job_list.addItem(item)
            self._update_item(job)
            self.queue.append(job.id)
        self._next()

    def _item(self, job_id: int) -> QListWidgetItem | None:
        for i in range(self.job_list.count()):
            item = self.job_list.item(i)
            if item.data(Qt.UserRole) == job_id:
                return item
        return None

    def _update_item(self, job: Job) -> None:
        item = self._item(job.id)
        if item is None:
            return
        name = job.path.name or str(job.path)
        extra = f" – {job.outcome.result.description}" if job.outcome else (f" – {job.error}" if job.error else "")
        item.setText(f"{STATUS_ICON.get(job.status, '')} {name}{extra}")
        item.setToolTip(str(job.path))

    def _next(self) -> None:
        if self.worker is not None or not self.queue:
            return
        job = self.jobs[self.queue.pop(0)]
        job.status = "läuft"
        self._update_item(job)
        self.ai_view.clear()
        self.log_view.appendPlainText(f"\n════════ {job.path} ════════")
        self.worker = JobWorker(job, self.settings)
        self.worker.log.connect(lambda _id, m: self.log_view.appendPlainText(m))
        self.worker.token.connect(self._on_token)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished_job.connect(self._on_finished)
        self.worker.failed_job.connect(self._on_failed)
        self.worker.finished.connect(self._worker_done)
        self.btn_cancel.setEnabled(True)
        self.worker.start()
        if self.settings.use_llm:
            self.tabs.setCurrentWidget(self.ai_view)

    def _on_token(self, _id: int, text: str) -> None:
        cursor = self.ai_view.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertText(text)
        self.ai_view.setTextCursor(cursor)
        self.ai_view.ensureCursorVisible()

    def _on_progress(self, _id: int, pct: int, stage: str) -> None:
        self.progress.setValue(pct)
        name = self.jobs[_id].path.name
        self.stage.setText(f"{name}: {stage} …" if pct < 100 else f"{name}: fertig")

    def _on_finished(self, job_id: int, outcome) -> None:
        job = self.jobs[job_id]
        job.status, job.outcome = "fertig", outcome
        self._update_item(job)
        self.job_list.setCurrentItem(self._item(job_id))
        self._show_job(job)
        self.tabs.setCurrentWidget(self.doc_view)
        if outcome.llm_error and self.settings.use_llm:
            self.statusBar().showMessage(f"Bericht ohne KI erstellt: {outcome.llm_error}", 15000)
        else:
            self.statusBar().showMessage(f"Fertig in {outcome.seconds:.0f} s – {outcome.files.html}", 15000)

    def _on_failed(self, job_id: int, msg: str) -> None:
        job = self.jobs[job_id]
        job.status = "abgebrochen" if msg == "Abgebrochen" else "fehler"
        job.error = msg
        self._update_item(job)
        self.stage.setText(f"{job.path.name}: {msg}")
        self.progress.setValue(0)

    def _worker_done(self) -> None:
        self.worker = None
        self.btn_cancel.setEnabled(False)
        self._next()

    def cancel(self) -> None:
        if self.worker:
            self.worker.cancel()
            self.stage.setText("Breche ab …")

    # ------------------------------------------------------------------ Anzeige
    def _selected_job(self) -> Job | None:
        item = self.job_list.currentItem()
        return self.jobs.get(item.data(Qt.UserRole)) if item else None

    def _show_selected(self, *_):
        job = self._selected_job()
        if job:
            self._show_job(job)

    def _show_job(self, job: Job) -> None:
        has = job.outcome is not None
        self.btn_browser.setEnabled(has)
        self.btn_folder.setEnabled(has)
        if has:
            md = job.outcome.files.markdown.read_text(encoding="utf-8")
            self.doc_view.setHtml(build_qt_html(md))
        elif job.status == "fehler":
            self.doc_view.setHtml(f"<h2>❌ Fehler</h2><pre>{job.error}</pre>")

    def open_in_browser(self) -> None:
        job = self._selected_job()
        if job and job.outcome:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(job.outcome.files.html)))

    def open_folder(self) -> None:
        job = self._selected_job()
        if job and job.outcome:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(job.outcome.files.folder)))

    # ------------------------------------------------------------------ Einstellungen / LLM
    def _refresh_llm_label(self, state: str = "") -> None:
        s = self.settings
        if not s.use_llm:
            self.llm_label.setText("🤖 KI: aus (nur technische Analyse)")
            return
        self.llm_label.setText(f"🤖 {s.model} @ {s.base_url}" + (f"\n{state}" if state else ""))

    def open_settings(self) -> None:
        dlg = SettingsDialog(self.settings, self)
        if dlg.exec():
            self.settings = dlg.result_settings()
            self.settings.save()
            self._refresh_llm_label()
            self.check_connection(silent=True)

    def check_connection(self, silent: bool) -> None:
        if not self.settings.use_llm or (self._check_worker and self._check_worker.isRunning()):
            return
        self._refresh_llm_label("⏳ prüfe Verbindung …")
        self._check_worker = FuncWorker(LLMClient(self.settings).check)

        def ok(msg):
            self._refresh_llm_label("🟢 bereit")
            if not silent:
                QMessageBox.information(self, "Verbindung", msg)

        def err(msg):
            self._refresh_llm_label("🔴 nicht erreichbar – Berichte entstehen dann ohne KI")
            if not silent:
                QMessageBox.warning(self, "Verbindung", msg)

        self._check_worker.done.connect(ok)
        self._check_worker.error.connect(err)
        self._check_worker.start()

    def closeEvent(self, e):
        if self.worker and self.worker.isRunning():
            if QMessageBox.question(self, "Beenden?", "Eine Analyse läuft noch. Wirklich beenden?") != QMessageBox.Yes:
                e.ignore()
                return
            self.worker.cancel()
            self.worker.wait(5000)
        e.accept()
