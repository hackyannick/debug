"""Hintergrund-Threads, damit die Oberfläche während Analyse und KI-Generierung flüssig bleibt."""

from __future__ import annotations

import threading
import traceback
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable

from PySide6.QtCore import QThread, Signal

from magicbox.config import Settings
from magicbox.engine import Cancelled
from magicbox.pipeline import Callbacks, run


@dataclass
class Job:
    id: int
    path: Path
    status: str = "wartet"  # wartet | läuft | fertig | fehler | abgebrochen
    outcome: Any = None
    error: str = ""


class JobWorker(QThread):
    log = Signal(int, str)
    token = Signal(int, str)
    progress = Signal(int, int, str)
    finished_job = Signal(int, object)
    failed_job = Signal(int, str)

    def __init__(self, job: Job, settings: Settings):
        super().__init__()
        self.job = job
        self.settings = replace(settings)  # Kopie: Änderungen während des Laufs wirken erst beim nächsten Job
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        jid = self.job.id
        cb = Callbacks(
            log=lambda m: self.log.emit(jid, m),
            progress=lambda p, s: self.progress.emit(jid, p, s),
            token=lambda t: self.token.emit(jid, t),
            is_cancelled=self._cancel.is_set,
        )
        try:
            outcome = run(self.job.path, self.settings, cb)
            self.finished_job.emit(jid, outcome)
        except Cancelled:
            self.failed_job.emit(jid, "Abgebrochen")
        except Exception as exc:  # noqa: BLE001 - Fehler sauber in der GUI anzeigen
            self.log.emit(jid, traceback.format_exc())
            self.failed_job.emit(jid, f"{exc.__class__.__name__}: {exc}")


class FuncWorker(QThread):
    """Führt eine beliebige Funktion im Hintergrund aus (z. B. Verbindungstest)."""

    done = Signal(object)
    error = Signal(str)

    def __init__(self, fn: Callable[[], Any]):
        super().__init__()
        self.fn = fn

    def run(self) -> None:
        try:
            self.done.emit(self.fn())
        except Exception as exc:  # noqa: BLE001
            self.error.emit(str(exc))
