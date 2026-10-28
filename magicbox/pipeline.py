"""Die eigentliche „Magic Box“: Datei rein → Analyse → (optional) LLM → Bericht raus."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from magicbox.config import Settings
from magicbox.engine import Cancelled, Engine
from magicbox.llm.client import LLMCancelled, LLMError
from magicbox.llm.documenter import Documenter
from magicbox.model import AnalysisResult
from magicbox.report.builder import ReportFiles, write_report


@dataclass
class JobOutcome:
    result: AnalysisResult
    files: ReportFiles
    llm_error: str
    seconds: float


@dataclass
class Callbacks:
    log: Callable[[str], None] = lambda msg: None
    progress: Callable[[int, str], None] = lambda pct, stage: None
    token: Callable[[str], None] | None = None
    is_cancelled: Callable[[], bool] = lambda: False


def run(path: Path, settings: Settings, cb: Callbacks | None = None, report_folder: Path | None = None) -> JobOutcome:
    cb = cb or Callbacks()
    start = time.monotonic()
    path = Path(path)

    cb.progress(5, "Statische Analyse")
    cb.log(f"▶ Starte Analyse: {path}")
    result = Engine(settings, log=cb.log, is_cancelled=cb.is_cancelled).analyze_path(path)

    llm_error = ""
    if settings.use_llm:
        cb.progress(45, "KI schreibt Dokumentation")
        cb.log(f"▶ Sende Fakten an {settings.provider} @ {settings.base_url} (Modell {settings.model})")
        try:
            doc = Documenter(settings, log=cb.log, on_token=cb.token, is_cancelled=cb.is_cancelled)
            doc.document(result)
            cb.log(f"✔ KI-Dokumentation fertig ({doc.calls} Anfrage(n))")
        except LLMCancelled as exc:
            raise Cancelled() from exc
        except (LLMError, ValueError) as exc:
            llm_error = str(exc)
            cb.log(f"⚠ KI nicht verfügbar – Bericht wird ohne KI erstellt: {exc}")
    else:
        llm_error = "KI ist in den Einstellungen deaktiviert."

    cb.progress(95, "Bericht schreiben")
    files = write_report(result, Path(settings.output_dir), llm_error if settings.use_llm else "", folder=report_folder)
    seconds = time.monotonic() - start
    cb.log(f"✔ Bericht gespeichert: {files.html} ({seconds:.0f} s)")
    cb.progress(100, "Fertig")
    return JobOutcome(result, files, llm_error, seconds)
