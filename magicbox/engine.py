"""Analyse-Engine: erkennt den Dateityp und lässt alle passenden Analyzer laufen (rekursiv für Archive)."""

from __future__ import annotations

import os
import time
import traceback
from pathlib import Path
from typing import Callable

from magicbox.analyzers import ANALYZERS, IdentifyAnalyzer
from magicbox.analyzers.base import Context
from magicbox.config import Settings
from magicbox.model import AnalysisResult, Section, Table

MAX_FILE_BYTES = 1024 * 1024 * 1024  # 1 GB – größere Dateien werden nur angelesen
# Technische Hinweise, die auch im Software-Profil bleiben (als „info“) – alle anderen Befunde sind Sicherheitsbewertung
TECHNICAL_NOTES = ("Archiv zu groß", "Entpackte Daten zu groß", "Passwortgeschützte", "UPX-Entpacken", "Limit erreicht",
                   "Verschlüsseltes App-Store-Binary")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".idea", ".vs"}

Log = Callable[[str], None]


class Cancelled(Exception):
    pass


class Engine:
    def __init__(self, settings: Settings, log: Log | None = None, is_cancelled: Callable[[], bool] | None = None):
        self.settings = settings
        self.log = log or (lambda msg: None)
        self.is_cancelled = is_cancelled or (lambda: False)
        self._identify = IdentifyAnalyzer()
        self._count = 0
        self.shared: dict = {}
        self.software = settings.profile == "allgemein"
        if self.software:
            skipped = ", ".join(a.name for a in ANALYZERS if a.malware_only)
            self.log(f"Software-Profil: keine Malware-Prüfungen ({skipped} übersprungen)")

    def analyze_path(self, path: Path) -> AnalysisResult:
        path = Path(path)
        if path.is_dir():
            return self._analyze_dir(path)
        size = path.stat().st_size
        with path.open("rb") as f:
            data = f.read(MAX_FILE_BYTES)
        result = self.analyze_bytes(path.name, data, depth=0, path=path)
        if size > len(data):
            result.size = size
            result.find("info", "Datei nur teilweise gelesen", f"Nur die ersten {MAX_FILE_BYTES // 2**20} MB wurden analysiert.")
        return result

    def analyze_bytes(self, name: str, data: bytes, depth: int = 0, path: Path | None = None) -> AnalysisResult:
        if self.is_cancelled():
            raise Cancelled()
        self._count += 1
        display = name if depth == 0 else f"{'  ' * depth}↳ {name}"
        self.log(f"Analysiere {display} ({len(data):,} Bytes)".replace(",", "."))
        path = path or Path(name)
        result = AnalysisResult(path=str(path), name=name, size=len(data), profile=self.settings.profile)
        ctx = Context(path=path, data=data, settings=self.settings, depth=depth, shared=self.shared)
        ctx.recurse = lambda child_name, child_data: self._child(child_name, child_data, depth + 1)

        self._identify.analyze(ctx, result)
        for analyzer in ANALYZERS:
            if self.is_cancelled():
                raise Cancelled()
            if (self.software and analyzer.malware_only) or not analyzer.matches(ctx, result):
                continue
            hint = getattr(analyzer, "slow_hint", "")
            if hint:
                self.log(f"  … {analyzer.name}: {hint}")
            started = time.monotonic()
            try:
                analyzer.analyze(ctx, result)
                if hint:
                    self.log(f"  ✓ {analyzer.name} fertig ({time.monotonic() - started:.0f} s)")
            except Cancelled:
                raise
            except Exception as exc:  # ein kaputter Analyzer darf den Rest nicht stoppen
                result.errors.append(f"{analyzer.name}: {exc.__class__.__name__}: {exc}")
                self.log(f"  ! Fehler in {analyzer.name}: {exc}")
                if os.environ.get("MAGICBOX_DEBUG"):
                    traceback.print_exc()
        if self.software:
            result.findings = self._software_findings(result.findings)
        self.log(f"  → {result.description}")
        return result

    @staticmethod
    def _software_findings(findings):
        """Software-Profil: Sicherheitsbefunde verwerfen, technische Hinweise als „info“ behalten."""
        kept = []
        for f in findings:
            if f.severity == "info":
                kept.append(f)
            elif f.title.startswith(TECHNICAL_NOTES):
                f.severity = "info"
                kept.append(f)
        return kept

    def _child(self, name: str, data: bytes, depth: int) -> AnalysisResult | None:
        if self._count >= self.settings.max_archive_members * 2:
            return None
        return self.analyze_bytes(name, data, depth=depth)

    def _analyze_dir(self, root: Path) -> AnalysisResult:
        result = AnalysisResult(path=str(root), name=root.name or str(root), size=0, kind="directory",
                                description="Ordner", profile=self.settings.profile)
        files: list[Path] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            files += [Path(dirpath) / f for f in sorted(filenames)]
        limit = self.settings.max_archive_members
        if len(files) > limit:
            result.find("info", "Limit erreicht", f"Nur die ersten {limit} von {len(files)} Dateien wurden analysiert.")
        rows = []
        for f in files[:limit]:
            rel = f.relative_to(root).as_posix()
            try:
                data = f.read_bytes()[:MAX_FILE_BYTES]
            except OSError as exc:
                result.errors.append(f"{rel}: {exc}")
                continue
            result.size += len(data)
            child = self.analyze_bytes(rel, data, depth=1, path=f)
            result.children.append(child)
            rows.append([rel, child.description])
        result.add(Section(f"Inhalt ({len(files)} Dateien)", table=Table(["Datei", "Typ"], rows, total=len(files)),
                           llm_priority=0))
        return result
