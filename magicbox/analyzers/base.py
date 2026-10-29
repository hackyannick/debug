"""Gemeinsame Hilfsfunktionen und Basisklasse für Analyzer."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from magicbox.config import Settings
from magicbox.model import AnalysisResult


@dataclass
class Context:
    path: Path
    data: bytes
    settings: Settings
    depth: int = 0
    # Von Analyzern befüllte Infos für spätere Analyzer (z. B. Architektur, Symbole)
    facts: dict = field(default_factory=dict)
    # Für alle Dateien eines Auftrags gemeinsam (z. B. Zähler für teure Werkzeuge)
    shared: dict = field(default_factory=dict)
    # Rekursive Analyse eingebetteter Dateien: recurse(name, data) -> AnalysisResult | None
    recurse: Callable[[str, bytes], AnalysisResult | None] | None = None


class Analyzer:
    """Ein Analyzer prüft mit ``matches`` ob er zuständig ist und schreibt Ergebnisse ins Result."""

    name = "base"
    kinds: tuple[str, ...] = ()  # leer = alle
    malware_only = False  # True: läuft nur im Malware-Profil (im Software-Profil übersprungen)

    def matches(self, ctx: Context, result: AnalysisResult) -> bool:
        return not self.kinds or result.kind in self.kinds

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:  # pragma: no cover
        raise NotImplementedError


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def fast_entropy(data: bytes, sample: int = 4 * 1024 * 1024) -> float:
    """Entropie mit bytes.count (schnell auch bei großen Dateien)."""
    if not data:
        return 0.0
    if len(data) > sample:
        step = len(data) // sample
        data = data[::step]
    n = len(data)
    total = 0.0
    for i in range(256):
        c = data.count(i)
        if c:
            p = c / n
            total -= p * math.log2(p)
    return total


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{n} B"


def clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"
