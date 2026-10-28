"""Datenmodell für Analyseergebnisse.

Alle Analyzer schreiben in ein gemeinsames ``AnalysisResult``. Daraus werden
sowohl der technische Bericht als auch der Kontext für das LLM erzeugt.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("info", "low", "medium", "high")


@dataclass
class Table:
    headers: list[str]
    rows: list[list[str]]
    total: int | None = None  # Gesamtzahl, falls rows gekürzt wurde


@dataclass
class Section:
    """Ein Block im technischen Bericht.

    ``llm_priority``: je kleiner, desto wichtiger für den LLM-Kontext
    (0 = immer mitgeben, 9 = nur wenn Platz ist).
    """

    title: str
    kv: dict[str, str] = field(default_factory=dict)
    table: Table | None = None
    text: str = ""
    code: str = ""
    code_lang: str = ""
    llm_priority: int = 5


@dataclass
class Finding:
    severity: str
    title: str
    detail: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"Unbekannte Severity: {self.severity}")


@dataclass
class AnalysisResult:
    path: str
    name: str
    size: int
    kind: str = "unknown"
    description: str = "Unbekanntes Format"
    hashes: dict[str, str] = field(default_factory=dict)
    entropy: float = 0.0
    sections: list[Section] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    children: list["AnalysisResult"] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    tools: list[str] = field(default_factory=list)
    # Indicators of Compromise: Typ -> Werte (URL, Domain, IPv4, E-Mail, Registry, Pfad, Hash …)
    iocs: dict[str, list[str]] = field(default_factory=dict)
    # Treffer von Erkennungsregeln (YARA) – Namen von Malware-Familien/Regeln
    detections: list[str] = field(default_factory=list)
    llm_doc: str = ""
    llm_model: str = ""

    def add(self, section: Section) -> Section:
        self.sections.append(section)
        return section

    def find(self, severity: str, title: str, detail: str = "") -> None:
        self.findings.append(Finding(severity, title, detail))

    def add_ioc(self, kind: str, value: str) -> None:
        values = self.iocs.setdefault(kind, [])
        if value not in values and len(values) < 500:
            values.append(value)

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
