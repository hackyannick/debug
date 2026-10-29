"""Datenmodell für Analyseergebnisse.

Alle Analyzer schreiben in ein gemeinsames ``AnalysisResult``. Daraus werden
sowohl der technische Bericht als auch der Kontext für das LLM erzeugt.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
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
    profile: str = ""  # "malware" oder "allgemein" (Software-Doku ohne Malware-Prüfungen)
    # Wer/was ist das? z. B. {"Produkt": "Qobuz", "Version": "8.3.0", "Hersteller": "Qobuz"} (Versionsinfo, package.json …)
    product: dict[str, str] = field(default_factory=dict)
    runtime: str = ""  # erkannte Laufzeitumgebung, z. B. "Electron 34.2.0"
    # Eigene Fragen an die KI: {"question", "answer", "model", "time"}
    qa: list[dict] = field(default_factory=list)

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

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AnalysisResult":
        """Gegenstück zu ``to_dict`` (z. B. analysis.json) – unbekannte Felder werden ignoriert."""
        known = {f.name for f in fields(cls)}
        d = {k: v for k, v in data.items() if k in known}
        d["sections"] = [_section(s) for s in d.get("sections", [])]
        d["findings"] = [Finding(**f) for f in d.get("findings", [])]
        d["children"] = [cls.from_dict(c) for c in d.get("children", [])]
        return cls(**d)


def _section(data: dict[str, Any]) -> Section:
    known = {f.name for f in fields(Section)}
    d = {k: v for k, v in data.items() if k in known}
    if d.get("table"):
        d["table"] = Table(**d["table"])
    return Section(**d)
