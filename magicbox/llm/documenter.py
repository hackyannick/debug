"""Erzeugt aus einem AnalysisResult per LLM eine verständliche Dokumentation (Map-Reduce für kleine Kontexte)."""

from __future__ import annotations

import math
import re
import time
from typing import Callable

from magicbox.config import Settings
from magicbox.model import AnalysisResult, Section

from . import prompts
from .client import LLMClient

Log = Callable[[str], None]
SEV_LABEL = {"high": "HOCH", "medium": "MITTEL", "low": "NIEDRIG", "info": "INFO"}
BORING_KINDS = {"image", "text"}
# Abschnittsmarken im extrahierten Code (radare2: "// ===== name =====", VBA: "' ===== modul =====")
UNIT_MARK = re.compile(r"^(?://|')\s*={3,}\s*(.+?)\s*={3,}\s*$")
# Beginn einer Funktion/Methode in Quelltext bzw. dekompiliertem Code
FUNC_START = re.compile(
    r"^[ \t]*(?:(?:public|private|protected|internal|static|async|override|virtual|sealed|final|export|unsafe)\s+)+"
    r"[\w<>\[\],.?]+(?:\s+[\w<>\[\],.?]+)?\s*\(|"
    r"^[ \t]*(?:async\s+)?(?:def|function|func|fn|sub|private\s+sub|public\s+sub|private\s+function|"
    r"public\s+function)\s+[\w$.]+", re.I | re.M)
STOPWORDS = set("""
aber alle allem allen aller alles also auch bitte dann dass dem den denen der des die dies diese diesem diesen dieser
dieses doch dort durch eine einem einen einer eines erkläre erklaere erklären etwas für funktion funktionen gibt habe
hier ihre ihren ist kann kannst mache macht mich mir mit nach nicht noch oder sich sie sind such suche suchen über und
uns unter verständlich verstaendlich vom von was welche welcher welches werden wie wird wo zum zur
code datei stelle stellen programm the and that this with what which does find function explain please
""".split())


def render_section(sec: Section, limit: int) -> str:
    out = [f"### {sec.title}"]
    for k, v in sec.kv.items():
        out.append(f"- {k}: {v}")
    if sec.table:
        out.append(" | ".join(sec.table.headers))
        for row in sec.table.rows:
            out.append(" | ".join(row))
        if sec.table.total and sec.table.total > len(sec.table.rows):
            out.append(f"(… insgesamt {sec.table.total} Einträge)")
    if sec.text:
        out.append(sec.text)
    if sec.code:
        out.append(f"```{sec.code_lang}\n{sec.code}\n```")
    text = "\n".join(out)
    if len(text) > limit:
        text = text[: limit - 20] + "\n… (gekürzt)"
        if sec.code and text.count("```") % 2:
            text += "\n```"
    return text


def collect_iocs(result: AnalysisResult, per_kind: int = 15) -> dict[str, list[str]]:
    merged: dict[str, list[str]] = {}
    for r in result.walk():
        for kind, values in r.iocs.items():
            lst = merged.setdefault(kind, [])
            lst.extend(v for v in values if v not in lst)
    return {k: v[:per_kind] for k, v in merged.items()}


def facts_text(result: AnalysisResult, budget: int, include_code: bool = True) -> str:
    """Kompakte Faktenbasis innerhalb eines Zeichenbudgets (wichtigste Abschnitte zuerst)."""
    head = [f"- Datei: {result.name}", f"- Typ: {result.description}", f"- Größe: {result.size} Bytes"]
    if result.hashes:
        head.append(f"- SHA-256: {result.hashes.get('sha256', '')}")
    detections = sorted({d for r in result.walk() for d in r.detections})
    if detections:
        head.append(f"- YARA-Treffer: {', '.join(detections)}")
    iocs = collect_iocs(result)
    if iocs:
        head.append("\n### Extrahierte Indikatoren (IOCs)")
        for kind, values in iocs.items():
            head.append(f"- {kind}: {', '.join(values)}")
    if result.findings:
        head.append("\n### Automatisch erkannte Auffälligkeiten")
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        for f in sorted(result.findings, key=lambda f: order[f.severity]):
            head.append(f"- [{SEV_LABEL[f.severity]}] {f.title}: {f.detail}")
    if result.children:
        head.append(f"\n### Enthaltene Dateien ({len(result.children)})")
        for c in result.children[:80]:
            head.append(f"- {c.name}: {c.description}")
    parts = ["\n".join(head)]
    used = len(parts[0])
    sections = [s for s in result.sections if include_code or not s.code or s.code_lang == "text"]
    for sec in sorted(sections, key=lambda s: s.llm_priority):
        remaining = budget - used
        if remaining < 300:
            break
        # Einzelne Abschnitte dürfen nicht alles fressen
        chunk = render_section(sec, min(remaining, max(1500, budget // 3)))
        parts.append(chunk)
        used += len(chunk) + 2
    return "\n\n".join(parts)


def code_material(result: AnalysisResult) -> str:
    blocks = [f"// --- {s.title} ---\n{s.code}" for s in sorted(result.sections, key=lambda s: s.llm_priority)
              if s.code and s.code_lang not in ("text", "")]
    return "\n\n".join(blocks)


def split_chunks(text: str, size: int) -> list[str]:
    """Teilt an Leerzeilen/Zeilenumbrüchen, damit Funktionen möglichst zusammenbleiben."""
    chunks, current = [], []
    length = 0
    for line in text.splitlines(keepends=True):
        if length + len(line) > size and current:
            chunks.append("".join(current))
            current, length = [], 0
        if len(line) > size:  # Monster-Zeile (minifiziert)
            for i in range(0, len(line), size):
                chunks.append(line[i:i + size])
            continue
        current.append(line)
        length += len(line)
    if current:
        chunks.append("".join(current))
    return chunks


class Documenter:
    def __init__(self, settings: Settings, log: Log | None = None, on_token: Callable[[str], None] | None = None,
                 is_cancelled: Callable[[], bool] | None = None,
                 on_progress: Callable[[int, int, str], None] | None = None):
        self.s = settings
        self.log = log or (lambda m: None)
        self.on_token = on_token
        self.on_progress = on_progress  # (erledigte Schritte, geplante Schritte, Bezeichnung)
        self.client = LLMClient(settings, is_cancelled=is_cancelled)
        self.calls = 0
        self.planned = 1  # wird präzisiert, sobald feststeht, wie viele Teilanalysen nötig sind

    def _ask(self, user: str, label: str) -> str:
        if self.on_progress:
            self.on_progress(self.calls, max(self.planned, self.calls + 1), label)
        self.calls += 1
        self.log(f"LLM: {label} …")
        if self.on_token:
            self.on_token(f"\n\n──── {label} ────\n")
        return self.client.chat(
            [{"role": "system", "content": prompts.system_prompt(self.s)}, {"role": "user", "content": user}],
            on_token=self.on_token,
        )

    def document(self, result: AnalysisResult) -> str:
        budget = self.s.context_chars
        self.planned = max(self.planned, self.calls + 1)
        notes = self._notes(result, budget)
        facts_budget = budget - min(len(notes), budget // 2)
        include_code = not notes  # Code wurde bereits in Notizen verdichtet
        facts = facts_text(result, facts_budget, include_code=include_code)
        doc = self._ask(prompts.document_prompt(result.name, facts, notes, self.s), "Dokumentation schreiben")
        result.llm_doc = doc
        result.llm_model = self.s.model
        return doc

    # ------------------------------------------------------------------
    def _notes(self, result: AnalysisResult, budget: int) -> str:
        """Verdichtet Code und Kind-Dateien, falls sie nicht direkt in den Kontext passen."""
        notes: list[str] = []
        if result.children:
            interesting = [c for c in result.children if c.kind not in BORING_KINDS or c.findings]
            interesting.sort(key=lambda c: (-len([f for f in c.findings if f.severity in ("high", "medium")]),
                                            c.kind in ("source",), -c.size))
            self.planned = self.calls + len(interesting[: self.s.max_llm_children]) + 1
            for child in interesting[: self.s.max_llm_children]:
                facts = facts_text(child, int(budget * 0.8))
                summary = self._ask(prompts.child_notes_prompt(child.name, facts), f"Teil-Analyse: {child.name}")
                child.llm_doc = summary
                notes.append(f"### {child.name} ({child.description})\n{summary}")
            return "\n\n".join(notes)

        code = code_material(result)
        full = facts_text(result, budget * 10)
        if len(full) <= budget or not code:
            return ""  # passt komplett in den Kontext
        context = facts_text(result, 1500, include_code=False)
        chunks = split_chunks(code, int(budget * 0.75) - len(context))
        if len(chunks) > self.s.max_code_chunks:
            self.log(f"Code hat {len(chunks)} Teile – nur die ersten {self.s.max_code_chunks} werden einzeln gelesen.")
            chunks = chunks[: self.s.max_code_chunks]
        self.planned = self.calls + len(chunks) + 1
        for i, chunk in enumerate(chunks, 1):
            summary = self._ask(prompts.code_notes_prompt(result.name, i, len(chunks), chunk, context),
                                f"Code-Teil {i}/{len(chunks)} zusammenfassen")
            notes.append(f"### Code-Teil {i}\n{summary}")
        return "\n\n".join(notes)

    # ------------------------------------------------------------------ Eigene Fragen
    def answer(self, result: AnalysisResult, question: str, reserve: int = 0) -> str:
        """Beantwortet eine Frage zur Datei, z. B. „Suche die Funktion, die … macht, und erkläre sie“.

        Passt der Code nicht komplett in den Kontext, leitet das Modell zuerst Suchbegriffe ab; die passendsten
        Code-Stellen (Funktionen, Methoden, Makros) werden per Stichwortsuche ausgewählt.
        ``reserve``: Anzahl danach noch geplanter Anfragen (nur für die Fortschrittsanzeige).
        """
        question = question.strip()
        budget = self.s.context_chars
        facts = facts_text(result, int(budget * 0.3), include_code=False)
        units = code_units(result)
        code_budget = max(1500, budget - len(facts) - len(question) - 1500)
        partial = sum(len(u[2]) + 40 for u in units) > code_budget
        self.planned = self.calls + (2 if partial else 1) + reserve
        terms = question_terms(question)
        if partial:
            reply = self._ask(prompts.search_terms_prompt(question), "Suchbegriffe ableiten")
            terms += [t for t in parse_terms(reply) if t not in terms]
            self.log(f"Suchbegriffe: {', '.join(terms) or '–'}")
            units = select_units(units, terms, code_budget)
            self.log("Ausgewählte Code-Stellen: " + (", ".join(u[0] for u in units) or "keine"))
        code = "\n\n".join(f"### {label}\n```{lang}\n{text.strip()}\n```" for label, lang, text in units)
        reply = self._ask(prompts.question_prompt(result.name, facts, code, partial, question, self.s),
                          "Frage beantworten")
        result.qa.append({"question": question, "answer": reply, "model": self.s.model, "time": time.time()})
        return reply


def code_units(result: AnalysisResult, size: int = 2400) -> list[tuple[str, str, str]]:
    """Zerlegt allen extrahierten Code in Einheiten (Bezeichnung, Sprache, Text) – möglichst je Funktion."""
    units: list[tuple[str, str, str]] = []
    for node in result.walk():
        prefix = "" if node is result else f"{node.name} › "
        for sec in node.sections:
            if not sec.code or sec.code_lang in ("text", ""):
                continue
            lines = sec.code.splitlines(keepends=True)
            has_marks = any(UNIT_MARK.match(l) for l in lines)
            parts: list[list[str]] = [[]]
            for line in lines:
                starts = UNIT_MARK.match(line) if has_marks else FUNC_START.match(line)
                if starts and any(x.strip() for x in parts[-1]):
                    parts.append([])
                parts[-1].append(line)
            for part in parts:
                text = "".join(part)
                if not text.strip():
                    continue
                first = next(l for l in part if l.strip()).strip()
                mark = UNIT_MARK.match(first)
                label = mark.group(1) if mark else (first[:90] if FUNC_START.match(first) else sec.title)
                for i, chunk in enumerate(split_chunks(text, size)):
                    units.append((prefix + label + (f" (Forts. {i})" if i else ""), sec.code_lang, chunk))
    return units


def question_terms(question: str) -> list[str]:
    words = re.findall(r"[\w.$:]{3,}", question.lower())
    out: list[str] = []
    for w in words:
        w = w.strip(".:")
        if len(w) >= 3 and w not in STOPWORDS and w not in out:
            out.append(w)
    return out


def parse_terms(reply: str) -> list[str]:
    out: list[str] = []
    for raw in re.split(r"[,;\n]", reply):
        t = raw.strip().strip("-*•`'\"„“”()[]").strip().lower()
        if 3 <= len(t) <= 40 and t not in STOPWORDS and t not in out and len(t.split()) <= 2:
            out.append(t)
    return out[:25]


def select_units(units: list[tuple[str, str, str]], terms: list[str], budget: int) -> list[tuple[str, str, str]]:
    """Die zur Frage passendsten Code-Einheiten (Stichwort-Treffer, gewichtet) innerhalb des Budgets."""
    def score(unit: tuple[str, str, str]) -> float:
        label, text = unit[0].lower(), unit[2].lower()
        total = 0.0
        for t in terms:
            n = text.count(t)
            weight = min(len(t), 12) / 4
            if n:
                total += (1 + math.log(n)) * weight
            if t in label:
                total += 3 * weight
        return total

    ranked = sorted(((score(u), i) for i, u in enumerate(units)), key=lambda x: (-x[0], x[1]))
    if not ranked or ranked[0][0] == 0:
        ranked = [(0, i) for i in range(len(units))]  # nichts gefunden: Einstiegspunkte (Anfang) zeigen
    picked, used = [], 0
    for sc, i in ranked:
        if ranked[0][0] and sc == 0:
            break
        size = len(units[i][2]) + 40
        if used + size > budget:
            continue
        picked.append(units[i])
        used += size
    return picked
