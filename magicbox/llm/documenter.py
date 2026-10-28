"""Erzeugt aus einem AnalysisResult per LLM eine verständliche Dokumentation (Map-Reduce für kleine Kontexte)."""

from __future__ import annotations

from typing import Callable

from magicbox.config import Settings
from magicbox.model import AnalysisResult, Section

from . import prompts
from .client import LLMClient

Log = Callable[[str], None]
SEV_LABEL = {"high": "HOCH", "medium": "MITTEL", "low": "NIEDRIG", "info": "INFO"}
BORING_KINDS = {"image", "text"}


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


def facts_text(result: AnalysisResult, budget: int, include_code: bool = True) -> str:
    """Kompakte Faktenbasis innerhalb eines Zeichenbudgets (wichtigste Abschnitte zuerst)."""
    head = [f"- Datei: {result.name}", f"- Typ: {result.description}", f"- Größe: {result.size} Bytes"]
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
                 is_cancelled: Callable[[], bool] | None = None):
        self.s = settings
        self.log = log or (lambda m: None)
        self.on_token = on_token
        self.client = LLMClient(settings, is_cancelled=is_cancelled)
        self.calls = 0

    def _ask(self, user: str, label: str) -> str:
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
        notes = self._notes(result, budget)
        facts_budget = budget - min(len(notes), budget // 2)
        include_code = not notes  # Code wurde bereits in Notizen verdichtet
        facts = facts_text(result, facts_budget, include_code=include_code)
        doc = self._ask(prompts.document_prompt(result.name, facts, notes, self.s), f"Dokumentation für {result.name}")
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
            for child in interesting[: self.s.max_llm_children]:
                facts = facts_text(child, int(budget * 0.8))
                summary = self._ask(prompts.child_notes_prompt(child.name, facts), f"Teil-Analyse {child.name}")
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
        for i, chunk in enumerate(chunks, 1):
            summary = self._ask(prompts.code_notes_prompt(result.name, i, len(chunks), chunk, context),
                                f"Code-Teil {i}/{len(chunks)}")
            notes.append(f"### Code-Teil {i}\n{summary}")
        return "\n\n".join(notes)
