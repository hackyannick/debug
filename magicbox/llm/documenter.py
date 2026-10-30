"""Erzeugt aus einem AnalysisResult per LLM eine verständliche Dokumentation (Map-Reduce für kleine Kontexte)."""

from __future__ import annotations

import math
import posixpath
import re
import time
from typing import Callable

from magicbox.analyzers.jsbundle import interest
from magicbox.analyzers.runtime import is_shell
from magicbox.config import Settings
from magicbox.model import AnalysisResult, Section

from . import prompts
from .client import LLMClient
from .tidy import tidy_glossary

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
    if result.product:  # belegte Angaben zur Identität (Versionsinfo/package.json) – das Modell soll nicht raten
        head.append("- Produkt laut Datei: " + " · ".join(f"{k}: {v}" for k, v in result.product.items()))
    if result.runtime:
        hint = next((s.kv.get("Wo liegt die Programmlogik?", "") for s in result.sections if s.title == "Laufzeitumgebung"), "")
        head.append(f"- Laufzeitumgebung: {result.runtime}" + (f" – {hint}" if hint else ""))
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
    if result.findings and result.profile == "allgemein":
        head.append("\n### Technische Hinweise")
        head += [f"- {f.title}: {f.detail}" for f in result.findings]
    elif result.findings:
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
        self._root_product: list[str] = []
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
        # Produkt-/Herstellername der App (z. B. „Qobuz“) – Code-Teile, die ihn enthalten, sind meist App-Code
        self._root_product = [v for k, v in result.product.items() if k in ("Produkt", "Hersteller")]
        budget = self.s.context_chars
        self.planned = max(self.planned, self.calls + 1)
        notes = self._notes(result, budget)
        facts_budget = budget - min(len(notes), budget // 2)
        include_code = not notes  # Code wurde bereits in Notizen verdichtet
        facts = facts_text(result, facts_budget, include_code=include_code)
        doc = self._ask(prompts.document_prompt(result.name, facts, notes, self.s), "Dokumentation schreiben")
        doc = tidy_glossary(doc)
        doc += verification_note(result, doc)
        result.llm_doc = doc
        result.llm_model = self.s.model
        return doc

    # ------------------------------------------------------------------
    def _notes(self, result: AnalysisResult, budget: int) -> str:
        """Verdichtet Code und Kind-Dateien, falls sie nicht direkt in den Kontext passen."""
        notes: list[str] = []
        if result.children:
            # Code aus Electron-Archiven (app.asar) liegt oft tiefer, z. B. Installer → Paket → app.asar → *.js
            candidates = list(result.children) + [g for node in result.walk() if node is not result and
                                                  node.kind == "asar" for g in node.children]
            software = self.s.profile == "allgemein"
            interesting = [c for c in candidates if (c.kind not in BORING_KINDS or c.findings)
                           and not (software and c.kind == "unknown" and not c.findings)
                           and not (software and ANIMATION_DATA_RE.search(c.name.replace("\\", "/")) and not c.findings)]

            def rank(c: AnalysisResult) -> tuple:
                serious = len([f for f in c.findings if f.severity in ("high", "medium")])
                code_first = c.kind == "source" if software else c.kind != "source"
                data_like = bool(DATA_LANG_RE.search(c.description))  # JSON/SQL/Text nach echtem Code
                return (-serious, is_shell(c), c.kind != "asar", not code_first, data_like, -c.size)
            interesting.sort(key=rank)
            # identische Dateien (gleicher Hash) nur einmal von der KI lesen lassen
            seen: set[str] = set()
            unique = []
            for c in interesting:
                digest = c.hashes.get("sha256", "")
                if digest and digest in seen:
                    continue
                seen.add(digest)
                unique.append(c)
            interesting = unique
            selected = group_small(interesting)[: self.s.max_llm_children]
            # Große Code-Dateien (Bundles): zusätzlich die aufschlussreichsten Teile einzeln lesen lassen
            big = [item for item, _ in selected if len(code_material(item)) > budget]
            chunk_budget = self.s.max_code_chunks
            per_big = max(1, chunk_budget // len(big)) if big else 0
            self.planned = self.calls + len(selected) + min(chunk_budget, per_big * len(big)) + 1
            for item, members in selected:
                code_notes = ""
                if item in big and chunk_budget > 0:
                    take = min(per_big, chunk_budget)
                    code_notes, used = self._chunk_notes(item, budget, take)
                    chunk_budget -= used
                limit = min(int(budget * 0.8), self.s.child_facts_chars)
                facts = facts_text(item, limit // 2 if code_notes else limit, include_code=not code_notes)
                if code_notes:
                    facts += "\n\n### Zusammenfassungen der aufschlussreichsten Code-Teile\n" + code_notes
                summary = self._ask(prompts.child_notes_prompt(item.name, facts, self.s.profile == "malware"),
                                    f"Teil-Analyse: {item.name}")
                if members:
                    members[0].llm_doc = (f"*Gemeinsame Einschätzung für {len(members)} Dateien "
                                          f"({', '.join(m.name for m in members[:12])}{' …' if len(members) > 12 else ''}):*"
                                          f"\n\n{summary}")
                else:
                    item.llm_doc = summary
                notes.append(f"### {item.name} ({item.description})\n{summary}")
            return "\n\n".join(notes)

        code = code_material(result)
        full = facts_text(result, budget * 10)
        if len(full) <= budget or not code:
            return ""  # passt komplett in den Kontext
        self.planned = self.calls + min(self.s.max_code_chunks, 1 + len(code) // max(1, budget // 2)) + 1
        text, _ = self._chunk_notes(result, budget, self.s.max_code_chunks)
        return text

    def _chunk_notes(self, result: AnalysisResult, budget: int, limit: int) -> tuple[str, int]:
        """Code in Teile zerlegen; passen nicht alle, die aufschlussreichsten wählen (Endpunkte, IPC, Aktionen …)."""
        code = code_material(result)
        context = facts_text(result, 1500, include_code=False)
        size = min(int(budget * 0.75) - len(context), self.s.code_chunk_chars)
        chunks = split_chunks(code, max(2000, size))
        picked = list(range(len(chunks)))
        if len(chunks) > limit:
            names = [v for k, v in result.product.items() if k in ("Produkt", "Hersteller")] + self._root_product
            own = {t for t in (re.sub(r"[^a-z0-9]", "", n.lower()) for n in names) if len(t) >= 3}
            ranked = sorted(picked, key=lambda i: (-interest(chunks[i], own), i))[:limit]
            picked = sorted(ranked)
            self.log(f"{result.name}: Code hat {len(chunks)} Teile – die {limit} aufschlussreichsten werden "
                     f"einzeln gelesen (Teile {', '.join(str(i + 1) for i in picked)}).")
        notes = []
        for i in picked:
            summary = self._ask(prompts.code_notes_prompt(result.name, i + 1, len(chunks), chunks[i], context,
                                                          self.s.profile == "malware"),
                                f"{result.name}: Code-Teil {i + 1}/{len(chunks)} zusammenfassen")
            notes.append(f"#### Code-Teil {i + 1} von {len(chunks)}\n{summary}")
        return "\n\n".join(notes), len(picked)

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
        reply += verification_note(result, reply)
        result.qa.append({"question": question, "answer": reply, "model": self.s.model, "time": time.time()})
        return reply


DLL_RE = re.compile(r"\b[\w.-]+\.(?:dll|sys|drv|ocx)\b", re.I)


def verification_note(result: AnalysisResult, text: str) -> str:
    """Gegenprüfung: Im KI-Text genannte DLLs müssen in den Analysedaten vorkommen – sonst Hinweis anhängen."""
    mentioned = {m.group().lower() for m in DLL_RE.finditer(text)}
    if not mentioned:
        return ""
    import json

    def facts_only(d: dict) -> dict:  # KI-Texte (Teil-Analysen, frühere Antworten) zählen nicht als Beleg
        return {k: ([facts_only(c) for c in v] if k == "children" else v) for k, v in d.items()
                if k not in ("llm_doc", "qa", "llm_model")}
    known = json.dumps(facts_only(result.to_dict()), ensure_ascii=False).lower()
    unknown = sorted(d for d in mentioned if d not in known)
    if not unknown:
        return ""
    return ("\n\n> ⚠️ **Gegenprüfung der Magic Box:** " + ", ".join(f"`{d}`" for d in unknown) +
            " kommt in den Analysedaten nicht vor – diese Angabe der KI ist vermutlich falsch.")


GROUP_MAX_SIZE = 8 * 1024
# Animations-/Grafikdaten als JSON (Lottie) – für die KI ohne Aussage über die App
ANIMATION_DATA_RE = re.compile(r"(?:^|/)(?:lotties?|motions|animations?)/[^/]+\.json$", re.I)
DATA_LANG_RE = re.compile(r"\((?:json|sql|text|css|xml|yaml|toml|ini|csv|markdown)\)")


def group_small(children: list[AnalysisResult]) -> list[tuple[AnalysisResult, list[AnalysisResult]]]:
    """Viele kleine Dateien gleicher Art (z. B. 9 SQL-Migrationen) zu einer gemeinsamen Teil-Analyse bündeln.
    Liefert (Eintrag, Mitglieder) – Mitglieder leer bei Einzeldateien; Reihenfolge wie übergeben."""
    buckets: dict[tuple[str, str], list[AnalysisResult]] = {}
    for c in children:
        if c.kind == "source" and c.size <= GROUP_MAX_SIZE and not c.findings:
            key = (posixpath.dirname(c.name), posixpath.splitext(c.name)[1].lower())
            buckets.setdefault(key, []).append(c)
    groups = {k: v for k, v in buckets.items() if len(v) >= 3}
    out, done = [], set()
    for c in children:
        key = (posixpath.dirname(c.name), posixpath.splitext(c.name)[1].lower())
        if key in groups:
            if key in done:
                continue
            done.add(key)
            members = groups[key]
            folder, ext = key
            combined = AnalysisResult(path=folder, name=f"{folder + '/' if folder else ''}*{ext} ({len(members)} Dateien)",
                                      size=sum(m.size for m in members), kind="source",
                                      description=f"{len(members)} kleine {ext or 'Text'}-Dateien", profile=c.profile)
            code = "\n\n".join(f"-- Datei: {m.name}\n" + next((s.code for s in m.sections if s.code and
                                                                   s.title.startswith("Quelltext")), "")
                                for m in members)
            combined.add(Section("Inhalt der Dateien", code=code, code_lang=members[0].sections[-1].code_lang
                                 if members[0].sections else "", llm_priority=0))
            out.append((combined, members))
        else:
            out.append((c, []))
    return out


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
