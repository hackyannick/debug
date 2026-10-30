"""Nachbearbeitung von KI-Texten: Wiederholungsschleifen erkennen und das Glossar auf echte Begriffe kürzen.

Kleine Modelle geraten am Ende langer Antworten gern in Schleifen („Audio-Stream-Format-Qualität-Codec-…“).
Das kostet Minuten Rechenzeit und macht den Bericht unlesbar.
"""

from __future__ import annotations

import os
import re

LOOP_PREFIX = 20  # so viele gleiche Anfangszeichen zweier aufeinanderfolgender Zeilen gelten als „ähnlich“
LOOP_RUN = 15     # so viele ähnliche Zeilen in Folge gelten als Schleife
GLOSSARY_MAX = 40


def _key(line: str) -> str:
    """Zeileninhalt ohne Tabellen-/Listen-Präfix, damit „| Begriff |“ und „- Begriff“ vergleichbar werden."""
    return re.sub(r"^[\s|*\-+>#\d.`]+", "", line).strip().lower()


def loop_start(text: str) -> int | None:
    """Zeichenposition, ab der sich der Text in einer Schleife ähnlicher Zeilen wiederholt (sonst None)."""
    lines = text.split("\n")
    run = 0
    start = 0
    fenced = lines[0].lstrip().startswith("```")
    for i in range(1, len(lines)):
        if lines[i].lstrip().startswith("```"):
            fenced = not fenced
        a, b = _key(lines[i - 1]), _key(lines[i])
        if fenced:  # Code-Zitate dürfen sich ähneln (z. B. Disassembly)
            run = 0
        elif a and b and (a == b or len(os.path.commonprefix([a, b])) >= LOOP_PREFIX):
            if run == 0:
                start = i  # die erste Zeile der Folge bleibt stehen
            run += 1
            if run >= LOOP_RUN:
                return len("\n".join(lines[:start]))
        else:
            run = 0
    return None


def cut_loop(text: str) -> str:
    pos = loop_start(text)
    return text if pos is None else text[:pos].rstrip()


def tidy_glossary(doc: str, heading: str = "Glossar", limit: int = GLOSSARY_MAX) -> str:
    """Glossar-Tabelle auf Begriffe beschränken, die im übrigen Text vorkommen, ohne Dubletten, höchstens ``limit``."""
    m = re.search(rf"^#+\s*{heading}\s*$", doc, re.M)
    if not m:
        return doc
    body = doc[:m.start()].lower()
    head, section = doc[:m.end()], doc[m.end():]
    nxt = re.search(r"^#+\s", section, re.M)
    rest = section[nxt.start():] if nxt else ""
    section = section[:nxt.start()] if nxt else section
    kept: list[str] = []
    seen: set[str] = set()
    rows = 0
    for line in section.split("\n"):
        cells = [c.strip() for c in line.strip().strip("|").split("|")] if line.lstrip().startswith("|") else []
        if len(cells) < 2 or re.fullmatch(r":?-{2,}:?", cells[0]) or cells[0].lower() in ("begriff", "term"):
            kept.append(line)
            continue
        term = re.sub(r"[`*]", "", cells[0]).strip()
        base = re.split(r"\s*\(", term)[0].strip().lower()
        if not base or base in seen or not cells[1] or base not in body or rows >= limit:
            continue
        seen.add(base)
        rows += 1
        kept.append(line)
    return head + "\n".join(kept) + rest
