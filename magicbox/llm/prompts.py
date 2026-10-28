"""Prompt-Bausteine. Bewusst kurz und strikt formuliert – kleine Modelle profitieren von klaren Vorgaben."""

from __future__ import annotations

from magicbox.config import Settings

DOC_HEADINGS = [
    ("Kurzfassung", "3–5 Sätze: Was ist das, wofür ist es da, wie vertrauenswürdig wirkt es? Für Nicht-Experten."),
    ("Was ist das für eine Datei?", "Format, Plattform, Programmiersprache/Compiler, Herkunft (Hersteller, Version), sofern belegt."),
    ("Was macht sie?", "Die Funktionsweise Schritt für Schritt bzw. die Hauptfunktionen. Nutze Aufzählungen."),
    ("Aufbau & wichtige Komponenten", "Wichtige Funktionen/Klassen/Module/Dateien und ihr Zusammenspiel. Gern eine Tabelle."),
    ("Schnittstellen & Abhängigkeiten", "Bibliotheken, Netzwerk (Adressen, Protokolle), Dateien, Registry, Kommandozeilen-Parameter, Konfiguration."),
    ("Sicherheitsbewertung", "Beginne mit einer Zeile 'Einstufung: unbedenklich | auffällig | gefährlich' und begründe sie mit Belegen."),
    ("Offene Fragen & Grenzen der Analyse", "Was ließ sich statisch nicht klären? Was wären sinnvolle nächste Schritte?"),
    ("Glossar", "Kurze, einfache Erklärungen der verwendeten Fachbegriffe (Tabelle: Begriff | Erklärung)."),
]


def system_prompt(s: Settings) -> str:
    return (
        "Du bist ein erfahrener Reverse Engineer und technischer Redakteur. Du bekommst die Ergebnisse "
        "einer automatisierten, rein statischen Analyse (die Datei wurde nie ausgeführt).\n"
        "Regeln:\n"
        "1. Stütze dich ausschließlich auf die gelieferten Fakten. Erfinde keine Funktionen, Namen oder Zahlen.\n"
        "2. Kennzeichne Schlussfolgerungen deutlich mit „vermutlich“ oder „deutet darauf hin“.\n"
        f"3. Schreibe {s.audience}. Erkläre Fachbegriffe beim ersten Auftreten kurz.\n"
        f"4. Antworte ausschließlich auf {s.language}, in sauberem Markdown, ohne Einleitungsfloskeln."
    )


def code_notes_prompt(name: str, part: int, total: int, code: str, context: str) -> str:
    return (
        f"Datei: {name}. Hier ist Teil {part} von {total} des extrahierten Codes (Quelltext, Pseudocode oder Disassembly).\n"
        f"Kontext zur Datei:\n{context}\n\n"
        f"```\n{code}\n```\n\n"
        "Fasse diesen Teil in höchstens 12 Stichpunkten zusammen: Zweck der enthaltenen Funktionen/Klassen, "
        "wichtige Abläufe und Datenflüsse, verwendete Schnittstellen (Netzwerk, Dateien, Prozesse, Krypto), "
        "auffällige oder sicherheitsrelevante Stellen. Nenne Funktionsnamen. Keine Einleitung."
    )


def child_notes_prompt(name: str, facts: str) -> str:
    return (
        f"Analyse-Fakten zur Datei „{name}“ (Teil eines Archivs/Ordners):\n\n{facts}\n\n"
        "Beschreibe in 3–6 Stichpunkten: Was ist diese Datei, welche Rolle spielt sie vermutlich im Gesamtpaket, "
        "gibt es sicherheitsrelevante Auffälligkeiten? Keine Einleitung."
    )


def document_prompt(name: str, facts: str, notes: str, s: Settings) -> str:
    outline = "\n".join(f"## {h}\n({hint})" for h, hint in DOC_HEADINGS)
    notes_block = f"\n\n# Zusammenfassungen der Code-Teile bzw. enthaltenen Dateien\n{notes}" if notes else ""
    return (
        f"# Analyse-Fakten zu „{name}“\n{facts}{notes_block}\n\n"
        "# Auftrag\n"
        f"Erstelle daraus eine verständliche Dokumentation auf {s.language}. Verwende exakt diese Gliederung "
        "(Überschriften ggf. in die Zielsprache übersetzen, Hinweise in Klammern nicht übernehmen):\n\n"
        f"{outline}"
    )
