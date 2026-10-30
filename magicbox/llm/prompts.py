"""Prompt-Bausteine. Bewusst kurz und strikt formuliert – kleine Modelle profitieren von klaren Vorgaben."""

from __future__ import annotations

from magicbox.config import Settings

DOC_HEADINGS = [
    ("Kurzfassung", "3–5 Sätze: Was ist das, wofür ist es da, für wen ist es gedacht? Für Nicht-Experten."),
    ("Was ist das für eine Datei?", "Format, Plattform, Programmiersprache/Compiler, Herkunft (Hersteller, Version), sofern belegt."),
    ("Was macht sie?", "Die Funktionsweise Schritt für Schritt bzw. die Hauptfunktionen. Nutze Aufzählungen. Gibt es "
                       "„Erkannte Funktionsbereiche“: je Bereich ein Punkt, keinen auslassen."),
    ("Aufbau & wichtige Komponenten", "Wichtige Funktionen/Klassen/Module/Dateien und ihr Zusammenspiel. Gern eine Tabelle."),
    ("Schnittstellen & Abhängigkeiten", "Bibliotheken, Netzwerk (Adressen, Protokolle), Dateien, Registry, Kommandozeilen-Parameter, Konfiguration."),
    ("Technische Besonderheiten", "Verwendete Frameworks/Laufzeitumgebungen, Build-Details, Plattform-Eigenheiten."),
    ("Offene Fragen & Grenzen der Analyse", "Was ließ sich statisch nicht klären? Was wären sinnvolle nächste Schritte?"),
    ("Glossar", "Kurze, einfache Erklärungen der oben verwendeten Fachbegriffe (Tabelle: Begriff | Erklärung), "
                "höchstens 25 Einträge."),
]


MALWARE_HEADINGS = [
    ("Kurzfassung", "Beginne mit 'Einstufung: harmlos | verdächtig | bösartig'. Dann 3–5 Sätze: vermutete Kategorie "
                    "(z. B. Infostealer, Ransomware, Loader, RAT, Adware), Hauptzweck, Gefährlichkeit. Eine Malware-Familie nur "
                    "nennen, wenn sie durch YARA-Treffer belegt ist."),
    ("Verhalten & Fähigkeiten", "Was kann die Datei? Belege jede Aussage (Import, capa-Regel, String, Code-Stelle)."),
    ("Ablauf / Infektionskette", "Stufen der Ausführung, dekodierte oder entpackte Teile, nachgeladene Payloads."),
    ("Kommunikation & Exfiltration", "C2-Server, Protokolle, welche Daten vermutlich abfließen."),
    ("Persistenz & Tarnung", "Autostart, Dienste, Verschleierung, Anti-Analyse – sofern belegt."),
    ("Indikatoren (IOCs)", "Tabelle Typ | Wert | Bedeutung mit den wichtigsten IOCs. Nur Werte aus den Fakten übernehmen, "
                           "Punkte als [.] und http als hxxp schreiben."),
    ("MITRE ATT&CK", "Tabelle ID | Technik | Beleg – nur Techniken, die durch die Fakten gestützt sind."),
    ("Erkennung & Gegenmaßnahmen", "Wie erkennt man eine Infektion, was blockieren/bereinigen? Konkret und umsetzbar."),
    ("Offene Fragen & nächste Schritte", "Was blieb statisch unklar (z. B. verschlüsselte Konfiguration)? Empfehlung, "
                                         "z. B. dynamische Analyse in einer isolierten Sandbox."),
    ("Glossar", "Kurze, einfache Erklärungen der oben verwendeten Fachbegriffe (Tabelle: Begriff | Erklärung), "
                "höchstens 25 Einträge."),
]


def headings(s: Settings) -> list[tuple[str, str]]:
    return MALWARE_HEADINGS if s.profile == "malware" else DOC_HEADINGS


def system_prompt(s: Settings) -> str:
    purpose = ("Ziel ist eine Software-Dokumentation, keine Sicherheitsanalyse: Bewerte nicht, ob die Software "
               "schädlich oder vertrauenswürdig ist, und vermute keine Schadfunktionen – beschreibe sachlich, was sie tut "
               "und wie sie aufgebaut ist.\n")
    if s.profile == "malware":
        purpose = ("Die Analyse dient der Abwehr (Incident Response, Threat Intelligence, Schutz eigener Systeme). "
                   "Beschreibe das Verhalten sachlich und vollständig, gib aber keine Anleitungen zur Nutzung, "
                   "Verbesserung oder Verbreitung der Software.\n")
    return (
        "Du bist ein erfahrener Reverse Engineer und technischer Redakteur. Du bekommst die Ergebnisse "
        "einer automatisierten, rein statischen Analyse (die Datei wurde nie ausgeführt).\n" + purpose +
        "Regeln:\n"
        "1. Stütze dich ausschließlich auf die gelieferten Fakten. Erfinde keine Funktionen, Namen oder Zahlen.\n"
        "2. Kennzeichne Schlussfolgerungen deutlich mit „vermutlich“ oder „deutet darauf hin“.\n"
        f"3. Schreibe {s.audience}. Erkläre Fachbegriffe beim ersten Auftreten kurz.\n"
        f"4. Antworte ausschließlich auf {s.language}, in sauberem Markdown, ohne Einleitungsfloskeln.\n"
        "5. Steht unter „Produkt laut Datei“ ein Name, Hersteller oder eine Version, übernimm genau diese Angaben "
        "und rate keine anderen Produkte.\n"
        "6. Nenne nur DLLs, Bibliotheken, Funktionen und Adressen, die wörtlich in den Fakten stehen.\n"
        "7. IP-Adressen und URLs aus Zeichenketten belegen keine Verbindung – oft stammen sie aus eingebauten "
        "Bibliotheken (z. B. DNS-Anbieterlisten von Browsern).\n"
        "8. „TLS-Callbacks“ bedeutet Thread Local Storage, nicht TLS/SSL-Verschlüsselung.\n"
        "9. Funktionen bekannter Laufzeitumgebungen und Bibliotheken (V8, Node.js, Chromium, OpenSSL, Qt …) gehören "
        "nicht zur eigentlichen Programmlogik – beschreibe sie nur als verwendete Technik. Ist eine "
        "Laufzeitumgebung genannt, erkläre, wo die eigentliche Programmlogik liegt.\n"
        "10. Gibt es eine „Funktionslandkarte“ (je Datei oder für die gesamte App), nutze IPC-Kanäle, Aktions-/Ereignisnamen, "
        "Endpunkte und Oberflächentexte, um konkrete Funktionen der Anwendung zu benennen (z. B. „Titel herunterladen“ "
        "statt „Netzwerkoperationen“). Minifizierter Code hat verkürzte Variablennamen – stütze dich auf diese "
        "Zeichenketten statt auf die Namen. Steht dort eine Tabelle angesprochener Server, behaupte nicht, es "
        "gäbe keine Adressen.\n"
        "11. Gibt es „Erkannte Funktionsbereiche“, gliedere die Beschreibung der Funktionen danach: jeder Bereich "
        "ein Punkt, in eigenen Worten erklärt, mit 1–2 Belegen (Kanal-/Aktionsname) – die wichtigsten zuerst."
    )


def code_notes_prompt(name: str, part: int, total: int, code: str, context: str, security: bool = True) -> str:
    focus = ("auffällige oder sicherheitsrelevante Stellen" if security
             else "Besonderheiten der Implementierung (keine Sicherheitsbewertung)")
    return (
        f"Datei: {name}. Hier ist Teil {part} von {total} des extrahierten Codes (Quelltext, Pseudocode oder Disassembly).\n"
        f"Kontext zur Datei:\n{context}\n\n"
        f"```\n{code}\n```\n\n"
        "Fasse diesen Teil in höchstens 12 Stichpunkten zusammen: Zweck der enthaltenen Funktionen/Klassen, "
        "wichtige Abläufe und Datenflüsse, verwendete Schnittstellen (Netzwerk, Dateien, Prozesse, Krypto), "
        f"{focus}. Nenne Funktionsnamen. Keine Einleitung."
    )


def child_notes_prompt(name: str, facts: str, security: bool = True) -> str:
    third = ("gibt es sicherheitsrelevante Auffälligkeiten (mit Beleg)?" if security
             else "was ist technisch bemerkenswert?")
    return (
        f"Analyse-Fakten zur Datei „{name}“ (Teil eines Archivs, Ordners oder eine entpackte/dekodierte Stufe):\n\n"
        f"{facts}\n\n"
        "Beschreibe in 3–6 Stichpunkten: Was ist diese Datei, welche Rolle spielt sie vermutlich im Gesamtpaket, "
        f"{third} Keine Einleitung."
    )


def document_prompt(name: str, facts: str, notes: str, s: Settings) -> str:
    outline = "\n".join(f"## {h}\n({hint})" for h, hint in headings(s))
    notes_block = f"\n\n# Zusammenfassungen der Code-Teile bzw. enthaltenen Dateien\n{notes}" if notes else ""
    return (
        f"# Analyse-Fakten zu „{name}“\n{facts}{notes_block}\n\n"
        "# Auftrag\n"
        f"Erstelle daraus eine verständliche Dokumentation auf {s.language}. Verwende exakt diese Gliederung "
        "(Überschriften ggf. in die Zielsprache übersetzen, Hinweise in Klammern nicht übernehmen):\n\n"
        f"{outline}"
    )


def search_terms_prompt(question: str) -> str:
    return (
        f"Frage zu einer analysierten Datei: „{question}“\n\n"
        "Welche Begriffe würden im Programmcode (Pseudocode, dekompilierter Code, Skript) an der gesuchten Stelle "
        "vorkommen? Denke an englische API- und Funktionsnamen, Bibliotheken und typische Teilwörter "
        "(z. B. für Netzwerk: socket, connect, send, http, InternetOpen; für Verschlüsselung: crypt, aes, xor, key). "
        "Antworte nur mit 5 bis 20 Begriffen in einer Zeile, durch Kommas getrennt, ohne Erklärung."
    )


def question_prompt(name: str, facts: str, code: str, partial: bool, question: str, s: Settings) -> str:
    code_block = ""
    if code:
        hint = ("(Auszug: die zur Frage passendsten Stellen laut Stichwortsuche – nicht der vollständige Code.)\n\n"
                if partial else "")
        code_block = f"\n\n# Code-Stellen\n{hint}{code}"
    return (
        f"# Analyse-Fakten zu „{name}“\n{facts}{code_block}\n\n"
        f"# Frage\n{question}\n\n"
        "# Auftrag\n"
        f"Beantworte die Frage auf {s.language}, ausschließlich anhand der Fakten und Code-Stellen oben.\n"
        "- Geht es um eine Funktion oder Stelle im Code: Nenne sie genau (Name bzw. Adresse, Klasse/Methode) und "
        "erkläre verständlich, was sie tut – Schritt für Schritt, mit Ein- und Ausgaben, aufgerufenen APIs und ihrer "
        "Rolle im Gesamtprogramm. Zitiere kurze, aussagekräftige Code-Zeilen.\n"
        "- Kommen mehrere Stellen in Frage, nenne die wahrscheinlichste zuerst und die übrigen kurz.\n"
        "- Lässt sich die Frage mit diesen Daten nicht sicher beantworten, sag das ehrlich, nenne, was am nächsten "
        "dran ist, und wie man weiterkommt.\n"
        "Beginne direkt mit der Antwort, ohne die Frage zu wiederholen."
    )
