# 🪄📦 Magic Box

**Datei rein – verständliche Doku raus.**

Magic Box ist eine Desktop-Anwendung, die Dateien automatisiert **statisch** auseinandernimmt (Reverse Engineering),
die Ergebnisse an ein **lokales LLM** (z. B. Ollama auf deinem Dell PowerEdge R640) schickt und daraus eine
gut lesbare **Dokumentation** erzeugt – als HTML, Markdown und JSON.

```
 Datei / Ordner ──► Statische Analyse ──► Faktenbasis ──► lokales LLM (R640) ──► Bericht (HTML/MD/JSON)
                    (wird NIE ausgeführt)   (portioniert für      (optional)          + technischer Anhang
                                             kleine Modelle)
```

## Was wird erkannt und analysiert?

| Format | Was Magic Box herausholt |
|---|---|
| **Windows PE** (EXE, DLL, SYS) | Header, Compile-Zeit, Subsystem, Schutzmechanismen (ASLR/DEP/CFG), Signatur, Versions-Infos, Sektionen + Entropie, Imports/Exports, Ressourcen, Packer (UPX, Themida, VMProtect …), .NET-Erkennung, Disassembly |
| **Linux ELF** | Architektur, Interpreter, benötigte Libs, Härtung (PIE/NX/RELRO/Canary/FORTIFY), Symbole, Sektionen, Disassembly der wichtigsten Funktionen mit aufgelösten PLT-Aufrufen (`call puts@plt`) |
| **macOS Mach-O** (inkl. Universal/Fat) | Architekturen, Dateityp, gelinkte Frameworks, Segmente, Code-Signatur, FairPlay-Verschlüsselung |
| **Java** `.class` / `.jar` / `.war` | Rekonstruierte Klassenstruktur (Felder, Methoden mit Signaturen), aufgerufene Methoden, String-Konstanten, sicherheitsrelevante APIs |
| **Android APK** | Inhalt, Berechtigungen (z. B. SMS, Standort), Klassen/DEX |
| **Archive** ZIP, TAR, GZ, BZ2, XZ, Office (DOCX/XLSX/PPTX) | Rekursiv bis zur eingestellten Tiefe, komplett im Speicher (kein Entpacken auf die Platte), Schutz vor ZIP-Bomben, VBA-Makro-Erkennung |
| **Quelltext/Skripte** (Python, JS/TS, PowerShell, Bash, C/C++, C#, Go, Rust, PHP, Java …) | Struktur (Klassen/Funktionen), Imports, verdächtige Muster (eval, Base64, kodierte PowerShell, Zugangsdaten im Code, Obfuskation) |
| **PDF** | Aktive Inhalte (JavaScript, OpenAction, Launch, eingebettete Dateien) |
| **Alles** | Hashes (MD5/SHA-1/SHA-256), Entropie, kategorisierte Strings (URLs, IPs, Pfade, Registry, Befehle, Secrets) |

Optional nutzt Magic Box **radare2** (falls installiert) für Funktionserkennung und **Pseudo-C-Code**,
der dem LLM deutlich besser hilft als reines Assembly.

Aus Imports/APIs werden außerdem **Fähigkeiten** abgeleitet (Netzwerk, Prozesse starten, Code-Injektion,
Registry, Autostart, Krypto …) und als Auffälligkeiten mit Ampel bewertet.

## Schnellstart

### 1. LLM auf dem R640 einrichten

Siehe **[docs/R640-LLM-Setup.md](docs/R640-LLM-Setup.md)** – kurz:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

```bash
sudo systemctl edit ollama.service   # OLLAMA_HOST=0.0.0.0:11434 setzen (siehe Anleitung)
```

```bash
ollama pull qwen2.5-coder:7b
```

### 2. Magic Box auf dem Desktop starten

Voraussetzung: Python ≥ 3.10.

**Windows:** Doppelklick auf `scripts\start_windows.bat`

**Linux/macOS:**

```bash
./scripts/start_linux.sh
```

Oder manuell:

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -e '.[gui]'
```

```bash
magicbox gui
```

Beim ersten Start unter **⚙️ Einstellungen** die Server-URL eintragen (z. B. `http://r640:11434` oder
`http://192.168.1.50:11434`), **Modelle laden** klicken, Modell wählen, **Verbindung testen**.

### 3. Datei reinwerfen

Datei oder Ordner auf die Box ziehen → im Tab **🤖 KI live** schreibt das Modell mit → danach erscheint die
Doku im Tab **📖 Dokumentation**. „🌐 Im Browser öffnen“ zeigt den schön formatierten HTML-Bericht (mit Dark Mode).

Ohne erreichbaren LLM-Server entsteht trotzdem ein Bericht – dann mit automatischer Kurzfassung und
technischem Anhang, aber ohne KI-Text.

## Aufbau des Berichts

1. **Auf einen Blick** – regelbasierte Kurzfassung mit Ampel (funktioniert auch ohne KI)
2. **KI-Dokumentation** – Kurzfassung · Was ist das? · Was macht es? · Aufbau & Komponenten ·
   Schnittstellen · Sicherheitsbewertung · Offene Fragen · Glossar
3. **Auffälligkeiten** – alle Befunde aller (auch verschachtelter) Dateien, nach Schwere sortiert
4. **Technischer Anhang** – alle Rohdaten: Header, Tabellen, Strings, Disassembly/Pseudocode, Inhalte von Archiven

Gespeichert wird in `~/MagicBox/Berichte/<datei>_<zeitstempel>/` (`bericht.html`, `bericht.md`, `analysis.json`).

## Kommandozeile & „Magic-Box-Ordner“ auf dem Server

```bash
magicbox analyze verdaechtig.exe --url http://r640:11434 --model qwen2.5-coder:7b --open
```

```bash
magicbox analyze firmware.zip --no-llm          # nur technische Analyse
```

```bash
magicbox check --url http://r640:11434          # Verbindung + Modell prüfen
```

**Drop-Folder-Modus** – ideal direkt auf dem R640 mit einer Samba-Freigabe: Datei in den Ordner kopieren,
kurz darauf liegt der Bericht in `_berichte/`, das Original wird nach `_erledigt/` verschoben.

```bash
magicbox watch /srv/magicbox/eingang --url http://127.0.0.1:11434
```

Ein passender systemd-Dienst liegt unter [`scripts/magicbox-watch.service`](scripts/magicbox-watch.service).

## Wie kleine Modelle trotzdem gute Dokus schreiben

Kleine lokale Modelle (7–14 B Parameter) haben wenig Kontext und neigen zum Fantasieren. Magic Box hilft ihnen:

- **Fakten statt Rohdaten:** Das Modell bekommt eine verdichtete, priorisierte Faktenbasis
  (Header, Fähigkeiten, Imports, Auffälligkeiten zuerst – Strings und Code nach Platz).
- **Map-Reduce:** Ist der Code zu groß, wird er in Teile zerlegt; jeder Teil wird einzeln zusammengefasst,
  danach entsteht aus allen Notizen die Gesamtdoku. Bei Archiven/Ordnern bekommt jede interessante Datei
  eine eigene Kurzanalyse.
- **Korrekte Kontextgröße:** `num_ctx` wird explizit an Ollama übergeben (Ollamas Standard ist klein und
  schneidet sonst still ab).
- **Strenge Regeln im Prompt:** nur belegte Fakten, Vermutungen kennzeichnen, feste Gliederung.
- `<think>`-Blöcke von Reasoning-Modellen (z. B. Qwen3) werden automatisch entfernt.

Alle Parameter (Kontextgröße, Temperatur, Sprache, Zielgruppe, Anzahl Teilanalysen) sind in den Einstellungen
anpassbar. Die Zielgruppe lässt sich z. B. auf „für Sicherheitsanalysten“ oder „für das Management“ umstellen.

## Sicherheit

- Dateien werden **nie ausgeführt** – alles ist statische Analyse. Archive werden im Speicher gelesen.
- Trotzdem gilt bei Malware: Analyse am besten in einer **isolierten VM**, Berichte enthalten u. a.
  URLs/IPs aus der Probe.
- Der HTML-Bericht ist gegen eingeschleustes HTML/JavaScript abgesichert (kein rohes HTML aus Probe oder
  KI-Antwort, Content-Security-Policy, keine externen Bilder/Links mit `javascript:`).
- Daten verlassen dein Netzwerk nicht, solange der LLM-Server lokal ist.
- Bitte nur Software analysieren, für die du die Berechtigung hast (eigene Software, Interoperabilität,
  Sicherheitsforschung im rechtlichen Rahmen).

## Erweitern

Ein neuer Analyzer ist eine kleine Klasse in `magicbox/analyzers/`:

```python
class MeinAnalyzer(Analyzer):
    name = "mein"
    kinds = ("pe",)            # für welche Dateitypen

    def analyze(self, ctx, result):
        result.add(Section("Meine Erkenntnis", kv={"Wert": "42"}, llm_priority=1))
        result.find("medium", "Etwas Auffälliges", "Details …")
```

…und in `magicbox/analyzers/__init__.py` in `ANALYZERS` eintragen. Alles Weitere (Bericht, LLM-Kontext) passiert
automatisch.

Ideen für später: Ghidra-Headless-Dekompilierung, .NET-Dekompilierung (ILSpy-CLI), YARA-Regeln,
`.pyc`-Dekompilierung, Batch-Vergleich zweier Versionen (Diff-Doku).

## Entwicklung

```bash
pip install -e '.[gui,dev]'
```

```bash
pytest
```

Die Tests brauchen keinen echten LLM-Server (ein Fake-Server spricht das Ollama- und OpenAI-Protokoll) und
erzeugen ihre Testdateien selbst.

Eigenständige `.exe` bauen (optional, unter Windows):

```bash
pip install pyinstaller
```

```bash
pyinstaller --noconsole --name MagicBox --collect-data magicbox -p . magicbox/gui/app.py
```

## Projektstruktur

```
magicbox/
├── analyzers/      # identify, strings, pe, elf, macho, java, archive, source(+pdf), radare2, disasm, apis
├── llm/            # client (Ollama/OpenAI-kompatibel), prompts, documenter (Map-Reduce)
├── report/         # Markdown/HTML/JSON-Bericht + style.css
├── gui/            # PySide6-Oberfläche (Drop-Zone, Aufträge, Live-KI, Einstellungen)
├── engine.py       # rekursive Analyse-Engine
├── pipeline.py     # Datei → Analyse → LLM → Bericht
└── cli.py          # analyze | watch | check | models | gui
docs/R640-LLM-Setup.md
scripts/            # Startskripte, systemd-Dienst
tests/
```
