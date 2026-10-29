# 🪄📦 Magic Box

**Datei rein – verständliche Doku raus. Komplett lokal, auch komplett offline.**

Magic Box nimmt Dateien – auch Schadsoftware – **statisch** auseinander (sie werden nie ausgeführt), lässt ein
**lokales LLM** (z. B. auf deinem PowerEdge R640) daraus eine verständliche Dokumentation schreiben und liefert
einen Bericht mit Bewertung, IOCs, MITRE ATT&CK und allen Rohdaten. Keine Cloud, keine Ablehnungen, keine Daten,
die dein Netzwerk verlassen.

```
 Desktop-App / Browser ──(Upload)──►  Magic-Box-Server (R640, Linux)  ──►  lokales LLM (Ollama, localhost)
                                       │  entpacken · zerlegen · bewerten
 Drop-Ordner (Samba) ─────────────────►│  YARA · capa · radare2 · ILSpy · olevba · UPX · 7-Zip
                                       └─► Bericht (HTML/MD/JSON) + IOCs (CSV)
```

## Aufbau – wie bei Spotify & Co.

| Teil | Was es ist |
|---|---|
| **Server** (`magicbox server`) | Nimmt Proben entgegen, arbeitet sie nacheinander ab, speichert Berichte. Läuft ideal auf dem R640 (Linux) – dort kann eine Windows-Probe nicht versehentlich gestartet werden. |
| **Web-Oberfläche** | Wird vom Server ausgeliefert. Komplett offline (kein CDN, keine externen Fonts), dunkles Design. |
| **Windows-App** (`desktop/`) | Echte Win32-Anwendung (WinForms, .NET Framework 4.8 – auf Windows 10/11 schon vorhanden) im Office-2003-Design. Spricht ausschließlich über die REST-API mit dem Server, Live-Ansicht per Server-Sent Events, Anmeldung über den System-Browser (Ory). Installer ≈ 300 KB. |
| **Desktop-App für Linux/macOS** (`magicbox desktop`) | Fenster mit eingebettetem Chromium (Qt WebEngine) um die Web-Oberfläche; ohne Server-Adresse startet sie einen eigenen Server lokal. |
| **Drop-Ordner** | Datei in einen (Samba-)Ordner legen → taucht als Auftrag in der Oberfläche auf. |
| **CLI** | `magicbox analyze probe.exe` für Skripte und Batch-Läufe. |

## Was analysiert wird

| Format | Was Magic Box herausholt |
|---|---|
| **Windows PE** (EXE/DLL/SYS) | Header, Compile-Zeit, Schutzmechanismen, Signatur, Versions-Infos, Sektionen + Entropie, Imports/Exports, Ressourcen, Packer, Disassembly bzw. radare2-Pseudocode |
| **.NET** | Klassen, Methoden, **String-Literale** (oft die Malware-Konfiguration: C2, Keys), aufgerufene APIs, Obfuskations-Erkennung, **Dekompilierung nach C#** (ILSpy) |
| **UPX-gepackt** | Wird automatisch entpackt, die entpackte Datei wird zusätzlich analysiert |
| **Linux ELF / macOS Mach-O** | Architektur, Libs, Härtung, Symbole, Disassembly/Pseudocode mit aufgelösten Aufrufen |
| **Archive** ZIP, 7z, RAR, TAR, GZ, XZ, BZ2 | Rekursiv; **Passwort-Archive** (`infected` & Co., auch AES) werden automatisch geöffnet; Schutz vor ZIP-Bomben |
| **Office** (DOC/XLS/DOCM/XLSM …) | **VBA-/XLM-Makros** extrahieren (olevba), AutoOpen & verdächtige Funktionen bewerten |
| **Skripte** (PowerShell, JS, VBS, Python, Bash, …) | Struktur, verdächtige Muster, **Deobfuskation**: `-EncodedCommand`, Base64-/Hex-Blobs → dekodierte Stufen und eingebettete EXEs werden weiter analysiert |
| **Java/Android** (CLASS, JAR, APK) | Klassenstruktur, aufgerufene Methoden, Konstanten, Berechtigungen |
| **PDF** | Aktive Inhalte (JavaScript, OpenAction, Launch, eingebettete Dateien) |
| **Alles** | Hashes, Entropie, Strings, **YARA** (Basisregeln + eigene/Community-Regeln), **capa** (Fähigkeiten + MITRE ATT&CK), **IOCs** (URLs, Domains, IPs, E-Mails, Registry, Pfade, Wallets) |

## Der Bericht

1. **Auf einen Blick** – Ampel, YARA-Treffer, erkannte Fähigkeiten (funktioniert auch ohne KI)
2. **KI-Dokumentation** (Profil *Malware*): Einstufung · Verhalten · Infektionskette · Kommunikation/Exfiltration ·
   Persistenz & Tarnung · IOCs · MITRE ATT&CK · Erkennung & Gegenmaßnahmen · offene Fragen · Glossar
   (Profil *Software*: Funktionsweise, Aufbau, Schnittstellen usw.)
3. **Auffälligkeiten** aller (auch verschachtelter/entpackter) Dateien
4. **IOCs** – entschärft (`hxxp://evil[.]com`) plus `iocs.csv` zum Import in Firewall/SIEM
5. **Technischer Anhang** – alle Rohdaten

### Fragen an die KI

Beim Hochladen (Feld *Frage an die KI*) oder später zu jedem fertigen Auftrag kannst du frei fragen, z. B.
„Suche die Funktion, die die Verbindung zum Server aufbaut, und erkläre sie verständlich.“
Die Antworten stehen oben im Bericht unter *Deine Fragen an die KI* (neueste zuerst).

Passt der extrahierte Code nicht komplett in den Kontext des Modells, leitet die KI zuerst Suchbegriffe aus der
Frage ab (z. B. `socket, connect, InternetOpen`); per Stichwortsuche werden dann die passendsten Funktionen,
Methoden bzw. Makros ausgewählt und mit den Analyse-Fakten an das Modell gegeben. Nachfragen analysieren die
Datei nicht neu – nur die KI arbeitet.

## Schnellstart

### Easy Setup (empfohlen)

Ein Skript fragt alles Nötige ab, schlägt sinnvolle Werte vor und prüft am Ende selbst, ob alles läuft:

**Mit Ory-Anmeldung** (Gateway mit nginx + Hydra/Kratos, Analyse auf dem R640):

```bash
sudo ./scripts/easy-setup.sh gateway      # auf dem Gateway: Hydra-Client, nginx + Zertifikat, Gruppe
```

```bash
scp magicbox-setup.env <benutzer>@<r640>:~/magicbox/
```

```bash
sudo ./scripts/easy-setup.sh server --env magicbox-setup.env   # auf dem R640: alles andere
```

**Ohne Ory** (ein Rechner, Zugangsschlüssel):

```bash
sudo ./scripts/easy-setup.sh solo
```

`--dry-run` zeigt nur an, was passieren würde; ein zweiter Lauf übernimmt die gespeicherten Antworten.
Für die Gateway-Rolle reicht die einzelne Datei `scripts/easy-setup.sh`.

### Server von Hand installieren

```bash
sudo ./scripts/install_server.sh --model qwen3-coder:30b
```

Das Skript (Debian 12/13 oder Ubuntu 22.04/24.04) installiert alles (Werkzeuge, capa-Regeln, YARA-Forge-Regeln, ILSpy, Ollama + Modell), richtet den
gesperrten systemd-Dienst ein und zeigt am Ende die URL mit Zugangsschlüssel. Ollama bleibt dabei auf `localhost`
– nur die Magic Box (Port 8765) ist im LAN erreichbar.

**Ganz ohne Internet?** Auf einem Online-Rechner `./scripts/make_offline_bundle.sh` ausführen, das Paket
rüberkopieren und `install_server.sh --offline` (bzw. `easy-setup.sh server` im entpackten Bundle) nutzen.
Details: [docs/R640-LLM-Setup.md](docs/R640-LLM-Setup.md).

### Windows-App (nativ, Office-2003-Design)

**Installer:** `MagicBox-Setup-<Version>.exe` – fragt die Server-Adresse ab (vorbelegt `https://magicbox.hackdv.com`),
legt Startmenü-/Desktop-Verknüpfung an und braucht keine Adminrechte. Gebaut wird er automatisch per GitHub Actions
(Workflow „Desktop-Installer (Windows)“, Download unter *Actions → Artefakte*; bei Tags `v*` zusätzlich am Release).
Lokal unter Windows: `powershell -ExecutionPolicy Bypass -File packaging\build_installer.ps1` (braucht .NET SDK 8 und
Inno Setup 6). Stille Verteilung: `MagicBox-Setup-0.1.0.exe /VERYSILENT /SERVER=https://magicbox.hackdv.com`.

**Aufbau wie Outlook/Word 2003:** links der Navigationsbereich *Aufträge*, in der Mitte der Auftrag (Schritte
Analyse → KI → Bericht, Fortschritt, Fragefeld, Register *Bericht · KI live · Protokoll*), rechts der
Aufgabenbereich *Neue Analyse* (Strg+F1). Dateien per Drag & Drop oder Strg+O; Bericht drucken (Strg+P),
als HTML/Markdown/JSON/IOC-CSV speichern; Server-Einstellungen und Werkzeug-Übersicht unter *Extras*.

**Anmeldung:** Beim ersten Start öffnet die App den Browser. Dort läuft der gewohnte Ory-Login (Captcha, 2FA);
anschließend bestätigst du auf einer Seite der Magic Box „Desktop-App zulassen“. Der Browser springt zurück
zu `http://127.0.0.1:<port>/callback`, die App tauscht den Einmal-Code per PKCE gegen ein API-Token
(`Authorization: Bearer mbd_…`, 30 Tage gültig, `desktop_session_days`). Das Token liegt DPAPI-verschlüsselt in
`%APPDATA%\MagicBox\desktop.json`; *Datei → Abmelden* widerruft es auf dem Server. Bei Servern mit
Zugangsschlüssel (`web_token`) fragt die App den Schlüssel direkt ab.

**Linux/macOS:** `./scripts/start_linux.sh` bzw. `magicbox desktop --server http://192.168.1.50:8765`
(Qt-WebEngine-Fenster um die Web-Oberfläche; ohne Server-Adresse startet ein lokaler Server).

### Nur im Browser

`http://<r640>:8765/?token=<schlüssel>` öffnen – fertig.

## Werkzeuge

Alle externen Werkzeuge sind optional – fehlt eins, wird der Schritt übersprungen. Den Status zeigt die
Oberfläche oben unter **🧰 Werkzeuge**.

| Werkzeug | Wofür | Installation |
|---|---|---|
| radare2 | Funktionserkennung, Pseudocode | `apt install radare2` |
| UPX | Entpacken | `apt install upx-ucl` |
| 7-Zip | 7z/RAR, AES-ZIPs | `apt install p7zip-full` |
| capa + Regeln | Fähigkeiten, MITRE ATT&CK | `pip install flare-capa` + [capa-rules](https://github.com/mandiant/capa-rules) (macht das Installationsskript) |
| YARA | Familien-/Verhaltenserkennung | `pip install yara-python`; Regeln z. B. von [YARA-Forge](https://github.com/YARAHQ/yara-forge) |
| ILSpy (ilspycmd) | .NET → C# | `dotnet tool install -g ilspycmd --version 8.2.0.7535` |
| oletools, dnfile, pyzipper | Makros, .NET-Metadaten, AES-ZIP | `pip install -e '.[malware]'` |

## Sicherheit

- **Nie ausgeführt:** alles ist statische Analyse. Proben werden ohne Ausführungsrechte gespeichert und nie
  wieder ausgeliefert (nur Berichte).
- **Anmeldung:** Zugangsschlüssel oder dein **Ory-Stack** – als OIDC-Client bei Hydra (empfohlen), über die
  Kratos-Sitzung oder hinter Oathkeeper. Captcha/2FA kommen aus deinem Login-UI, Freigabe nach Gruppe
  (`groups`-Claim), E-Mail oder Domain.
  Anleitung: [docs/Ory-Anmeldung.md](docs/Ory-Anmeldung.md).
- **Server-Härtung:** systemd-Sandbox (read-only System, kein Home, eigene /tmp), CSRF-Schutz,
  Schutz vor DNS-Rebinding, Content-Security-Policy.
- **Berichte sind sicher zu öffnen:** kein HTML/JavaScript aus Probe oder KI-Antwort, IOCs entschärft,
  Bericht in einem abgeschotteten iframe.
- **Netz:** Ollama nur auf localhost; für echten Offline-Betrieb ausgehenden Verkehr am Server sperren.
- Empfehlung: Server als eigene VM ohne Internetzugang. Nur Dateien analysieren, für die du berechtigt bist.

## Kommandozeile

```bash
magicbox server --host 0.0.0.0 --watch /srv/magicbox/eingang     # Server + Drop-Ordner
magicbox desktop [--server URL]                                  # Desktop-App
magicbox analyze probe.exe --open                                # einzelne Datei, Bericht im Browser
magicbox analyze probe.zip --no-llm                              # nur technische Analyse
magicbox check --url http://127.0.0.1:11434 --model qwen3-coder:30b
```

## Entwicklung

```bash
pip install -e '.[desktop,malware,dev]'
```

```bash
pytest
```

Die Tests brauchen kein echtes LLM (ein Fake-Server spricht Ollama- und OpenAI-Protokoll) und erzeugen ihre
Testdateien selbst; Tests für externe Werkzeuge (upx, 7z, dotnet, gcc, radare2) werden übersprungen, wenn diese fehlen.

Neuer Analyzer: Klasse in `magicbox/analyzers/` (siehe vorhandene), in `analyzers/__init__.py` eintragen – Bericht,
IOCs und LLM-Kontext entstehen automatisch.

```
magicbox/
├── analyzers/   identify · strings · pe · dotnet(+Makros) · elf · macho · java · archive · source(+pdf)
│                deobfuscate · iocs · yara_scan · capa · unpack · radare2 · disasm · apis
├── yara_rules/  mitgelieferte Basisregeln
├── llm/         Client (Ollama/OpenAI-kompatibel), Prompts (Profile), Map-Reduce-Dokumentierer
├── report/      Bericht (HTML/MD/JSON/CSV)
├── server/      HTTP-API, Live-Ereignisse, Auftragsverwaltung, Drop-Ordner, Anmeldung (Token/OIDC/Kratos/Oathkeeper)
├── web/         Oberfläche (HTML/CSS/JS, ohne Abhängigkeiten)
├── gui/         Desktop-App für Linux/macOS (Qt WebEngine)
├── engine.py · pipeline.py · tools.py · cli.py
desktop/         Native Windows-App (C#, WinForms/.NET Framework 4.8, Office-2003-Design, REST-API-Client)
packaging/       Windows-Installer: Inno-Setup-Skript, Build-Skript, Symbol
scripts/         easy-setup.sh · install_server.sh · make_offline_bundle.sh · magicbox-server.service · Startskripte
```
