# Magic Box auf dem Dell PowerEdge R640 (Xeon Gold 5218R) – auch komplett offline

Diese Anleitung macht aus dem R640 eine eigenständige Analyse-Box: Magic-Box-Server + lokales LLM (Ollama),
erreichbar per Desktop-App oder Browser, auf Wunsch **ohne jede Internetverbindung**.

## 1. Empfohlener Aufbau

```
 LAN ── Port 8765 ──► [ VM „magicbox“ auf dem R640 (Ubuntu) ]
                         ├─ magicbox-server  (Analyse, Web-Oberfläche, Drop-Ordner)
                         └─ ollama           (nur 127.0.0.1:11434, nicht im LAN)
                       ausgehender Verkehr: gesperrt
```

- **Eigene VM** (Proxmox/ESXi/KVM) für die Analyse – gibt eine saubere Trennung zum Rest und lässt sich per
  Snapshot zurücksetzen. Bare-Metal geht auch.
- **Linux** als Analyse-System: Windows-Malware kann dort nicht versehentlich starten.
- Der VM möglichst **alle CPU-Kerne eines Sockels** und genug RAM für das Modell geben (siehe unten).

## 2. Welches Modell für den Xeon Gold 5218R?

Der 5218R (Cascade Lake, 20 Kerne) hat **AVX-512 inkl. VNNI** – das beschleunigt vor allem das Einlesen langer
Prompts (die Magic Box schickt viele Fakten). Die Schreibgeschwindigkeit hängt dagegen fast nur an der
**Speicherbandbreite** (6 Kanäle DDR4-2666 pro Sockel). Deshalb sind **Mixture-of-Experts-Modelle** ideal:
viele Parameter (Qualität), aber pro Token nur wenige aktiv (Tempo).

| Modell (Ollama-Name) | RAM (Q4) | aktive Parameter | grobe Schätzung | Einsatz |
|---|---|---|---|---|
| **`qwen3-coder:30b`** (MoE) | ~19 GB | ~3 B | ~12–20 Token/s | **Erste Wahl:** versteht Code/Assembly/Pseudocode sehr gut |
| `gpt-oss:20b` (MoE) | ~14 GB | ~3,6 B | ~12–20 Token/s | Starke Alternative (etwas strengeres Sicherheits-Training) |
| `gpt-oss:120b` (MoE) | ~65 GB | ~5 B | ~6–10 Token/s | Nur bei ≥ 96 GB RAM: beste Qualität |
| `qwen2.5-coder:14b` | ~9 GB | 14 B | ~6–8 Token/s | Wenn wenig RAM frei ist |
| `qwen2.5-coder:7b` | ~5 GB | 7 B | ~10–15 Token/s | Schnell, aber flachere Dokus |
| ❌ dichte 32B/70B-Modelle | 20–40 GB | alle | ~1–4 Token/s | Zu langsam für mehrere KI-Anfragen pro Probe |

Die Token/s sind aus der Speicherbandbreite geschätzt, nicht gemessen. Aktuelle Modelle: <https://ollama.com/library>.

**Selbst messen** (`prompt eval rate` = Einlesen, `eval rate` = Schreiben):

```bash
ollama run qwen3-coder:30b --verbose "Erkläre, was CreateRemoteThread macht."
```

**AVX-512 aktiv?** Im Ollama-Log sollte `AVX512 = 1` stehen:

```bash
journalctl -u ollama --no-pager | grep -i avx512
```

### Hardware-Tipps

- **Alle 6 Speicherkanäle pro CPU bestücken** – bringt mehr als jede andere Einstellung:
  ```bash
  sudo dmidecode -t memory | grep -E "^\s+(Size|Speed|Locator):"
  ```
- BIOS: System Profile **Performance**.
- **Zwei Sockel (NUMA):** Passt das Modell in den RAM eines Sockels, ist es oft schneller, Ollama an einen
  Sockel zu binden (`sudo systemctl edit ollama.service`, `which ollama` für den Pfad):
  ```ini
  [Service]
  ExecStart=
  ExecStart=/usr/bin/numactl --cpunodebind=0 --membind=0 /usr/local/bin/ollama serve
  ```
  Vorher/nachher mit `--verbose` vergleichen.
- Quantisierung Q4_K_M (Ollama-Standard) beibehalten; Q8 ist etwas besser, aber halb so schnell.

## 3. Installation mit Internet (einmalig)

```bash
git clone <dieses-repo> magicbox && cd magicbox
```

```bash
sudo ./scripts/install_server.sh --model qwen3-coder:30b
```

Das Skript erledigt:

1. Systempakete: radare2, UPX, 7-Zip, .NET-SDK (für ILSpy), Python-venv
2. Benutzer `magicbox`, Ordner `/srv/magicbox/{daten,eingang,yara}`, Konfiguration `/etc/magicbox/settings.json`
3. Python-Umgebung mit capa, YARA, oletools, dnfile, pyzipper
4. capa-Regeln (passend zur capa-Version) und YARA-Forge-Regeln
5. ilspycmd (.NET-Dekompiler)
6. Ollama (nur auf `127.0.0.1`) und das Modell
7. Den abgesicherten Dienst `magicbox-server` (Port 8765) mit zufälligem Zugangsschlüssel

Am Ende steht die URL inkl. Schlüssel im Terminal. Der Schlüssel liegt auch in `/etc/magicbox/settings.json`
(`web_token`).

**Danach Internet kappen** (siehe Abschnitt 5) – die Box braucht es nicht mehr.

## 4. Installation komplett ohne Internet

Auf einem Rechner **mit** Internet – am besten eine frische VM/ein Container mit **derselben Ubuntu-Version**
wie der Server (sonst passen .deb-Pakete und Python-Wheels nicht):

```bash
./scripts/make_offline_bundle.sh --model qwen3-coder:30b
```

Das erzeugt `magicbox-offline.tar.gz` mit: Python-Wheels, .deb-Paketen inkl. Abhängigkeiten, capa- und
YARA-Regeln, ilspycmd, Ollama und – falls Ollama auf dem Online-Rechner installiert ist – den Modelldateien.
Per USB-Stick auf den Server bringen, dann:

```bash
tar xzf magicbox-offline.tar.gz && cd magicbox-offline/magicbox
```

```bash
sudo ./scripts/install_server.sh --offline .. --model qwen3-coder:30b
```

Modell ohne Ollama auf dem Online-Rechner? Den Ordner `~/.ollama/models` (bzw. `/usr/share/ollama/.ollama/models`)
von irgendeinem Rechner mit dem gezogenen Modell nach `magicbox-offline/ollama-models/` kopieren.

## 5. Abschotten

Nur die Magic Box aus dem LAN erlauben, alles andere – vor allem **ausgehend** – sperren:

```bash
sudo ufw default deny incoming
```

```bash
sudo ufw default deny outgoing
```

```bash
sudo ufw allow from 192.168.1.0/24 to any port 8765 proto tcp
```

```bash
sudo ufw allow from 192.168.1.0/24 to any port 22 proto tcp
```

```bash
sudo ufw enable
```

(Netz an dein LAN anpassen; SSH-Regel nur, wenn du sie brauchst. Ollama ist ohnehin nur lokal erreichbar.)
Updates später wieder über ein neues Offline-Bundle oder kurzzeitig geöffneten Ausgang.

## 6. Anmeldung über Ory

Statt des Zugangsschlüssels kann die Magic Box deinen Ory-Stack nutzen (gleicher Login wie für deine anderen
Dienste, inkl. Captcha und 2FA): siehe [Ory-Anmeldung.md](Ory-Anmeldung.md).

## 7. Benutzen

- **Browser:** `http://<server>:8765/?token=<schlüssel>`
- **Desktop-App** (Windows/Linux/macOS): `scripts/start_windows.bat` bzw. `scripts/start_linux.sh`, dann
  *Magic Box → Server wechseln …* → `http://<server>:8765`, beim ersten Öffnen den Schlüssel eingeben.
- **Drop-Ordner:** `/srv/magicbox/eingang` per Samba freigeben – alles, was dort landet, erscheint als Auftrag.
  Proben am besten als ZIP mit Passwort `infected` transportieren (wird automatisch geöffnet), damit der
  Virenscanner des Arbeitsplatzes sie nicht vorher löscht.

Logs:

```bash
journalctl -u magicbox-server -f
```

Einstellungen (Modell, Kontextgröße, Zielgruppe, Passwörter, eigene YARA-Regeln …) lassen sich in der
Oberfläche unter **⚙️ Einstellungen** ändern. Netzwerk und Zugangsschlüssel nur in `/etc/magicbox/settings.json`
(danach `sudo systemctl restart magicbox-server`).

### Empfohlene Einstellungen für den 5218R

| Einstellung | Wert |
|---|---|
| Modell | `qwen3-coder:30b` |
| Kontextgröße | 16384 (bei zu langsamem Einlesen 8192 – die Box teilt dann stärker auf) |
| Max. KI-Teilanalysen | 6–8 bei großen Archiven |
| Zielgruppe | „für Sicherheitsanalysten“ oder „technisch interessierte Laien“ |

## Alternative LLM-Server

Statt Ollama funktioniert jeder **OpenAI-kompatible** Server (Schnittstelle „OpenAI-kompatibel“), z. B.
`llama-server` aus llama.cpp:

```bash
llama-server -m qwen3-coder-30b-a3b-q4_k_m.gguf --host 127.0.0.1 --port 8080 -c 16384
```

Dann als Server-URL `http://127.0.0.1:8080` eintragen.
