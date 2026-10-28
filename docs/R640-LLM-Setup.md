# Lokales LLM auf dem Dell PowerEdge R640 einrichten

Diese Anleitung macht aus dem R640 den KI-Server für die Magic Box. Grundlage ist **Ollama** auf
Ubuntu Server 22.04/24.04 (Debian, Rocky usw. gehen genauso).

> Der R640 hat typischerweise **keine GPU** – das ist okay. Moderne LLM-Runtimes (llama.cpp, auf dem
> Ollama aufbaut) laufen gut auf Xeon-Scalable-CPUs mit **AVX-512**. Entscheidend sind **RAM-Größe** und
> **Speicherbandbreite**, nicht die Kernzahl allein.

## 1. Hardware-Tipps für maximale Geschwindigkeit

- **Alle Speicherkanäle bestücken:** Xeon Scalable (1./2. Gen.) hat 6 Kanäle pro Sockel. Ein RAM-Riegel pro
  Kanal (also 6 bzw. 12 Riegel) bringt deutlich mehr Token/s als wenige große Riegel.
- **BIOS:** System Profile auf *Performance*, Logical Processor (Hyper-Threading) darf an bleiben.
- **Zwei Sockel (NUMA):** LLM-Inferenz leidet, wenn Speicher zwischen den CPUs hin- und hergeschoben wird.
  Wenn das Modell in den RAM eines Sockels passt, ist es oft schneller, Ollama an einen Sockel zu binden
  (siehe Abschnitt 4). Ausprobieren lohnt sich.
- **GPU (optional):** Der R640 ist 1 HE und nimmt nur flache Karten mit niedriger Leistungsaufnahme auf
  (z. B. eine NVIDIA T4 mit 16 GB). Kompatibilität, Riser und Kühlung vorher bei Dell prüfen. Mit GPU wird
  es um ein Vielfaches schneller – Ollama erkennt NVIDIA-Karten automatisch.

## 2. Ollama installieren

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Das richtet automatisch einen systemd-Dienst `ollama` ein. Test:

```bash
ollama --version
```

## 3. Im Netzwerk erreichbar machen

Standardmäßig lauscht Ollama nur auf `127.0.0.1`. Für Zugriffe von deinem Desktop:

```bash
sudo systemctl edit ollama.service
```

Im Editor zwischen den Kommentarzeilen einfügen:

```ini
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
# Modell nach der letzten Anfrage 30 Minuten im RAM halten (spart Ladezeit)
Environment="OLLAMA_KEEP_ALIVE=30m"
# Eine Anfrage nach der anderen – auf CPU schneller als parallel
Environment="OLLAMA_NUM_PARALLEL=1"
```

Dann neu starten:

```bash
sudo systemctl daemon-reload && sudo systemctl restart ollama
```

### Firewall – wichtig!

Ollama hat **keine Authentifizierung**. Nur aus dem eigenen LAN freigeben, niemals ins Internet:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 11434 proto tcp
```

(Netz an dein LAN anpassen.) Wer Zugriff von außen braucht: VPN (WireGuard/Tailscale) oder ein Reverse-Proxy
mit Passwort davor – dann in der Magic Box den API-Key bzw. die Proxy-URL eintragen.

## 4. Modell auswählen und laden

Empfehlungen für Reverse-Engineering-Dokus (Code verstehen + gut formulieren). Modellnamen und verfügbare
Größen ändern sich laufend – aktuelle Liste: <https://ollama.com/library>.

| Modell (Ollama-Name) | RAM-Bedarf ca. | Einschätzung auf CPU |
|---|---|---|
| `qwen2.5-coder:7b` | ~6 GB | **Startpunkt.** Schnell, versteht Code/Assembly ordentlich, gutes Deutsch |
| `qwen2.5-coder:14b` | ~10 GB | Spürbar bessere Analysen, etwa halb so schnell wie 7b |
| `qwen3-coder:30b` (MoE) | ~20 GB | **Top-Tipp bei viel RAM:** Mixture-of-Experts, nur ein kleiner Teil der Parameter ist pro Token aktiv → auf CPU überraschend flott bei hoher Qualität |
| `qwen3:14b` / `qwen3:30b` | ~10 / ~20 GB | Allround-Modelle mit „Denk“-Modus; `<think>`-Blöcke filtert die Magic Box automatisch heraus |
| `llama3.1:8b` | ~6 GB | Solide Alternative, Deutsch etwas schwächer |

Laden (Beispiel):

```bash
ollama pull qwen2.5-coder:7b
```

Kurzer Test direkt auf dem Server:

```bash
ollama run qwen2.5-coder:7b "Erkläre in zwei Sätzen, was die Windows-API CreateRemoteThread macht."
```

Geschwindigkeit messen (zeigt `eval rate` in Token/s):

```bash
ollama run qwen2.5-coder:7b --verbose "Schreibe ein Haiku über Assembler."
```

**Grobe Erwartung ohne GPU:** ein 7b-Modell liefert auf einem gut bestückten Dual-Xeon einige bis gut zehn
Token/s; eine Doku (~1500 Token) braucht dann wenige Minuten. Große Archive mit vielen Teilanalysen dauern
entsprechend länger – dafür ist der Drop-Folder-Modus (unten) ideal.

### Optional: an einen CPU-Sockel binden (NUMA)

```bash
sudo apt install numactl
```

```bash
sudo systemctl edit ollama.service
```

```ini
[Service]
ExecStart=
ExecStart=/usr/bin/numactl --cpunodebind=0 --membind=0 /usr/local/bin/ollama serve
```

Den Pfad zu `ollama` mit `which ollama` prüfen. Vorher/nachher mit `--verbose` vergleichen und die
schnellere Variante behalten.

## 5. Magic Box verbinden

In der App unter **⚙️ Einstellungen**:

| Feld | Wert |
|---|---|
| Schnittstelle | Ollama |
| Server-URL | `http://<IP-oder-Name-des-R640>:11434` |
| Modell | z. B. `qwen2.5-coder:7b` (oder „Modelle laden“ klicken) |
| Kontextgröße | 16384 (bei 7b/14b gut; mehr Kontext = mehr RAM und langsamer) |

Dann **Verbindung testen**. Alternativ per Kommandozeile:

```bash
magicbox check --url http://r640:11434 --model qwen2.5-coder:7b
```

> Die Magic Box übergibt die Kontextgröße bei jeder Anfrage (`num_ctx`). Ohne das würde Ollama mit einem
> kleinen Standardkontext arbeiten und lange Analysen still abschneiden.

## 6. Bonus: Magic Box als „Briefkasten“ direkt auf dem R640

Statt die GUI zu benutzen, kann der R640 selbst die Box sein: Datei per Netzwerkfreigabe hineinkopieren,
Bericht kommt automatisch zurück.

```bash
sudo useradd --system --create-home --home-dir /opt/magicbox magicbox
```

```bash
sudo -u magicbox git clone <dein-repo> /opt/magicbox/app
```

```bash
cd /opt/magicbox && sudo -u magicbox python3 -m venv .venv && sudo -u magicbox .venv/bin/pip install -e ./app
```

```bash
sudo mkdir -p /srv/magicbox/eingang && sudo chown -R magicbox: /srv/magicbox
```

Optional radare2 für Pseudocode:

```bash
sudo apt install radare2
```

Dienst einrichten (Pfade in der Datei ggf. anpassen):

```bash
sudo cp /opt/magicbox/app/scripts/magicbox-watch.service /etc/systemd/system/
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now magicbox-watch
```

Jetzt `/srv/magicbox/eingang` per Samba freigeben. Alles, was du hineinlegst, wird analysiert; Berichte
landen in `eingang/_berichte/`, Originale in `eingang/_erledigt/`. Log ansehen:

```bash
journalctl -u magicbox-watch -f
```

## Alternative zu Ollama

Jeder **OpenAI-kompatible** Server funktioniert ebenfalls (Schnittstelle „OpenAI-kompatibel“ wählen):
`llama-server` aus llama.cpp, vLLM (mit GPU), LM Studio, LocalAI. Beispiel llama.cpp:

```bash
llama-server -m qwen2.5-coder-7b-instruct-q4_k_m.gguf --host 0.0.0.0 --port 8080 -c 16384
```

In der Magic Box dann `http://r640:8080` eintragen.
