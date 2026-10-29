"""Faktenauszug aus großem/minifiziertem JavaScript (webpack-Bundles, Electron-Hauptprozess, UI-Bundles).

Minifizierter Code verliert Variablennamen, behält aber alles, was nach außen sichtbar ist: Zeichenketten,
API-Namen, Endpunkte, IPC-Kanäle, Aktionsnamen. Daraus ergibt sich eine „Landkarte“ der Funktionen – kompakt
genug für den KI-Kontext, auch wenn das Bundle selbst Megabytes groß ist.
"""

from __future__ import annotations

import re
from collections import Counter
from urllib.parse import urlsplit

from magicbox.model import AnalysisResult, Section, Table

from .base import Analyzer, Context, clip
from .identify import source_language
from .strings import _readability

MIN_SIZE = 100 * 1024

URL_RE = re.compile(r"""https?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s"'`<>\\)\]},]*)?""")
API_PATH_RE = re.compile(r"""["'`](/(?:[a-z0-9_.-]+/){1,6}[A-Za-z0-9_.{}:-]+)["'`]""")
IPC_RE = re.compile(r"""\b(?:ipcMain|ipcRenderer)\s*\.\s*(on|once|handle|handleOnce|invoke|send|sendSync)\s*\(\s*["'`]([^"'`]{1,80})["'`]""")
WEBCONTENTS_SEND_RE = re.compile(r"""webContents\s*\.\s*send\s*\(\s*["'`]([^"'`]{1,80})["'`]""")
BRIDGE_RE = re.compile(r"""exposeInMainWorld\s*\(\s*["'`]([^"'`]{1,60})["'`]""")
PROTOCOL_RE = re.compile(r"""setAsDefaultProtocolClient\s*\(\s*["'`]([\w.+-]{1,40})["'`]""")
SWITCH_RE = re.compile(r"""appendSwitch\s*\(\s*["'`]([^"'`]{1,80})["'`]""")
ENV_RE = re.compile(r"""process\.env\.([A-Z][A-Z0-9_]{2,60})|process\.env\[["'`]([A-Z][A-Z0-9_]{2,60})["'`]\]""")
STORAGE_RE = re.compile(r"""localStorage\s*\.\s*(?:get|set|remove)Item\s*\(\s*["'`]([^"'`]{1,80})["'`]""")
# Redux/Flux-Aktionen ("PLAYER/PLAY_TRACK", "player/trackChanged") und Ereignisnamen ("track:play")
ACTION_RE = re.compile(r"""["'`]((?:[A-Z][A-Z0-9_]{2,30}/[A-Z][A-Z0-9_/]{2,60})|(?:[a-z][a-zA-Z0-9]{2,30}/[a-z][a-zA-Z0-9]{2,40}(?:/[a-zA-Z0-9]{2,40})?)|(?:[a-z][a-zA-Z]{2,25}:[a-z][a-zA-Z]{2,30}))["'`]""")
QUOTED_RE = re.compile(r""""([^"\\\n]{12,160})"|'([^'\\\n]{12,160})'""")

ELECTRON_APIS = [
    (r"\bnew\s+\w*\.?BrowserWindow\b|\bBrowserWindow\b", "Fenster (BrowserWindow)"),
    (r"\bTray\b", "Infobereich-Symbol (Tray)"),
    (r"Menu\.buildFromTemplate|Menu\.setApplicationMenu", "Menüs"),
    (r"\bautoUpdater\b|Squirrel|electron-updater", "Automatische Updates"),
    (r"setAsDefaultProtocolClient|protocol\.register\w+|protocol\.handle", "Eigenes URL-Protokoll"),
    (r"globalShortcut", "Globale Tastenkürzel"),
    (r"powerSaveBlocker|powerMonitor", "Energieverwaltung (Standby verhindern/überwachen)"),
    (r"nativeTheme", "Hell-/Dunkelmodus des Systems"),
    (r"shell\.openExternal", "Öffnet Links im Standard-Browser"),
    (r"dialog\.show\w+", "System-Dialoge (Öffnen/Speichern/Meldung)"),
    (r"new\s+Notification\b|\bNotification\(", "Desktop-Benachrichtigungen"),
    (r"crashReporter|@sentry|Sentry\.", "Absturz-/Fehlerberichte"),
    (r"opentelemetry|OTEL_", "Telemetrie (OpenTelemetry)"),
    (r"safeStorage|keytar|Credential", "Sichere Ablage von Zugangsdaten"),
    (r"app\.requestSingleInstanceLock", "Nur eine Instanz gleichzeitig"),
    (r"setLoginItemSettings", "Autostart mit Windows"),
    (r"contextBridge|preload", "Brücke Oberfläche ↔ Hauptprozess (preload)"),
    (r"navigator\.mediaSession|MediaMetadata", "Mediensteuerung (Medientasten, Systemanzeige)"),
    (r"\bAudioContext\b|HTMLAudioElement|new\s+Audio\(", "Audio-Wiedergabe im Browser-Teil"),
    (r"\bWebSocket\b", "WebSocket-Verbindungen"),
    (r"indexedDB", "IndexedDB (lokale Datenbank im Browser-Teil)"),
    (r"\bsqlite3?\b", "SQLite-Datenbank"),
    (r"castv2|chromecast|Chromecast", "Chromecast"),
    (r"\bDLNA\b|\bUPnP\b|ssdp", "DLNA/UPnP (Netzwerk-Wiedergabe)"),
    (r"\bdownload\w*\(|\bDownloadItem\b|will-download", "Downloads"),
    (r"\bi18n\b|\btranslate\(|\blocale\b", "Mehrsprachigkeit"),
]
_API_RES = [(re.compile(p), label) for p, label in ELECTRON_APIS]
NOISE_HOSTS = ("www.w3.org", "w3.org", "schemas.", "purl.org", "json-schema.org", "reactjs.org", "fb.me",
               "github.com", "mozilla.org", "developer.mozilla.org", "tools.ietf.org", "example.com", "localhost")


def _top(counter: Counter, n: int) -> list[str]:
    return [k for k, _ in counter.most_common(n)]


def extract(text: str) -> dict[str, list]:
    facts: dict[str, list] = {}
    hosts: Counter = Counter()
    examples: dict[str, str] = {}
    for m in URL_RE.finditer(text):
        url = m.group().rstrip(".,;:'\"")
        host = urlsplit(url).netloc.lower()
        if not host or any(host.endswith(n) or host.startswith(n) for n in NOISE_HOSTS):
            continue
        hosts[host] += 1
        if host not in examples or (len(url) > len(examples[host]) and len(url) < 140):
            examples[host] = url
    if hosts:
        facts["hosts"] = [[h, str(c), clip(examples[h], 120)] for h, c in hosts.most_common(30)]
    paths = Counter(m.group(1) for m in API_PATH_RE.finditer(text)
                    if not m.group(1).startswith(("/static/", "/assets/", "/node_modules/")))
    if paths:
        facts["api_paths"] = _top(paths, 40)
    ipc: Counter = Counter()
    for m in IPC_RE.finditer(text):
        ipc[f"{m.group(2)} ({m.group(1)})"] += 1
    for m in WEBCONTENTS_SEND_RE.finditer(text):
        ipc[f"{m.group(1)} (webContents.send)"] += 1
    if ipc:
        facts["ipc"] = _top(ipc, 60)
    for key, rx in (("bridge", BRIDGE_RE), ("protocols", PROTOCOL_RE), ("switches", SWITCH_RE), ("storage", STORAGE_RE)):
        found = Counter(m.group(1) for m in rx.finditer(text))
        if found:
            facts[key] = _top(found, 40)
    env = Counter(m.group(1) or m.group(2) for m in ENV_RE.finditer(text))
    if env:
        facts["env"] = _top(env, 40)
    actions = Counter(m.group(1) for m in ACTION_RE.finditer(text)
                      if not m.group(1).startswith(("http", "text/", "application/", "image/", "audio/", "video/")))
    if actions:
        facts["actions"] = _top(actions, 80)
    apis = [[label, str(len(rx.findall(text)))] for rx, label in _API_RES if rx.search(text)]
    if apis:
        facts["apis"] = apis
    texts = {t for m in QUOTED_RE.finditer(text) for t in [m.group(1) or m.group(2)]
             if " " in t and not t.startswith(("http", "/", ".", "#")) and "{" not in t and "=" not in t}
    natural = [t for t in sorted(texts, key=_readability) if not _readability(t)[0]]
    if natural:
        facts["texts"] = natural[:60]
    return facts


def interest(text: str) -> int:
    """Wie „aufschlussreich“ ein Code-Stück ist (Endpunkte, IPC, Aktionen, Electron-APIs) – für die Auswahl
    der Teile, die die KI einzeln liest."""
    score = 3 * len(IPC_RE.findall(text)) + 2 * len(URL_RE.findall(text)) + len(ACTION_RE.findall(text))
    score += sum(1 for rx, _ in _API_RES if rx.search(text))
    return score


class JSBundleAnalyzer(Analyzer):
    name = "jsbundle"
    kinds = ("source",)

    def matches(self, ctx: Context, result: AnalysisResult) -> bool:
        if not super().matches(ctx, result) or len(ctx.data) < MIN_SIZE:
            return False
        lang = ctx.facts.get("language") or source_language(ctx.data, ctx.path.name)
        return lang in ("javascript", "typescript", "html")

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        text = ctx.data.decode("utf-8", "replace")
        facts = extract(text)
        if not facts:
            return
        lines = []
        labels = {
            "api_paths": "API-Pfade", "ipc": "IPC-Kanäle (Oberfläche ↔ Hauptprozess)",
            "bridge": "Für die Oberfläche freigegebene Schnittstellen (contextBridge)",
            "protocols": "Eigene URL-Protokolle", "switches": "Chromium-Schalter", "storage": "Gespeicherte Einstellungen (localStorage)",
            "env": "Umgebungsvariablen", "actions": "Aktions-/Ereignisnamen (Funktionslandkarte)",
            "texts": "Texte/Meldungen der Oberfläche",
        }
        for key, label in labels.items():
            if facts.get(key):
                sep = "\n" if key == "texts" else ", "
                lines.append(f"**{label}:**{' ' if sep == ', ' else sep}" + sep.join(facts[key]))
        result.add(Section("Bundle-Auswertung (Funktionslandkarte)", text="\n\n".join(lines), llm_priority=0))
        if facts.get("apis"):
            result.add(Section("Genutzte Plattform-Funktionen", table=Table(["Funktion", "Fundstellen"], facts["apis"]),
                               llm_priority=0))
        if facts.get("hosts"):
            result.add(Section("Angesprochene Server/Dienste (aus dem Code)",
                               table=Table(["Host", "Vorkommen", "Beispiel"], facts["hosts"]), llm_priority=0,
                               text="Adressen im Code – ob und wann sie aufgerufen werden, ist statisch nicht belegt."))
