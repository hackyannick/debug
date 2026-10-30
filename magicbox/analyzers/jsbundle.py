"""Faktenauszug aus großem/minifiziertem JavaScript (webpack-Bundles, Electron-Hauptprozess, UI-Bundles).

Minifizierter Code verliert Variablennamen, behält aber alles, was nach außen sichtbar ist: Zeichenketten,
API-Namen, Endpunkte, IPC-Kanäle, Aktionsnamen. Daraus ergibt sich eine „Landkarte“ der Funktionen – kompakt
genug für den KI-Kontext, auch wenn das Bundle selbst Megabytes groß ist. ``aggregate`` fasst die Landkarten
aller Dateien einer App zusammen, damit auch die Gesamt-Doku sie sieht.
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

# Links aus Fehlermeldungen/Doku eingebauter Bibliotheken – sagen nichts über die App
DOC_HOSTS = {
    "momentjs.com", "docs.sentry.io", "sentry.io", "sequelize.org", "storybook.js.org", "react-dnd.github.io",
    "testing-library.com", "redux.js.org", "formatjs.io", "npms.io", "reactjs.org", "react.dev", "fb.me", "nodejs.org",
    "github.com", "stuk.github.io", "www.sqlite.org", "www.prisma.io", "docs.oracle.com", "www.oracle.com",
    "evilmartians.com", "w3ctech.com", "www.w3ctech.com", "dogs.are.great", "f.a.k", "my-image.com", "bit.ly",
    "goo.gl", "mui.com", "lodash.com", "babeljs.io", "webpack.js.org", "electronjs.org", "www.electronjs.org",
    "developer.mozilla.org", "mozilla.org", "www.w3.org", "w3.org", "purl.org", "json-schema.org", "tools.ietf.org",
    "example.com", "example.org", "localhost", "ns.adobe.com", "schemas.microsoft.com", "www.npmjs.com",
    "stackoverflow.com", "en.wikipedia.org", "opentelemetry.io", "nextjs.org", "vuejs.org", "angular.io",
    "vitest.dev", "html.spec.whatwg.org", "whatwg.org", "testing-playground.com", "redux-toolkit.js.org",
    "mozilla.github.io", "unpkg.com", "jsfiddle.net", "codepen.io", "caniuse.com", "web.dev", "v8.dev",
}
SOCIAL_HOSTS = {
    "facebook.com", "www.facebook.com", "graph.facebook.com", "twitter.com", "x.com", "linkedin.com",
    "www.linkedin.com", "vk.com", "connect.ok.ru", "connect.mail.ru", "www.reddit.com", "reddit.com",
    "www.instapaper.com", "www.youtube.com", "www.youtube-nocookie.com", "pinterest.com", "www.pinterest.com",
    "t.me", "wa.me", "api.whatsapp.com", "www.tumblr.com", "api.tumblr.com", "tumblr.com", "bookmark.hatenaapis.com",
    "b.hatena.ne.jp", "social-plugins.line.me", "service.weibo.com", "getpocket.com", "api.pinterest.com",
    "tinyurl.com", "www.xing.com", "telegram.me", "mastodon.social", "www.addtoany.com",
}
HOST_RE = re.compile(r"^[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}$")
# Namen von Node-Modulen, Pfaden und Formaten, die wie Aktionsnamen aussehen
NOISE_ACTION_HEADS = {
    "node", "xml", "xlink", "xmlns", "svg", "chai", "storybook", "sql", "connection", "lib", "test", "path", "posix",
    "win32", "stream", "streams", "timers", "util", "dns", "fs", "readline", "inspector", "assert", "domain", "http2",
    "worker", "perf", "diagnostics", "string", "sys", "tty", "wasi", "repl", "sea", "sqlite", "punycode",
    "querystring", "url", "v8", "vm", "zlib", "os", "net", "tls", "crypto", "events", "buffer", "child", "cluster",
    "console", "constants", "dgram", "module", "process", "async", "http", "https", "text", "application", "image",
    "audio", "video", "font", "multipart", "data", "blob", "mailto", "tel", "about", "chrome", "file", "javascript",
    "webpack", "src", "dist", "assets", "static", "legacy", "react", "redux", "moment", "sentry", "babel", "core",
    "sequelize", "packages", "allownull", "hover", "display", "color", "font", "margin", "padding", "position", "width",
    "height", "border", "background", "cursor", "overflow", "opacity", "transform", "transition", "focus", "active",
    "visited", "before", "after", "tinyspy", "vitest", "jest",
}
DE_WORDS = {"der", "die", "das", "und", "nicht", "sie", "ihre", "ihr", "ist", "wird", "werden", "bitte", "mit", "für",
            "auf", "eine", "einen", "keine", "kann", "können", "wurde", "wurden", "zu", "von", "oder", "jetzt"}
EN_WORDS = {"the", "you", "your", "is", "are", "to", "please", "with", "for", "this", "not", "can", "cannot", "and",
            "will", "has", "have", "been", "was", "now", "there", "an", "of", "in", "on"}
OTHER_WORDS = {"você", "não", "está", "usted", "puedes", "para", "las", "los", "una", "della", "che", "il", "vous",
               "votre", "les", "des", "pour", "est", "pas", "sono", "seu", "sua", "também", "aquí", "nos", "vos"}
LIBRARY_MARKERS = re.compile(r"sentry|sequelize|moment|jszip|socks|\bspan\b|transaction|\bdsn\b|deprecated|spotlight|"
                             r"tracing|promise|callback|undefined|instance|webpack|polyfill|eslint|\breact\b|redux|"
                             r"\bprop\b|argument|stack ?trace|\bmodule\b|options object|isolation scope|minidump|"
                             r"zip64|central directory|check-?ins?\b|\bscope\b|debugger|\banr\b|\bframe\b|"
                             r"\bsql\b|sqlite|\bbatch|\bqueue ?size|\battributes?\b|association|iterator|"
                             r"connection ?manager|multicast|dhcp|\bsocket\b|\bnull\b|\bboolean\b|\bpassing\b|"
                             r"\bconfigured\b|\bsandbox\b|init box|\bsegment\b|\bbits?\b|\bbuffer\b|\bvalue\b|"
                             r"\biterable\b|\bconstructor\b|\bschema\b|\bmodel\b|\bmemory\b|duplicate key|identifier|where object|"
                             r"source files|context lines|bounds of|pending requests|\bsdk\b|logger|error object|"
                             r"no client|nodeclient|forget to load", re.I)
CODE_WORD_RE = re.compile(r"\b(?!macOS\b)[a-z]{3,}[A-Z][A-Za-z]*\b")  # pressDelay, maxQueueSize … = Entwicklermeldung
# Umgebungsvariablen, die eingebaute Bibliotheken (Sentry, CI-Erkennung, graceful-fs …) abfragen
ENV_NOISE_RE = re.compile(r"^(?:SENTRY_|CI_|GITHUB_|GITLAB_|AWS_|ALIYUN_|IBM_|TENCENT|FLY_|PRISMA_|VERCEL|NETLIFY|"
                          r"HEROKU|RENDER_|RAILWAY|BITBUCKET_|APPVEYOR_|CODEBUILD_|CIRCLE|TRAVIS|BUILDKITE|DRONE|"
                          r"JENKINS|TEAMCITY|CF_PAGES|SPECTRON|TEST_|GRACEFUL_FS_|UV_THREADPOOL|READABLE_STREAM|"
                          r"NODE_DEBUG$|REGION_NAME$|CI$|DEBUG$)")


def ui_rank(text: str, own: set[str] = frozenset()) -> tuple:
    """Oberflächentexte vor Meldungen eingebauter Bibliotheken: an Nutzer gerichtet, Produktname, Großschreibung."""
    low = text.lower()
    addressed = bool(re.search(r"\b(you|your|sie|ihre?n?|du|dein)\b", low))
    product = any(o in low.replace(" ", "") for o in own)
    return (bool(LIBRARY_MARKERS.search(text)), not (addressed or product), not text[:1].isupper(), _readability(text))


def _language_ok(text: str) -> bool:
    """Oberflächentexte nur auf Deutsch/Englisch zeigen – dieselbe Meldung in 6 Sprachen bringt nichts."""
    words = set(re.findall(r"[a-zäöüßéèêàçãõñ]+", text.lower()))
    return bool(words & (DE_WORDS | EN_WORDS)) and not words & OTHER_WORDS


def _top(counter: Counter, n: int) -> list[str]:
    return [k for k, _ in counter.most_common(n)]


def _host_kind(host: str, own: set[str]) -> str:
    if any(t in host.replace("-", "").replace(".", "") for t in own):
        return "eigener Dienst"
    if host in SOCIAL_HOSTS:
        return "Teilen/Einbettung (soziale Netzwerke)"
    return "Fremddienst/CDN"


def extract(text: str, own: set[str] = frozenset()) -> dict:
    """Strukturierte Landkarte eines Bundles. ``own``: Namensbestandteile der App (z. B. {"qobuz"})."""
    facts: dict = {}
    hosts: Counter = Counter()
    examples: dict[str, str] = {}
    for m in URL_RE.finditer(text):
        url = m.group().rstrip(".,;:'\"$({")
        host = urlsplit(url).netloc.lower().split(":")[0]
        if not HOST_RE.match(host) or host in DOC_HOSTS or any(host.endswith("." + d) for d in DOC_HOSTS):
            continue
        hosts[host] += 1
        if host not in examples or (len(url) > len(examples[host]) and len(url) < 140):
            examples[host] = url
    if hosts:
        facts["hosts"] = {h: {"count": c, "example": examples[h], "kind": _host_kind(h, own)}
                          for h, c in hosts.most_common(40)}
    paths = Counter(m.group(1) for m in API_PATH_RE.finditer(text)
                    if not m.group(1).startswith(("/static/", "/assets/", "/node_modules/", "/legacy/", "/usr/", "/var/",
                                                  "/etc/", "/proc/", "/sys/", "/dev/")))
    if paths:
        facts["api_paths"] = _top(paths, 60)
    ipc: dict[str, str] = {}
    for m in IPC_RE.finditer(text):
        ipc.setdefault(m.group(2), m.group(1))
    for m in WEBCONTENTS_SEND_RE.finditer(text):
        ipc.setdefault(m.group(1), "webContents.send")
    if ipc:
        facts["ipc"] = ipc
    for key, rx in (("bridge", BRIDGE_RE), ("protocols", PROTOCOL_RE), ("switches", SWITCH_RE), ("storage", STORAGE_RE)):
        found = Counter(m.group(1) for m in rx.finditer(text))
        if found:
            facts[key] = _top(found, 40)
    env = Counter(name for m in ENV_RE.finditer(text) for name in [m.group(1) or m.group(2)]
                  if not ENV_NOISE_RE.match(name))
    if env:
        facts["env"] = _top(env, 40)
    actions = Counter()
    for m in ACTION_RE.finditer(text):
        name = m.group(1)
        head = re.split(r"[/:]", name, maxsplit=1)[0].lower()
        if head not in NOISE_ACTION_HEADS and not re.fullmatch(r"[YMDHhms/:.-]+", name):
            actions[name] += 1
    if actions:
        facts["actions"] = _top(actions, 100)
    apis = {label: len(rx.findall(text)) for rx, label in _API_RES if rx.search(text)}
    if apis:
        facts["apis"] = apis
    texts = {t.strip() for m in QUOTED_RE.finditer(text) for t in [m.group(1) or m.group(2)]
             if " " in t and not t.startswith(("http", "/", ".", "#")) and "{" not in t and "=" not in t}

    # Meldungen eingebauter Bibliotheken (Sentry, Sequelize, ZIP …) sind keine Oberflächentexte der App
    natural = [t for t in texts if not _readability(t)[0] and _language_ok(t)
               and not LIBRARY_MARKERS.search(t) and not CODE_WORD_RE.search(t)]
    if natural:
        facts["texts"] = sorted(natural, key=lambda t: ui_rank(t, own))[:50]
    return facts


# Funktionsbereiche: Wörter in Kanal-, Aktions- und Routennamen → verständliche Bereiche (für die Gliederung der Doku)
AREAS = [
    ("Wiedergabe & Warteschlange", {"player", "playqueue", "queue", "shuffle", "repeat", "volume", "pause", "play",
                                    "seek", "playback"}, set()),
    ("Ausgabegeräte & Audioqualität", {"output", "exclusive", "asio", "wasapi", "samplerate", "hires", "quality",
                                       "dsd", "dxd", "bitdepth", "equalizer", "devices", "device"}, {"hi-res", "hi-fi", "audio-output"}),
    ("Wiedergabe auf anderen Geräten (Chromecast, DLNA, Connect)",
     {"chromecast", "cast", "castdevice", "dlna", "upnp", "airplay", "renderer", "renderers", "qconnect"}, set()),
    ("Downloads & Offline-Nutzung", {"download", "downloads", "downloaded", "offline", "cache"}, set()),
    ("Käufe, Shop & Guthaben", {"purchase", "purchases", "wallet", "coins", "cashback", "checkout", "payment",
                                "subscription", "subscribe", "price", "buy"}, {"store-router", "webstore"}),
    ("Lokale Musik & Import", {"import", "imports", "imported"}, {"localmusic", "/local/"}),
    ("Bibliothek, Favoriten & Playlists", {"favorite", "favorites", "favourite", "playlist", "playlists", "collection",
                                           "collections", "library"}, {"userlibrary", "user-library"}),
    ("Entdecken, Redaktion & Radio", {"discover", "magazine", "radio", "award", "awards", "editorial", "genre",
                                      "featured", "story"}, {"newreleases", "new-releases"}),
    ("Suche", {"search"}, set()),
    ("Konto & Anmeldung", {"login", "logout", "oauth", "account", "signin", "signup", "password"}, set()),
    ("Einstellungen & Darstellung", {"settings", "setting", "theme", "language", "zoom", "preferences"}, set()),
    ("Benachrichtigungen", {"notification", "notifications", "notify", "badge"}, set()),
    ("Updates", {"update", "updates", "upgrade", "updater"}, set()),
    ("Fehlerberichte & Protokolle", {"log", "logs", "logfile", "sentry", "crash", "report", "diagnostics"}, set()),
    ("Teilen & soziale Funktionen", {"share", "sharer", "social", "follow"}, set()),
    ("Videos, Booklets & Zusatzinhalte", {"video", "videos", "booklet", "lyrics", "interviews"}, set()),
]
_WORD_SPLIT = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")


def feature_areas(facts: dict) -> list[tuple[str, int, list[str]]]:
    """Leitet aus Kanal-, Aktions- und Routennamen (und Oberflächentexten) Funktionsbereiche ab – mit Belegen."""
    identifiers = list(facts.get("ipc", {})) + list(facts.get("actions", [])) + list(facts.get("api_paths", []))
    texts = list(facts.get("texts", []))
    found: dict[str, list[str]] = {}
    counts: Counter = Counter()
    for item, is_text in [(i, False) for i in identifiers] + [(t, True) for t in texts]:
        low = item.lower()
        words = {w.lower() for w in _WORD_SPLIT.findall(item)}
        joined = re.sub(r"[^a-z0-9/]", "", low)
        for label, keys, compounds in AREAS:
            if words & keys or any(c in low or c.replace("-", "") in joined for c in compounds):
                counts[label] += 1
                examples = found.setdefault(label, [])
                if not is_text and len(examples) < 6 and item not in examples:
                    examples.append(item)
    out = []
    for label, n in counts.most_common():
        if n >= 2:
            out.append((label, n, found.get(label) or []))
    return out


# Mitgebündelte Bibliotheken (Telemetrie, ZIP, ORM, Datum, Polyfills …) – deren Code erklärt nicht die App
BUNDLED_LIBRARY_RE = re.compile(
    r"opentelemetry|SpanProcessor|\bspanId\b|sentry|RewriteFrames|zip64|ZipFile|centralDirectory|sequelize|"
    r"QueryInterface|moment\(|momentjs|Intl\.|CanonicalizeTimeZoneName|InitializeNumberFormat|core-js|regenerator|"
    r"protobuf|@license|SPDX-License|Copyright \(c\)|webpack/runtime|__webpack_require__\.(?:d|r|o)\b|socks|"
    r"node-gyp|semver|minipass|tar-stream", re.I)


def interest(text: str, own: set[str] = frozenset()) -> int:
    """Wie „aufschlussreich“ ein Code-Stück für die App ist – für die Auswahl der Teile, die die KI einzeln liest.
    Zählt IPC-Kanäle, Aktionen, eigene Namen (z. B. „qobuz“) und Plattform-APIs; Code mitgebündelter Bibliotheken
    (Telemetrie, ZIP, ORM …) und deren Doku-Links zählen nicht bzw. negativ."""
    own_urls = sum(1 for m in URL_RE.finditer(text)
                   if urlsplit(m.group()).netloc.lower().split(":")[0] not in DOC_HOSTS)
    low = text.lower()
    score = 5 * len(IPC_RE.findall(text)) + 2 * len(WEBCONTENTS_SEND_RE.findall(text)) + len(ACTION_RE.findall(text))
    score += own_urls + sum(1 for rx, _ in _API_RES if rx.search(text))
    score += 3 * sum(low.count(t) for t in own)
    score -= 4 * len(BUNDLED_LIBRARY_RE.findall(text))
    return score


def group_channels(channels: list[str]) -> list[str]:
    """IPC-Kanäle nach Präfix gruppieren: „player (12): play-music, pause-music, …“."""
    groups: dict[str, list[tuple[str, str]]] = {}
    for ch in sorted(set(channels), key=str.lower):
        parts = re.split(r"[-:_]", ch, maxsplit=1)
        head = parts[0].lower() if len(parts) > 1 and parts[0] else ""
        groups.setdefault(head, []).append((parts[1] if head else ch, ch))
    single = [v[0][1] for h, v in groups.items() if h and len(v) == 1]
    lines = [f"{h} ({len(v)}): {', '.join(rest for rest, _ in v)}" for h, v in groups.items() if h and len(v) > 1]
    rest = [orig for _, orig in groups.get("", [])] + single
    if rest:
        lines.append(f"weitere ({len(rest)}): {', '.join(sorted(rest, key=str.lower))}")
    return lines


def render(facts: dict, title: str) -> list[Section]:
    """Abschnitte für Bericht und KI-Kontext aus einer (ggf. zusammengefassten) Landkarte."""
    lines = []
    areas = feature_areas(facts)
    if areas:
        lines.append("**Erkannte Funktionsbereiche (abgeleitet aus Kanal-, Aktions-, Routennamen und Texten):**\n"
                     + "\n".join(f"- {label} ({n} Belege)" + (f": {', '.join(ex)}" if ex else "")
                                  for label, n, ex in areas))
    if facts.get("ipc"):
        lines.append(f"**IPC-Kanäle Oberfläche ↔ Hauptprozess ({len(facts['ipc'])}), nach Bereich:**\n"
                     + "\n".join(f"- {line}" for line in group_channels(list(facts["ipc"]))))
    labels = {
        "api_paths": "App-Routen/API-Pfade", "bridge": "Für die Oberfläche freigegebene Schnittstellen (contextBridge)",
        "protocols": "Eigene URL-Protokolle", "switches": "Chromium-Schalter", "storage": "Gespeicherte Einstellungen (localStorage)",
        "env": "Umgebungsvariablen", "actions": "Aktions-/Ereignisnamen (Funktionslandkarte)",
    }
    for key, label in labels.items():
        if facts.get(key):
            lines.append(f"**{label}:** " + ", ".join(facts[key]))
    if facts.get("texts"):
        lines.append("**Texte/Meldungen der Oberfläche (Auswahl, deutsch/englisch):**\n"
                     + "\n".join(f"- {clip(t, 160)}" for t in facts["texts"]))
    sections = []
    if lines:
        sections.append(Section(title, text="\n\n".join(lines), llm_priority=0))
    if facts.get("apis"):
        rows = [[label, str(n)] for label, n in sorted(facts["apis"].items(), key=lambda kv: -kv[1])]
        sections.append(Section("Genutzte Plattform-Funktionen", table=Table(["Funktion", "Fundstellen"], rows),
                                llm_priority=0))
    if facts.get("hosts"):
        order = {"eigener Dienst": 0, "Fremddienst/CDN": 1, "Teilen/Einbettung (soziale Netzwerke)": 2}
        rows = [[h, d["kind"], str(d["count"]), clip(d["example"], 110)]
                for h, d in sorted(facts["hosts"].items(), key=lambda kv: (order.get(kv[1]["kind"], 3), -kv[1]["count"]))]
        sections.append(Section("Angesprochene Server/Dienste (aus dem Code)",
                                table=Table(["Host", "Art", "Vorkommen", "Beispiel"], rows[:40], total=len(rows)),
                                text="Adressen im Code – ob und wann sie aufgerufen werden, ist statisch nicht belegt. "
                                     "Links aus Fehlermeldungen/Doku eingebauter Bibliotheken sind ausgeblendet.",
                                llm_priority=0))
    return sections


def merge(maps: list[dict], own: set[str] = frozenset()) -> dict:
    out: dict = {}
    for m in maps:
        for key, value in m.items():
            if key == "hosts":
                hosts = out.setdefault("hosts", {})
                for h, d in value.items():
                    if h in hosts:
                        hosts[h]["count"] += d["count"]
                    else:
                        hosts[h] = dict(d)
            elif key == "apis":
                apis = out.setdefault("apis", {})
                for label, n in value.items():
                    apis[label] = apis.get(label, 0) + n
            elif key == "ipc":
                out.setdefault("ipc", {}).update({k: v for k, v in value.items() if k not in out.get("ipc", {})})
            elif key == "env":
                continue  # meist Umgebungsvariablen eingebauter Bibliotheken (CI, Cloud) – in der Gesamtsicht weglassen
            else:
                lst = out.setdefault(key, [])
                lst.extend(v for v in value if v not in lst)
    if "texts" in out:
        out["texts"] = sorted(out["texts"], key=lambda t: ui_rank(t, own))[:40]
    if "actions" in out:
        out["actions"] = out["actions"][:120]
    return out


def aggregate(result: AnalysisResult, own: set[str] = frozenset()) -> None:
    """Landkarten aller Dateien einer App zusammenführen – damit die Gesamt-Doku die Funktionen sieht."""
    maps = [n.app_map for n in result.walk() if n is not result and n.app_map]
    if len(maps) < 1 or not result.children:
        return
    merged = merge(maps, own)
    for sec in render(merged, "Funktionslandkarte der gesamten App"):
        if sec.title != "Funktionslandkarte der gesamten App":
            sec.title += " – gesamte App"
        result.add(sec)


class JSBundleAnalyzer(Analyzer):
    name = "jsbundle"
    kinds = ("source",)

    def matches(self, ctx: Context, result: AnalysisResult) -> bool:
        if not super().matches(ctx, result) or len(ctx.data) < MIN_SIZE:
            return False
        lang = ctx.facts.get("language") or source_language(ctx.data, ctx.path.name)
        return lang in ("javascript", "typescript", "html")

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        own = set(ctx.shared.get("first_party_tokens", ()))
        facts = extract(ctx.data.decode("utf-8", "replace"), own)
        if not facts:
            return
        result.app_map = facts
        for sec in render(facts, "Bundle-Auswertung (Funktionslandkarte)"):
            result.add(sec)
