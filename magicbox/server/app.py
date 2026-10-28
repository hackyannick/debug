"""HTTP-Server (nur Standardbibliothek): REST-API, Live-Ereignisse (SSE) und die Web-Oberfläche."""

from __future__ import annotations

import hmac
import ipaddress
import json
import mimetypes
import queue
import socket
import threading
import urllib.parse
from dataclasses import asdict, fields
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from magicbox import __version__, tools
from magicbox.config import Settings
from magicbox.llm.client import LLMClient, LLMError

from .jobs import FolderWatcher, JobManager

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
COOKIE = "mb_token"
# Über die Web-Oberfläche änderbare Einstellungen (Netzwerk/Zugang bewusst nicht)
EDITABLE = {
    "use_llm", "provider", "base_url", "model", "api_key", "context_tokens", "max_answer_tokens", "temperature",
    "timeout_s", "language", "audience", "max_llm_children", "max_code_chunks", "profile", "max_archive_depth",
    "max_archive_members", "max_disasm_functions", "use_radare2", "radare2_path", "archive_passwords", "upx_path",
    "sevenzip_path", "use_capa", "capa_path", "capa_rules", "capa_timeout_s", "yara_rules_dir", "ilspy_path",
    "tool_timeout_s",
}
REPORT_FILES = {
    "report": ("report/bericht.html", "text/html; charset=utf-8", None),
    "report.md": ("report/bericht.md", "text/markdown; charset=utf-8", "bericht.md"),
    "analysis.json": ("report/analysis.json", "application/json", "analysis.json"),
    "iocs.csv": ("report/iocs.csv", "text/csv; charset=utf-8", "iocs.csv"),
}
REPORT_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-ancestors 'self'"
UI_CSP = ("default-src 'self'; img-src 'self' data:; style-src 'self'; frame-src 'self'; connect-src 'self'; "
          "frame-ancestors 'none'")


class MagicBoxServer:
    def __init__(self, settings: Settings, host: str | None = None, port: int | None = None,
                 token: str | None = None, config_path: Path | None = None):
        self.settings = settings
        self.config_path = config_path
        self.token = settings.web_token if token is None else token
        self.manager = JobManager(settings)
        self.httpd = ThreadingHTTPServer((host or settings.host, settings.port if port is None else port),
                                         self._handler_class())
        self.httpd.daemon_threads = True
        self.watchers: list[FolderWatcher] = []
        self._serving = False

    @property
    def url(self) -> str:
        host, port = self.httpd.server_address[:2]
        if host in ("0.0.0.0", "::"):
            host = "127.0.0.1"
        return f"http://{host}:{port}"

    def watch(self, folder: Path) -> None:
        w = FolderWatcher(self.manager, folder)
        w.start()
        self.watchers.append(w)

    def serve_forever(self) -> None:
        self._serving = True
        self.httpd.serve_forever(poll_interval=0.5)

    def start_background(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, name="magicbox-http", daemon=True)
        t.start()
        return t

    def shutdown(self) -> None:
        self.manager.stop()
        if self._serving:  # httpd.shutdown() würde sonst ewig auf eine nie gestartete Schleife warten
            self.httpd.shutdown()
        self.httpd.server_close()

    def apply_settings(self, changes: dict) -> Settings:
        types = {f.name: f.type for f in fields(Settings)}
        current = asdict(self.settings)
        for key, value in changes.items():
            if key not in EDITABLE:
                continue
            if key == "api_key" and value == "••••••":
                continue
            if key == "archive_passwords" and isinstance(value, str):
                value = [p.strip() for p in value.splitlines() if p.strip()]
            t = str(types[key])
            if t == "bool":
                value = bool(value)
            elif t == "int":
                value = int(value)
            elif t == "float":
                value = float(value)
            current[key] = value
        new = Settings(**current)
        for f in fields(Settings):  # in-place, damit alle Referenzen (JobManager) die Änderung sehen
            setattr(self.settings, f.name, getattr(new, f.name))
        self.settings.save(self.config_path)
        return self.settings

    # ------------------------------------------------------------------
    def _handler_class(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = f"MagicBox/{__version__}"

            def log_message(self, fmt, *args):  # ruhig – Fehler landen ohnehin in den Antworten
                pass

            # ---------------------------------------------------------- Hilfen
            def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Cache-Control", "no-store")
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)

            def _json(self, obj, status: int = 200) -> None:
                self._send(status, json.dumps(obj, ensure_ascii=False).encode(), "application/json; charset=utf-8")

            def _error(self, status: int, msg: str) -> None:
                self._json({"error": msg}, status)

            def _body_json(self) -> dict:
                n = int(self.headers.get("Content-Length") or 0)
                if n > 1024 * 1024:
                    raise ValueError("Anfrage zu groß")
                return json.loads(self.rfile.read(n) or b"{}")

            def _query(self) -> dict[str, str]:
                return {k: v[-1] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).items()}

            def _cookie_token(self) -> str:
                for part in (self.headers.get("Cookie") or "").split(";"):
                    k, _, v = part.strip().partition("=")
                    if k == COOKIE:
                        return urllib.parse.unquote(v)
                return ""

            def _authorized(self) -> bool:
                if not server.token:
                    return True
                auth = self.headers.get("Authorization", "")
                given = auth[7:] if auth.startswith("Bearer ") else self._cookie_token()
                return bool(given) and hmac.compare_digest(given.encode(), server.token.encode())

            def _host_ok(self) -> bool:
                """Schutz vor DNS-Rebinding: ohne Token nur Zugriffe per IP, localhost oder Rechnername."""
                if server.token:
                    return True
                host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
                if host in ("localhost", socket.gethostname().lower(), socket.getfqdn().lower()):
                    return True
                try:
                    ipaddress.ip_address(host)
                    return True
                except ValueError:
                    return False

            def _csrf_ok(self) -> bool:
                # Browser senden eigene Header nur von derselben Herkunft (sonst CORS-Preflight → blockiert)
                return self.headers.get("X-MagicBox") == "1"

            # ---------------------------------------------------------- Routing
            def do_HEAD(self):
                self.do_GET()

            def do_GET(self):
                self._dispatch("GET")

            def do_POST(self):
                self._dispatch("POST")

            def do_PUT(self):
                self._dispatch("PUT")

            def do_DELETE(self):
                self._dispatch("DELETE")

            def _dispatch(self, method: str) -> None:
                path = urllib.parse.urlsplit(self.path).path
                try:
                    if not self._host_ok():
                        return self._error(403, "Unbekannter Hostname – Zugriff per IP oder Zugangsschlüssel (web_token) einrichten.")
                    if method == "GET" and (path == "/" or path.startswith("/static/")):
                        return self._static(path)
                    if not path.startswith("/api/"):
                        return self._error(404, "Nicht gefunden")
                    if path == "/api/login" and method == "POST":
                        return self._login()
                    if not self._authorized():
                        return self._error(401, "Zugangsschlüssel erforderlich")
                    if method != "GET" and not self._csrf_ok():
                        return self._error(403, "Fehlender X-MagicBox-Header")
                    return self._api(method, path)
                except KeyError:
                    return self._error(404, "Auftrag nicht gefunden")
                except (ValueError, TypeError) as exc:
                    return self._error(400, str(exc))
                except (BrokenPipeError, ConnectionResetError):
                    return None
                except Exception as exc:  # noqa: BLE001
                    return self._error(500, f"{exc.__class__.__name__}: {exc}")

            def _static(self, path: str) -> None:
                q = self._query()
                if path == "/" and q.get("token") and server.token:
                    # Einmal-Login per Link (z. B. aus der Desktop-App): Cookie setzen und Token aus der URL entfernen
                    if hmac.compare_digest(q["token"].encode(), server.token.encode()):
                        cookie = f"{COOKIE}={urllib.parse.quote(server.token)}; HttpOnly; SameSite=Strict; Path=/"
                        return self._send(303, b"", "text/plain", {"Location": "/", "Set-Cookie": cookie})
                name = "index.html" if path == "/" else path[len("/static/"):]
                target = (WEB_DIR / name).resolve()
                if WEB_DIR not in target.parents or not target.is_file():
                    return self._error(404, "Nicht gefunden")
                ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
                if ctype.startswith("text/") or ctype.endswith("javascript"):
                    ctype += "; charset=utf-8"
                self._send(200, target.read_bytes(), ctype, {"Content-Security-Policy": UI_CSP})

            def _login(self) -> None:
                token = str(self._body_json().get("token", ""))
                if server.token and hmac.compare_digest(token.encode(), server.token.encode()):
                    cookie = f"{COOKIE}={urllib.parse.quote(token)}; HttpOnly; SameSite=Strict; Path=/"
                    body = json.dumps({"ok": True}).encode()
                    return self._send(200, body, "application/json", {"Set-Cookie": cookie})
                return self._error(401, "Falscher Zugangsschlüssel")

            def _api(self, method: str, path: str) -> None:
                m = server.manager
                parts = path.strip("/").split("/")[1:]  # ohne "api"
                if parts == ["status"]:
                    s = server.settings
                    return self._json({
                        "version": __version__,
                        "llm": {"enabled": s.use_llm, "provider": s.provider, "url": s.base_url, "model": s.model},
                        "profile": s.profile,
                        "tools": [asdict(t) for t in tools.status(s)],
                        "auth": bool(server.token),
                    })
                if parts == ["events"] and method == "GET":
                    return self._events()
                if parts == ["settings"]:
                    if method == "PUT":
                        server.apply_settings(self._body_json())
                    data = {k: v for k, v in asdict(server.settings).items() if k in EDITABLE}
                    if data.get("api_key"):
                        data["api_key"] = "••••••"
                    return self._json(data)
                if parts == ["llm", "check"] and method == "POST":
                    try:
                        return self._json({"ok": True, "message": LLMClient(server.settings).check()})
                    except LLMError as exc:
                        return self._json({"ok": False, "message": str(exc)})
                if parts == ["llm", "models"]:
                    try:
                        return self._json({"models": LLMClient(server.settings).list_models()})
                    except LLMError as exc:
                        return self._json({"models": [], "error": str(exc)})
                if parts == ["jobs"]:
                    if method == "POST":
                        return self._upload()
                    return self._json(m.list())
                if len(parts) >= 2 and parts[0] == "jobs":
                    job_id = parts[1]
                    m.job_dir(job_id)  # validiert die ID
                    if len(parts) == 2:
                        if method == "DELETE":
                            try:
                                m.delete(job_id)
                            except RuntimeError as exc:
                                return self._error(409, str(exc))
                            return self._json({"ok": True})
                        job = m.get(job_id)
                        return self._json({**job.public(), "log": m.log_lines(job_id), "ai": m.ai_text(job_id)})
                    action = parts[2]
                    if action == "cancel" and method == "POST":
                        m.cancel(job_id)
                        return self._json(m.get(job_id).public())
                    if action == "rerun" and method == "POST":
                        return self._json(m.rerun(job_id).public())
                    if action in REPORT_FILES and method == "GET":
                        m.get(job_id)
                        rel, ctype, download = REPORT_FILES[action]
                        f = m.job_dir(job_id) / rel
                        if not f.is_file():
                            return self._error(404, "Bericht noch nicht fertig")
                        extra = {"Content-Security-Policy": REPORT_CSP}
                        if download:
                            name = f"{Path(m.get(job_id).name).stem}_{download}"
                            extra["Content-Disposition"] = f"attachment; filename*=UTF-8''{urllib.parse.quote(name)}"
                        return self._send(200, f.read_bytes(), ctype, extra)
                return self._error(404, "Unbekannter Endpunkt")

            def _upload(self) -> None:
                q = self._query()
                size = int(self.headers.get("Content-Length") or -1)
                if size < 0:
                    raise ValueError("Content-Length fehlt")
                if size > server.settings.max_upload_mb * 1024 * 1024:
                    self.close_connection = True
                    return self._error(413, f"Datei größer als {server.settings.max_upload_mb} MB")
                name = q.get("name") or "probe"
                profile = q.get("profile", "") if q.get("profile") in ("malware", "allgemein") else ""
                job = server.manager.create(name, self.rfile, size, password=q.get("password", ""), profile=profile)
                return self._json(job.public(), 201)

            def _events(self) -> None:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Accel-Buffering", "no")
                self.end_headers()
                self.close_connection = True
                sub = server.manager.hub.subscribe()
                try:
                    self.wfile.write(b"retry: 2000\n\n")
                    self.wfile.flush()
                    while not server.manager._stop.is_set():
                        try:
                            event = sub.get(timeout=15)
                            payload = json.dumps(event, ensure_ascii=False)
                            self.wfile.write(f"data: {payload}\n\n".encode())
                        except queue.Empty:
                            self.wfile.write(b": ping\n\n")
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError, OSError):
                    pass
                finally:
                    server.manager.hub.unsubscribe(sub)

        return Handler


def serve(settings: Settings, host: str | None = None, port: int | None = None, watch: list[Path] | None = None,
          config_path: Path | None = None) -> None:
    srv = MagicBoxServer(settings, host=host, port=port, config_path=config_path)
    for folder in watch or []:
        srv.watch(folder)
    print(f"🪄 Magic Box {__version__} läuft auf {srv.url}  (Daten: {srv.manager.root})")
    if srv.httpd.server_address[0] not in ("127.0.0.1", "::1") and not srv.token:
        print("⚠  Server ist im Netzwerk erreichbar, aber ohne Zugangsschlüssel. Empfohlen: web_token in der Konfiguration setzen.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown()
