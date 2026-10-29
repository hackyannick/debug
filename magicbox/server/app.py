"""HTTP-Server (nur Standardbibliothek): REST-API, Live-Ereignisse (SSE) und die Web-Oberfläche."""

from __future__ import annotations

import hmac
import html
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
from magicbox.report.builder import build_classic_html

from .auth import COOKIE, AuthFailed, Authenticator, Forbidden, Identity
from .oidc import SESSION_COOKIE, STATE_COOKIE, OIDCError
from .jobs import FolderWatcher, JobManager

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
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
        self.auth = Authenticator(settings, self.token, data_dir=settings.data_dir)
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
                    for item in (v if isinstance(v, list) else [v]):
                        self.send_header(k, item)
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

            def _return_to(self) -> str:
                """Adresse, zu der der Browser nach dem Login zurückkehrt."""
                if server.settings.public_url:
                    return server.settings.public_url.rstrip("/") + "/"
                proto = self.headers.get("X-Forwarded-Proto", "http").split(",")[0].strip() or "http"
                host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or "127.0.0.1"
                return f"{proto}://{host.split(',')[0].strip()}/"

            def _identify(self) -> Identity:
                return server.auth.authenticate(self.headers, self._return_to())

            def _host_ok(self) -> bool:
                """Schutz vor DNS-Rebinding: ohne Anmeldung nur Zugriffe per IP, localhost oder Rechnername."""
                if server.auth.protects:
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
                    if method == "GET" and path.startswith("/static/"):
                        return self._static(path)
                    if method == "GET" and path == "/":
                        return self._index()
                    if method == "GET" and path == "/auth/logout":
                        return self._logout()
                    if method == "GET" and path in ("/auth/login", "/auth/callback") and server.auth.oidc:
                        return self._oidc_login() if path == "/auth/login" else self._oidc_callback()
                    if method == "GET" and path == "/auth/info":
                        return self._json({"version": __version__, "mode": server.auth.mode,
                                           "login": server.auth.desktop_login})
                    if path == "/auth/desktop" and method in ("GET", "POST"):
                        return self._desktop_approve(method)
                    if path == "/auth/desktop/token" and method == "POST":
                        body = self._body_json()
                        return self._json(server.auth.desktop.exchange(
                            str(body.get("code", "")), str(body.get("verifier", "")), str(body.get("label", ""))))
                    if not path.startswith("/api/"):
                        return self._error(404, "Nicht gefunden")
                    if path == "/api/login" and method == "POST":
                        return self._login()
                    try:
                        self.identity = self._identify()
                    except AuthFailed as exc:
                        return self._json({"error": str(exc), "login_url": exc.login_url, "mode": server.auth.mode}, 401)
                    except Forbidden as exc:
                        return self._error(403, str(exc))
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

            def _index(self) -> None:
                q = self._query()
                if q.get("token") and server.token:
                    # Einmal-Login per Link (z. B. aus der Desktop-App): Cookie setzen und Token aus der URL entfernen
                    if hmac.compare_digest(q["token"].encode(), server.token.encode()):
                        cookie = f"{COOKIE}={urllib.parse.quote(server.token)}; HttpOnly; SameSite=Strict; Path=/"
                        return self._send(303, b"", "text/plain", {"Location": "/", "Set-Cookie": cookie})
                if server.auth.mode != "token":
                    # Bei Ory direkt zum Login weiterleiten statt eine leere Oberfläche zu zeigen
                    try:
                        self._identify()
                    except AuthFailed as exc:
                        if exc.login_url:
                            return self._send(303, b"", "text/plain", {"Location": exc.login_url})
                        return self._send(401, _page("Anmeldung erforderlich", html.escape(str(exc))),
                                          "text/html; charset=utf-8")
                    except Forbidden as exc:
                        return self._send(403, _page("Kein Zugriff", f"{html.escape(str(exc))} <a href='/auth/logout'>Abmelden</a>"),
                                          "text/html; charset=utf-8")
                return self._static("/static/index.html")

            def _form(self) -> dict[str, str]:
                n = int(self.headers.get("Content-Length") or 0)
                if n > 65536:
                    raise ValueError("Anfrage zu groß")
                raw = self.rfile.read(n).decode("utf-8", "replace")
                return {k: v[-1] for k, v in urllib.parse.parse_qs(raw).items()}

            def _desktop_approve(self, method: str) -> None:
                """Browser-Teil der Desktop-Anmeldung: Login (Ory) → Bestätigung → Rücksprung zur App."""
                desk = server.auth.desktop
                html_type = "text/html; charset=utf-8"
                q = self._query() if method == "GET" else self._form()
                try:
                    port, state, challenge = desk.parse_request(q)
                except ValueError as exc:
                    return self._send(400, _page("Anmeldung fehlgeschlagen", html.escape(str(exc))), html_type)
                if server.auth.desktop_login != "browser":
                    return self._send(400, _page("Anmeldung über die App", "Dieser Server nutzt einen Zugangsschlüssel – "
                                                 "bitte direkt in der Desktop-App eingeben."), html_type)
                return_to = self._return_to().rstrip("/") + "/auth/desktop?" + urllib.parse.urlencode(
                    {"port": port, "state": state, "challenge": challenge})
                try:
                    ident = server.auth.authenticate(self.headers, return_to)
                except AuthFailed as exc:
                    if exc.login_url and method == "GET":
                        return self._send(303, b"", "text/plain", {"Location": exc.login_url})
                    return self._send(401, _page("Anmeldung erforderlich", html.escape(str(exc))), html_type)
                except Forbidden as exc:
                    return self._send(403, _page("Kein Zugriff", html.escape(str(exc))), html_type)
                if ident.method == "desktop":  # ein App-Token darf keine weiteren Tokens ausstellen
                    return self._send(403, _page("Kein Zugriff", "Bitte im Browser anmelden."), html_type)
                if method == "POST":
                    if not desk.check_csrf(ident, port, state, challenge, q.get("csrf", "")):
                        return self._send(403, _page("Anmeldung fehlgeschlagen", "Bestätigung ungültig oder abgelaufen – "
                                                     "bitte die Anmeldung in der App neu starten."), html_type)
                    if q.get("decision") != "allow":
                        target = desk.callback(port, {"error": "access_denied", "state": state})
                    else:
                        target = desk.approve(ident, port, state, challenge)
                    return self._send(303, b"", "text/plain", {"Location": target})
                hidden = "".join(f"<input type='hidden' name='{k}' value='{html.escape(str(v), quote=True)}'>"
                                 for k, v in (("port", port), ("state", state), ("challenge", challenge),
                                              ("csrf", desk.csrf(ident, port, state, challenge))))
                btn = ("padding:8px 18px;border-radius:6px;font:inherit;cursor:pointer;margin-right:8px;"
                       "border:1px solid {b};background:{bg};color:#fff")
                body = (f"<p>Die <b>Magic-Box-Desktop-App</b> auf diesem PC möchte im Namen von "
                        f"<b>{html.escape(ident.name)}</b> auf die Magic Box zugreifen.</p>"
                        "<p style='color:#8b94a5'>Nur zulassen, wenn du die Anmeldung gerade selbst in der App "
                        f"gestartet hast. Die Anmeldung gilt {server.settings.desktop_session_days} Tage und endet "
                        "mit „Abmelden“ in der App.</p>"
                        f"<form method='post' action='/auth/desktop'>{hidden}"
                        f"<button name='decision' value='allow' style='{btn.format(b='#0b5ed7', bg='#0b5ed7')}'>"
                        "Zulassen</button>"
                        f"<button name='decision' value='deny' style='{btn.format(b='#313847', bg='#171b23')}'>"
                        "Abbrechen</button></form>")
                return self._send(200, _page("Desktop-App anmelden", body), html_type,
                                  {"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                   "form-action 'self' http://127.0.0.1:*; frame-ancestors 'none'"})

            def _logout(self) -> None:
                clear = [f"{COOKIE}=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/"]
                if server.auth.oidc:
                    oidc = server.auth.oidc
                    target = oidc.logout(self.headers) or "/"
                    clear.append(oidc.cookie(SESSION_COOKIE, "", max_age=0))
                else:
                    target = server.auth.logout_url(self.headers, self._return_to()) or "/"
                return self._send(303, b"", "text/plain", {"Location": target, "Set-Cookie": clear})

            def _oidc_login(self) -> None:
                oidc = server.auth.oidc
                try:
                    url, state = oidc.begin(self._query().get("next", "/"))
                except OIDCError as exc:
                    return self._send(502, _page("Anmeldung nicht möglich", html.escape(str(exc))),
                                      "text/html; charset=utf-8")
                return self._send(303, b"", "text/plain",
                                  {"Location": url, "Set-Cookie": oidc.cookie(STATE_COOKIE, state, max_age=600)})

            def _oidc_callback(self) -> None:
                oidc = server.auth.oidc
                retry = "<a href='/auth/login'>Erneut anmelden</a>"
                try:
                    ident, id_token, next_path = oidc.complete(self._query(), self.headers.get("Cookie", ""))
                    server.auth.check_access(ident)
                except OIDCError as exc:
                    return self._send(400, _page("Anmeldung fehlgeschlagen", f"{html.escape(str(exc))}<br>{retry}"),
                                      "text/html; charset=utf-8")
                except Forbidden as exc:
                    return self._send(403, _page("Kein Zugriff", f"{html.escape(str(exc))}<br>"
                                                 "<a href='/auth/logout'>Abmelden</a>"), "text/html; charset=utf-8")
                sid = oidc.create_session(ident, id_token)
                cookies = [oidc.cookie(SESSION_COOKIE, sid, max_age=self.server_settings_hours()),
                           oidc.cookie(STATE_COOKIE, "", max_age=0)]
                return self._send(303, b"", "text/plain", {"Location": next_path, "Set-Cookie": cookies})

            def server_settings_hours(self) -> int:
                return server.settings.oidc_session_hours * 3600

            def _static(self, path: str) -> None:
                name = path[len("/static/"):]
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
                    ident = self.identity
                    return self._json({
                        "version": __version__,
                        "llm": {"enabled": s.use_llm, "provider": s.provider, "url": s.base_url, "model": s.model},
                        "profile": s.profile,
                        "tools": [asdict(t) for t in tools.status(s)],
                        "auth": server.auth.protects,
                        "auth_mode": server.auth.mode,
                        "user": {"name": ident.name, "method": ident.method},
                        "can_logout": ident.method != "none",
                    })
                if parts == ["logout"] and method == "POST":  # Desktop-App: eigenes Token widerrufen
                    auth = self.headers.get("Authorization", "")
                    revoked = server.auth.desktop.revoke(auth[7:].strip()) if auth.startswith("Bearer ") else False
                    return self._json({"ok": True, "revoked": revoked})
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
                        # Stand von Protokoll/KI-Text vor dem Job-Stand lesen: so ist nichts davon jünger
                        log_total = m.log_count.get(job_id)
                        log, ai = m.log_lines(job_id), m.ai_text(job_id)
                        return self._json({**m.get(job_id).public(), "log": log, "ai": ai,
                                           "log_total": len(log) if log_total is None else log_total})
                    action = parts[2]
                    if action == "cancel" and method == "POST":
                        m.cancel(job_id)
                        return self._json(m.get(job_id).public())
                    if action == "rerun" and method == "POST":
                        return self._json(m.rerun(job_id).public())
                    if action == "ask" and method == "POST":
                        try:
                            job = m.ask(job_id, str(self._body_json().get("question", "")))
                        except RuntimeError as exc:
                            return self._error(409, str(exc))
                        return self._json(job.public())
                    if action == "report.classic" and method == "GET":  # für die Windows-App (IE-Engine)
                        f = m.job_dir(job_id) / "report" / "bericht.md"
                        if not f.is_file():
                            return self._error(404, "Bericht noch nicht fertig")
                        page = build_classic_html(f.read_text(encoding="utf-8"), m.get(job_id).name)
                        return self._send(200, page.encode(), "text/html; charset=utf-8",
                                          {"Content-Security-Policy": REPORT_CSP})
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
                job = server.manager.create(name, self.rfile, size, password=q.get("password", ""), profile=profile,
                                            user=self.identity.name, question=q.get("question", ""))
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


def _page(title: str, body: str) -> bytes:
    """Einfache Hinweisseite (z. B. Anmeldefehler) im selben dunklen Kartenstil wie die Oberfläche."""
    return (f"<!doctype html><meta charset='utf-8'><meta name='color-scheme' content='dark'>"
            f"<meta name='viewport' content='width=device-width, initial-scale=1'><title>{html.escape(title)}</title>"
            "<body style=\"margin:0;min-height:100vh;background:#07090d;color:#e5e8ee;"
            "font:15px/1.5 'Segoe UI',system-ui,sans-serif;display:flex;flex-direction:column;align-items:center\">"
            "<div style='color:#5aa2ff;font-weight:650;margin:28px 0 22px'>🪄 Magic Box</div>"
            "<div style='width:min(520px,calc(100vw - 32px));background:#11141a;border:1px solid #252b36;"
            "border-radius:6px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,.55)'>"
            f"<div style='background:#0b5ed7;color:#fff;padding:11px 16px'>{html.escape(title)}</div>"
            f"<div style='padding:18px 16px'>{body}</div></div></body>").encode()


def serve(settings: Settings, host: str | None = None, port: int | None = None, watch: list[Path] | None = None,
          config_path: Path | None = None) -> None:
    srv = MagicBoxServer(settings, host=host, port=port, config_path=config_path)
    for folder in watch or []:
        srv.watch(folder)
    print(f"🪄 Magic Box {__version__} läuft auf {srv.url}  (Daten: {srv.manager.root})")
    print(f"   Anmeldung: {srv.auth.mode}")
    if srv.httpd.server_address[0] not in ("127.0.0.1", "::1") and not srv.auth.protects:
        print("⚠  Server ist im Netzwerk erreichbar, aber ohne Anmeldung. Empfohlen: web_token oder auth_mode (Ory) setzen.")
    if srv.auth.mode == "oidc" and not srv.settings.public_url:
        print("⚠  auth_mode=oidc: public_url fehlt (z. B. https://magicbox.hackdv.com) – Rücksprung-URL unbekannt.")
    if srv.auth.mode == "oathkeeper" and srv.httpd.server_address[0] not in ("127.0.0.1", "::1"):
        print("⚠  auth_mode=oathkeeper: Magic Box sollte nur auf 127.0.0.1 lauschen und ausschließlich über Oathkeeper erreichbar sein.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown()
