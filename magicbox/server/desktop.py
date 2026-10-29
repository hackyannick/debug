"""Anmeldung der nativen Desktop-App (Windows) – wie bei „gh auth login“ oder RFC 8252.

Ablauf:
1. Die App lauscht auf ``http://127.0.0.1:<port>/callback`` und öffnet im System-Browser
   ``/auth/desktop?port=…&state=…&challenge=…`` (PKCE: challenge = BASE64URL(SHA256(verifier))).
2. Der Browser meldet sich wie gewohnt an (Ory mit Captcha/2FA) und bestätigt auf einer Seite der Magic Box,
   dass die App Zugriff bekommen soll.
3. Die Magic Box leitet mit einem kurzlebigen Einmal-Code zurück an die App.
4. Die App tauscht Code + verifier gegen ein API-Token (``mbd_…``) und ruft damit die REST-API auf
   (``Authorization: Bearer mbd_…``).

Die Tokens werden nur gehasht gespeichert (``desktop_sessions.json``) und lassen sich einzeln widerrufen.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import urllib.parse
from pathlib import Path

from .auth import Identity

TOKEN_PREFIX = "mbd_"
CODE_TTL = 120
STATE_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
CHALLENGE_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class DesktopAuth:
    def __init__(self, data_dir=None, days: int = 30):
        self.days = days
        self._secret = secrets.token_bytes(32)  # nur für die Bestätigungsseite (CSRF), darf beim Neustart wechseln
        self._lock = threading.Lock()
        self._codes: dict[str, tuple[float, str, Identity]] = {}  # code -> (ablauf, challenge, identität)
        self._sessions: dict[str, dict] = {}
        self._file = Path(data_dir).expanduser() / "desktop_sessions.json" if data_dir else None
        self._load()

    # ------------------------------------------------------------------ Browser-Teil
    @staticmethod
    def parse_request(q: dict[str, str]) -> tuple[int, str, str]:
        try:
            port = int(q.get("port", ""))
        except ValueError:
            raise ValueError("Ungültiger Port") from None
        state, challenge = q.get("state", ""), q.get("challenge", "")
        if not 1024 <= port <= 65535 or not STATE_RE.match(state) or not CHALLENGE_RE.match(challenge):
            raise ValueError("Ungültige Anmeldeanfrage der Desktop-App")
        return port, state, challenge

    def csrf(self, ident: Identity, port: int, state: str, challenge: str) -> str:
        msg = f"{ident.method}|{ident.id}|{port}|{state}|{challenge}".encode()
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def check_csrf(self, ident: Identity, port: int, state: str, challenge: str, token: str) -> bool:
        return hmac.compare_digest(self.csrf(ident, port, state, challenge), token or "")

    def approve(self, ident: Identity, port: int, state: str, challenge: str) -> str:
        """Erzeugt den Einmal-Code und liefert die Rücksprung-Adresse zur App."""
        code = secrets.token_urlsafe(32)
        now = time.monotonic()
        with self._lock:
            self._codes = {k: v for k, v in self._codes.items() if v[0] > now}
            if len(self._codes) > 1000:
                raise ValueError("Zu viele offene Anmeldungen")
            self._codes[code] = (now + CODE_TTL, challenge, ident)
        return self.callback(port, {"code": code, "state": state})

    @staticmethod
    def callback(port: int, params: dict[str, str]) -> str:
        return f"http://127.0.0.1:{port}/callback?{urllib.parse.urlencode(params)}"

    # ------------------------------------------------------------------ App-Teil
    def exchange(self, code: str, verifier: str, label: str = "") -> dict:
        with self._lock:
            entry = self._codes.pop(code or "", None)
        if entry is None or entry[0] < time.monotonic():
            raise ValueError("Anmeldecode ungültig oder abgelaufen – bitte erneut anmelden.")
        _, challenge, ident = entry
        expected = base64.urlsafe_b64encode(hashlib.sha256((verifier or "").encode()).digest()).rstrip(b"=").decode()
        if not hmac.compare_digest(expected, challenge):
            raise ValueError("PKCE-Prüfung fehlgeschlagen")
        token = TOKEN_PREFIX + secrets.token_urlsafe(32)
        expires = time.time() + self.days * 86400
        with self._lock:
            now = time.time()
            self._sessions = {k: v for k, v in self._sessions.items() if v["exp"] > now}
            self._sessions[_hash(token)] = {"id": ident.id, "name": ident.name, "method": ident.method,
                                            "groups": list(ident.groups), "exp": expires, "created": now,
                                            "label": label[:80]}
            self._save()
        return {"token": token, "name": ident.name, "expires": int(expires)}

    def identity(self, token: str) -> Identity | None:
        if not token.startswith(TOKEN_PREFIX):
            return None
        with self._lock:
            data = self._sessions.get(_hash(token))
        if not data or data["exp"] < time.time():
            return None
        return Identity(data["id"], data["name"], "desktop", tuple(data.get("groups", [])))

    def revoke(self, token: str) -> bool:
        with self._lock:
            gone = self._sessions.pop(_hash(token), None) is not None
            if gone:
                self._save()
        return gone

    # ------------------------------------------------------------------ Speicher
    def _load(self) -> None:
        if not self._file:
            return
        try:
            data = json.loads(self._file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        now = time.time()
        self._sessions = {k: v for k, v in data.items() if isinstance(v, dict) and v.get("exp", 0) > now}

    def _save(self) -> None:
        if not self._file:
            return
        try:
            self._file.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._file.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._sessions, f)
            os.replace(tmp, self._file)
        except OSError:
            pass
