"""OIDC-Client (Authorization Code Flow mit PKCE) – z. B. gegen Ory Hydra.

Ablauf:  /auth/login → Hydra (Login-UI mit Captcha, Kratos, 2FA, Consent) → /auth/callback
         → Code gegen Tokens tauschen (serverseitig) → ID-Token prüfen → eigene Sitzung (Cookie ``mb_session``).

Der Browser spricht nur mit dem Autorisierungs- und dem Logout-Endpunkt. Discovery, Token-Tausch und JWKS
laufen serverseitig und können über eine interne Adresse gehen (``oidc_internal_base``), falls der Server die
öffentliche Adresse nicht erreicht (kein Hairpin-NAT).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
from pathlib import Path

from magicbox.config import Settings

from .auth import Identity, JWKSVerifier, get_json, parse_cookies

SESSION_COOKIE = "mb_session"
STATE_COOKIE = "mb_oidc_state"
PENDING_TTL = 600
DISCOVERY_TTL = 3600


class OIDCError(Exception):
    pass


def _hash(sid: str) -> str:
    return hashlib.sha256(sid.encode()).hexdigest()


def safe_next(path: str) -> str:
    """Nur lokale Pfade als Rücksprungziel (kein Open Redirect)."""
    if not path or not path.startswith("/") or path.startswith("//") or "\\" in path:
        return "/"
    return path


class OIDCClient:
    def __init__(self, settings: Settings, data_dir=None):
        self.s = settings
        self._disc: dict | None = None
        self._disc_time = 0.0
        self._lock = threading.Lock()
        self._pending: dict[str, tuple[float, str, str, str]] = {}  # state -> (ablauf, nonce, verifier, next)
        self._sessions: dict[str, dict] = {}
        self._file = Path(data_dir).expanduser() / "sessions.json" if data_dir else None
        self.jwks = JWKSVerifier(lambda: self._server_url(self.discovery()["jwks_uri"]))
        self._load()

    # ------------------------------------------------------------------ Konfiguration
    @property
    def redirect_uri(self) -> str:
        if not self.s.public_url:
            raise OIDCError("public_url muss für OIDC gesetzt sein (z. B. https://magicbox.hackdv.com)")
        return self.s.public_url.rstrip("/") + "/auth/callback"

    @property
    def secure(self) -> bool:
        return self.s.public_url.startswith("https://")

    def discovery(self) -> dict:
        with self._lock:
            if self._disc and time.monotonic() - self._disc_time < DISCOVERY_TTL:
                return self._disc
        base = (self.s.oidc_internal_base or self.s.oidc_issuer).rstrip("/")
        if not base:
            raise OIDCError("oidc_issuer ist nicht gesetzt")
        try:
            disc = get_json(f"{base}/.well-known/openid-configuration", {"Accept": "application/json"})
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise OIDCError(f"OIDC-Discovery unter {base} nicht erreichbar: {exc}") from exc
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
            if key not in disc:
                raise OIDCError(f"Discovery ohne {key}")
        with self._lock:
            self._disc, self._disc_time = disc, time.monotonic()
        return disc

    def _server_url(self, url: str) -> str:
        """Öffentliche Endpunkt-URL auf die interne Basis umschreiben (Pfad bleibt)."""
        if not self.s.oidc_internal_base:
            return url
        parts = urllib.parse.urlsplit(url)
        base = urllib.parse.urlsplit(self.s.oidc_internal_base)
        return urllib.parse.urlunsplit((base.scheme, base.netloc, parts.path, parts.query, ""))

    @property
    def issuer(self) -> str:
        return self.s.oidc_issuer or self.discovery()["issuer"]

    # ------------------------------------------------------------------ Login
    def begin(self, next_path: str) -> tuple[str, str]:
        """Gibt (URL zum Autorisierungs-Endpunkt, state) zurück."""
        disc = self.discovery()
        state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        now = time.monotonic()
        with self._lock:
            self._pending = {k: v for k, v in self._pending.items() if v[0] > now}
            if len(self._pending) > 5000:
                raise OIDCError("Zu viele offene Anmeldungen")
            self._pending[state] = (now + PENDING_TTL, nonce, verifier, safe_next(next_path))
        params = {
            "response_type": "code", "client_id": self.s.oidc_client_id, "redirect_uri": self.redirect_uri,
            "scope": self.s.oidc_scopes, "state": state, "nonce": nonce,
            "code_challenge": challenge, "code_challenge_method": "S256",
        }
        return f"{disc['authorization_endpoint']}?{urllib.parse.urlencode(params)}", state

    def complete(self, query: dict[str, str], cookie_header: str) -> tuple[Identity, str, str]:
        """Callback auswerten → (Identität, ID-Token, Rücksprungpfad)."""
        if query.get("error"):
            raise OIDCError(f"Anmeldung abgelehnt: {query.get('error_description') or query['error']}")
        state = query.get("state", "")
        if not state or parse_cookies(cookie_header).get(STATE_COOKIE) != state:
            raise OIDCError("Ungültiger oder abgelaufener Anmeldevorgang (state) – bitte erneut anmelden.")
        with self._lock:
            pending = self._pending.pop(state, None)
        if pending is None or pending[0] < time.monotonic():
            raise OIDCError("Anmeldevorgang abgelaufen – bitte erneut anmelden.")
        _, nonce, verifier, next_path = pending
        tokens = self._token_request(query.get("code", ""), verifier)
        try:
            claims = self.jwks.verify(tokens.get("id_token", ""), issuer=self.issuer,
                                      audience=self.s.oidc_client_id, nonce=nonce)
        except ValueError as exc:
            raise OIDCError(f"ID-Token ungültig: {exc}") from exc
        groups = claims.get("groups") if isinstance(claims.get("groups"), list) else []
        name = claims.get("email") or claims.get("preferred_username") or claims.get("sub", "?")
        ident = Identity(str(claims.get("sub", "")), str(name), "oidc", tuple(map(str, groups)))
        return ident, tokens["id_token"], next_path

    def _token_request(self, code: str, verifier: str) -> dict:
        if not code:
            raise OIDCError("Kein Autorisierungscode erhalten")
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.redirect_uri,
                "code_verifier": verifier}
        headers = {"Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"}
        if self.s.oidc_token_auth == "client_secret_post":
            form.update(client_id=self.s.oidc_client_id, client_secret=self.s.oidc_client_secret)
        else:  # RFC 6749 §2.3.1: ID und Geheimnis vor Base64 form-urlkodieren
            raw = f"{urllib.parse.quote(self.s.oidc_client_id, safe='')}:{urllib.parse.quote(self.s.oidc_client_secret, safe='')}"
            headers["Authorization"] = "Basic " + base64.b64encode(raw.encode()).decode()
        url = self._server_url(self.discovery()["token_endpoint"])
        try:
            return get_json(url, headers, data=urllib.parse.urlencode(form).encode())
        except urllib.error.HTTPError as exc:
            try:
                err = json.loads(exc.read() or b"{}")
            except ValueError:
                err = {}
            detail = err.get("error_description") or err.get("error") or f"HTTP {exc.code}"
            raise OIDCError(f"Token-Tausch fehlgeschlagen: {detail}") from exc
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise OIDCError(f"Token-Endpunkt nicht erreichbar: {exc}") from exc

    # ------------------------------------------------------------------ Sitzungen
    def create_session(self, ident: Identity, id_token: str) -> str:
        sid = secrets.token_urlsafe(32)
        with self._lock:
            now = time.time()
            self._sessions = {k: v for k, v in self._sessions.items() if v["exp"] > now}
            self._sessions[_hash(sid)] = {"id": ident.id, "name": ident.name, "groups": list(ident.groups),
                                          "exp": now + self.s.oidc_session_hours * 3600, "id_token": id_token}
            self._save()
        return sid

    def session_identity(self, headers) -> Identity | None:
        sid = parse_cookies(headers.get("Cookie", "")).get(SESSION_COOKIE, "")
        if not sid:
            return None
        with self._lock:
            data = self._sessions.get(_hash(sid))
        if not data or data["exp"] < time.time():
            return None
        return Identity(data["id"], data["name"], "oidc", tuple(data.get("groups", [])))

    def logout(self, headers) -> str:
        """Beendet die lokale Sitzung und liefert die Logout-URL des Anbieters (oder leer)."""
        sid = parse_cookies(headers.get("Cookie", "")).get(SESSION_COOKIE, "")
        with self._lock:
            data = self._sessions.pop(_hash(sid), None) if sid else None
            self._save()
        try:
            end = self.discovery().get("end_session_endpoint", "")
        except OIDCError:
            return ""
        if not end:
            return ""
        params = {}
        if data and data.get("id_token"):
            params["id_token_hint"] = data["id_token"]
        if self.s.oidc_post_logout_uri:
            params["post_logout_redirect_uri"] = self.s.oidc_post_logout_uri
            params["state"] = secrets.token_urlsafe(8)
        return f"{end}?{urllib.parse.urlencode(params)}" if params else end

    def cookie(self, name: str, value: str, max_age: int | None = None) -> str:
        parts = [f"{name}={value}", "HttpOnly", "Path=/", "SameSite=Lax"]  # Lax: Rücksprung vom Anbieter ist cross-site
        if self.secure:
            parts.append("Secure")
        if max_age is not None:
            parts.append(f"Max-Age={max_age}")
        return "; ".join(parts)

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
        """Sitzungen überleben einen Neustart (gespeichert wird nur der Hash der Sitzungs-ID)."""
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
