"""Anmeldung für den Magic-Box-Server: Zugangsschlüssel, Ory Kratos (Session) oder Ory Oathkeeper (ID-Token).

Kratos:     Die Magic Box prüft das Session-Cookie (``ory_kratos_session`` bzw. ``ory_session_*``) per
            ``GET /sessions/whoami`` bei Kratos. Ohne gültige Sitzung geht es in den Kratos-Login-Flow
            (inkl. Captcha/2FA, wie in Kratos bzw. dem Login-UI konfiguriert) und danach zurück.
Oathkeeper: Oathkeeper steht davor, authentifiziert (z. B. ``cookie_session`` gegen Kratos) und reicht per
            ``id_token``-Mutator ein signiertes JWT im ``Authorization``-Header weiter. Die Magic Box prüft
            Signatur (RS256/384/512 über JWKS), Ablauf, Aussteller und Zielgruppe.

Für Skripte/CLI bleibt ``Authorization: Bearer <web_token>`` in jedem Modus möglich (wenn ``web_token`` gesetzt ist).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from magicbox.config import Settings

COOKIE = "mb_token"
WHOAMI_TTL = 30  # Sekunden – kurzer Cache, damit nicht jede Anfrage Kratos fragt
JWKS_TTL = 600
DIGEST_INFO = {  # PKCS#1-v1.5-Präfixe (ASN.1 DigestInfo)
    "RS256": (hashlib.sha256, bytes.fromhex("3031300d060960864801650304020105000420")),
    "RS384": (hashlib.sha384, bytes.fromhex("3041300d060960864801650304020205000430")),
    "RS512": (hashlib.sha512, bytes.fromhex("3051300d060960864801650304020305000440")),
}
# Verbindungen zu Kratos/Oathkeeper sind intern – nie über einen System-Proxy leiten
_DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))


@dataclass
class Identity:
    id: str
    name: str
    method: str  # token | kratos | oathkeeper | none


class AuthFailed(Exception):
    """Nicht angemeldet (401) – ``login_url`` sagt dem Browser, wohin."""

    def __init__(self, message: str, login_url: str = ""):
        super().__init__(message)
        self.login_url = login_url


class Forbidden(Exception):
    """Angemeldet, aber nicht berechtigt (403)."""


def b64url(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def rsa_verify(alg: str, n: int, e: int, message: bytes, signature: bytes) -> bool:
    """RSASSA-PKCS1-v1_5-Prüfung ohne Zusatzbibliotheken."""
    if alg not in DIGEST_INFO:
        return False
    hash_fn, prefix = DIGEST_INFO[alg]
    k = (n.bit_length() + 7) // 8
    if len(signature) != k or k < 256:  # mindestens 2048 Bit
        return False
    em = pow(int.from_bytes(signature, "big"), e, n).to_bytes(k, "big")
    t = prefix + hash_fn(message).digest()
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    return hmac.compare_digest(em, expected)


def parse_cookies(header: str) -> dict[str, str]:
    out = {}
    for part in (header or "").split(";"):
        k, sep, v = part.strip().partition("=")
        if sep:
            out[k] = v
    return out


def allowed(name: str, rules: list[str]) -> bool:
    if not rules:
        return True
    low = name.lower()
    for r in rules:
        r = r.strip().lower()
        if r and (low == r or (r.startswith("@") and low.endswith(r))):
            return True
    return False


class Authenticator:
    def __init__(self, settings: Settings, token: str):
        self.s = settings
        self.token = token
        self._cache: dict[str, tuple[float, Identity | None, str]] = {}
        self._jwks: dict[str, dict] = {}
        self._jwks_time = 0.0
        self._lock = threading.Lock()

    @property
    def mode(self) -> str:
        return self.s.auth_mode if self.s.auth_mode in ("kratos", "oathkeeper") else "token"

    @property
    def protects(self) -> bool:
        """Ist überhaupt eine Anmeldung aktiv? (sonst greift nur der Hostnamen-Schutz)"""
        return self.mode != "token" or bool(self.token)

    # ------------------------------------------------------------------ Einstieg
    def authenticate(self, headers, return_to: str) -> Identity:
        """Gibt die Identität zurück oder wirft AuthFailed/Forbidden."""
        auth = headers.get("Authorization", "")
        bearer = auth[7:].strip() if auth.startswith("Bearer ") else ""
        cookie_token = urllib.parse.unquote(parse_cookies(headers.get("Cookie", "")).get(COOKIE, ""))
        for candidate in (bearer, cookie_token):
            if self.token and candidate and hmac.compare_digest(candidate.encode(), self.token.encode()):
                return Identity("token", "Zugangsschlüssel", "token")

        if self.mode == "token":
            if not self.token:
                return Identity("anonymous", "lokal", "none")
            raise AuthFailed("Zugangsschlüssel erforderlich")
        if self.mode == "kratos":
            ident = self._kratos(headers, return_to)
        else:
            ident = self._oathkeeper(bearer, return_to)
        if not allowed(ident.name, self.s.auth_allowed):
            raise Forbidden(f"{ident.name} ist für die Magic Box nicht freigeschaltet.")
        return ident

    def login_url(self, return_to: str, aal2: bool = False) -> str:
        if self.s.auth_login_url:
            sep = "&" if "?" in self.s.auth_login_url else "?"
            return f"{self.s.auth_login_url}{sep}return_to={urllib.parse.quote(return_to, safe='')}"
        if self.mode == "kratos" or self.s.kratos_public_url:
            base = (self.s.kratos_browser_url or self.s.kratos_public_url).rstrip("/")
            q = {"return_to": return_to}
            if aal2:
                q["aal"] = "aal2"
            return f"{base}/self-service/login/browser?{urllib.parse.urlencode(q)}"
        if self.mode == "oathkeeper":
            # Über Oathkeeper aufgerufen, greift dessen Redirect-Error-Handler zum Login
            return self.s.public_url or ""
        return ""

    def logout_url(self, headers, return_to: str) -> str:
        """Kratos-Logout-Link für die aktuelle Sitzung (Browser-Flow), sonst leer."""
        if not self.s.kratos_public_url:
            return ""
        cookies = self._ory_cookies(headers)
        if not cookies:
            return ""
        q = urllib.parse.urlencode({"return_to": return_to})
        try:
            data = self._get_json(f"{self.s.kratos_public_url.rstrip('/')}/self-service/logout/browser?{q}",
                                  {"Cookie": cookies, "Accept": "application/json"})
        except (OSError, ValueError, urllib.error.URLError):
            return ""
        return data.get("logout_url", "")

    # ------------------------------------------------------------------ Kratos
    @staticmethod
    def _ory_cookies(headers) -> str:
        cookies = parse_cookies(headers.get("Cookie", ""))
        return "; ".join(f"{k}={v}" for k, v in cookies.items() if k.startswith("ory_"))

    def _kratos(self, headers, return_to: str) -> Identity:
        if not self.s.kratos_public_url:
            raise AuthFailed("auth_mode=kratos, aber kratos_public_url ist nicht gesetzt.")
        cookies = self._ory_cookies(headers)
        session_token = headers.get("X-Session-Token", "")
        if not cookies and not session_token:
            raise AuthFailed("Nicht angemeldet", self.login_url(return_to))
        key = hashlib.sha256(f"{cookies}|{session_token}".encode()).hexdigest()
        now = time.monotonic()
        with self._lock:
            hit = self._cache.get(key)
        if hit and hit[0] > now:
            ident, reason = hit[1], hit[2]
        else:
            ident, reason = self._whoami(cookies, session_token)
            with self._lock:
                if len(self._cache) > 2000:
                    self._cache.clear()
                self._cache[key] = (now + WHOAMI_TTL, ident, reason)
        if ident is None:
            raise AuthFailed(reason, self.login_url(return_to, aal2=reason == "aal2"))
        return ident

    def _whoami(self, cookies: str, session_token: str) -> tuple[Identity | None, str]:
        h = {"Accept": "application/json"}
        if cookies:
            h["Cookie"] = cookies
        if session_token:
            h["X-Session-Token"] = session_token
        try:
            data = self._get_json(f"{self.s.kratos_public_url.rstrip('/')}/sessions/whoami", h)
        except urllib.error.HTTPError as exc:
            # 403 bei Kratos = Sitzung vorhanden, aber höhere AAL nötig
            return None, "aal2" if exc.code == 403 else "Sitzung ungültig oder abgelaufen"
        except (OSError, ValueError, urllib.error.URLError) as exc:
            return None, f"Kratos nicht erreichbar: {exc}"
        if not data.get("active"):
            return None, "Sitzung inaktiv"
        if self.s.auth_require_aal2 and data.get("authenticator_assurance_level") != "aal2":
            return None, "aal2"
        identity = data.get("identity") or {}
        traits = identity.get("traits") or {}
        name = (traits.get("email") or traits.get("username")
                or (traits.get("name") if isinstance(traits.get("name"), str) else "") or identity.get("id", "?"))
        return Identity(identity.get("id", ""), str(name), "kratos"), ""

    @staticmethod
    def _get_json(url: str, headers: dict) -> dict:
        req = urllib.request.Request(url, headers=headers)
        with _DIRECT.open(req, timeout=10) as r:
            return json.loads(r.read() or b"{}")

    # ------------------------------------------------------------------ Oathkeeper (ID-Token)
    def _oathkeeper(self, jwt: str, return_to: str) -> Identity:
        if not jwt or jwt.count(".") != 2:
            raise AuthFailed("Kein ID-Token – Zugriff nur über Oathkeeper", self.login_url(return_to))
        try:
            claims = self.verify_jwt(jwt)
        except ValueError as exc:
            raise AuthFailed(f"ID-Token ungültig: {exc}", self.login_url(return_to)) from exc
        session = claims.get("session") or {}
        traits = ((session.get("identity") or {}).get("traits") or {}) if isinstance(session, dict) else {}
        name = claims.get("email") or traits.get("email") or claims.get("preferred_username") or claims.get("sub", "?")
        if self.s.auth_require_aal2 and claims.get("aal", session.get("authenticator_assurance_level")) not in (None, "aal2"):
            raise AuthFailed("Zweiter Faktor erforderlich", self.login_url(return_to, aal2=True))
        return Identity(str(claims.get("sub", "")), str(name), "oathkeeper")

    def verify_jwt(self, jwt: str) -> dict:
        head_b64, body_b64, sig_b64 = jwt.split(".")
        try:
            header = json.loads(b64url(head_b64))
            claims = json.loads(b64url(body_b64))
            signature = b64url(sig_b64)
        except (ValueError, json.JSONDecodeError) as exc:
            raise ValueError("nicht dekodierbar") from exc
        alg = header.get("alg")
        if alg not in DIGEST_INFO:
            raise ValueError(f"Algorithmus {alg!r} nicht erlaubt")
        key = self._key(header.get("kid"))
        n, e = int.from_bytes(b64url(key["n"]), "big"), int.from_bytes(b64url(key["e"]), "big")
        if not rsa_verify(alg, n, e, f"{head_b64}.{body_b64}".encode(), signature):
            raise ValueError("Signatur falsch")
        now = time.time()
        if "exp" not in claims or now > float(claims["exp"]) + 60:
            raise ValueError("abgelaufen")
        if "nbf" in claims and now < float(claims["nbf"]) - 60:
            raise ValueError("noch nicht gültig")
        if self.s.oathkeeper_issuer and claims.get("iss") != self.s.oathkeeper_issuer:
            raise ValueError("falscher Aussteller (iss)")
        if self.s.oathkeeper_audience:
            aud = claims.get("aud")
            auds = aud if isinstance(aud, list) else [aud]
            if self.s.oathkeeper_audience not in auds:
                raise ValueError("falsche Zielgruppe (aud)")
        return claims

    def _key(self, kid: str | None) -> dict:
        with self._lock:
            fresh = time.monotonic() - self._jwks_time < JWKS_TTL
            key = self._pick(kid)
        # unbekanntes kid → neu laden (z. B. Schlüsselrotation), aber höchstens alle 10 s
        if (key is None and time.monotonic() - self._jwks_time > 10) or not fresh:
            self._refresh_jwks()
            with self._lock:
                key = self._pick(kid)
        if key is None:
            raise ValueError("unbekannter Schlüssel (kid)")
        return key

    def _pick(self, kid: str | None) -> dict | None:
        if kid:
            return self._jwks.get(kid)
        rsa = [k for k in self._jwks.values() if k.get("kty") == "RSA"]
        return rsa[0] if len(rsa) == 1 else None

    def _refresh_jwks(self) -> None:
        if not self.s.oathkeeper_jwks_url:
            raise ValueError("oathkeeper_jwks_url ist nicht gesetzt")
        try:
            data = self._get_json(self.s.oathkeeper_jwks_url, {"Accept": "application/json"})
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise ValueError(f"JWKS nicht abrufbar: {exc}") from exc
        keys = {k.get("kid", f"_{i}"): k for i, k in enumerate(data.get("keys", []))
                if k.get("kty") == "RSA" and k.get("use", "sig") == "sig"}
        with self._lock:
            self._jwks = keys
            self._jwks_time = time.monotonic()
