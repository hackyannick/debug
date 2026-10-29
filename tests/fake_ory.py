"""Nachgebaute Ory-Endpunkte für Tests: Kratos (/sessions/whoami, Logout) und Oathkeeper-JWKS."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _b64(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class FakeOry:
    """``sessions``: Cookie-Wert -> whoami-Antwort (oder HTTP-Status als int)."""

    def __init__(self):
        self.sessions: dict[str, dict | int] = {}
        # Hydra: code -> (Claims, code_challenge, redirect_uri); Client-Zugang
        self.codes: dict[str, tuple[dict, str, str]] = {}
        self.client = ("magicbox", "")
        self.signing_key = None
        self.public = "https://id.example.de"
        self.token_requests: list[dict] = []
        self.userinfo: dict | None = None  # Antwort des userinfo-Endpunkts (None = 401)
        self.jwks: list[dict] = []
        self.calls: list[str] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, obj, code=200):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = urllib.parse.urlsplit(self.path).path
                outer.calls.append(path)
                cookie = self.headers.get("Cookie", "")
                value = next((c.split("=", 1)[1] for c in cookie.split("; ") if c.startswith("ory_kratos_session=")), "")
                if path == "/sessions/whoami":
                    res = outer.sessions.get(value or self.headers.get("X-Session-Token", ""), 401)
                    return self._json(res) if isinstance(res, dict) else self._json({"error": {"code": res}}, res)
                if path == "/self-service/logout/browser":
                    if value in outer.sessions:
                        return self._json({"logout_url": "https://auth.example.de/self-service/logout?token=abc"})
                    return self._json({"error": {}}, 401)
                if path == "/.well-known/jwks.json":
                    return self._json({"keys": outer.jwks})
                if path == "/.well-known/openid-configuration":
                    p = outer.public  # wie Hydra: öffentliche URLs, obwohl intern abgefragt
                    return self._json({"issuer": p + "/", "authorization_endpoint": p + "/oauth2/auth",
                                       "token_endpoint": p + "/oauth2/token", "jwks_uri": p + "/.well-known/jwks.json",
                                       "end_session_endpoint": p + "/oauth2/sessions/logout",
                                       "userinfo_endpoint": p + "/userinfo"})
                if path == "/userinfo":
                    if self.headers.get("Authorization") != "Bearer at" or outer.userinfo is None:
                        return self._json({"error": "invalid_token"}, 401)
                    return self._json(outer.userinfo)
                self._json({"error": "not found"}, 404)

            def do_POST(self):
                path = urllib.parse.urlsplit(self.path).path
                body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
                form = {k: v[0] for k, v in urllib.parse.parse_qs(body).items()}
                outer.token_requests.append({"form": form, "auth": self.headers.get("Authorization", "")})
                if path != "/oauth2/token":
                    return self._json({"error": "not found"}, 404)
                cid, secret = outer.client
                raw = f"{urllib.parse.quote(cid, safe='')}:{urllib.parse.quote(secret, safe='')}".encode()
                if self.headers.get("Authorization") != "Basic " + base64.b64encode(raw).decode():
                    return self._json({"error": "invalid_client"}, 401)
                entry = outer.codes.pop(form.get("code", ""), None)
                if entry is None:
                    return self._json({"error": "invalid_grant", "error_description": "code unbekannt"}, 400)
                claims, challenge, redirect_uri = entry
                verifier_hash = base64.urlsafe_b64encode(
                    hashlib.sha256(form.get("code_verifier", "").encode()).digest()).rstrip(b"=").decode()
                if verifier_hash != challenge or form.get("redirect_uri") != redirect_uri:
                    return self._json({"error": "invalid_grant", "error_description": "PKCE/redirect_uri"}, 400)
                return self._json({"access_token": "at", "token_type": "bearer", "id_token": outer.sign(claims)})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def add_rsa_key(self, private_key, kid: str) -> None:
        pub = private_key.public_key().public_numbers()
        self.jwks.append({"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": _b64(pub.n), "e": _b64(pub.e)})

    def sign(self, claims: dict) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
        head, body = enc({"alg": "RS256", "kid": "hydra", "typ": "JWT"}), enc(claims)
        sig = self.signing_key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{head}.{body}." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    def authorize(self, auth_url: str, claims: dict) -> str:
        """Simuliert Login + Consent bei Hydra: gibt die Callback-URL mit Code zurück."""
        q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(auth_url).query).items()}
        code = "code-" + q["state"][:8]
        full = {"iss": self.public + "/", "aud": [q["client_id"]], "nonce": q["nonce"],
                "exp": int(time.time()) + 3600, "iat": int(time.time()), **claims}
        self.codes[code] = (full, q["code_challenge"], q["redirect_uri"])
        return f"{q['redirect_uri']}?code={code}&state={q['state']}&scope=openid"

    def close(self):
        self.server.shutdown()


def whoami(email: str, aal: str = "aal1") -> dict:
    return {"active": True, "authenticator_assurance_level": aal,
            "identity": {"id": "8f1c-" + email.split("@")[0], "traits": {"email": email}}}
