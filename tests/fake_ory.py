"""Nachgebaute Ory-Endpunkte für Tests: Kratos (/sessions/whoami, Logout) und Oathkeeper-JWKS."""

from __future__ import annotations

import base64
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _b64(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class FakeOry:
    """``sessions``: Cookie-Wert -> whoami-Antwort (oder HTTP-Status als int)."""

    def __init__(self):
        self.sessions: dict[str, dict | int] = {}
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
                self._json({"error": "not found"}, 404)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def add_rsa_key(self, private_key, kid: str) -> None:
        pub = private_key.public_key().public_numbers()
        self.jwks.append({"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256", "n": _b64(pub.n), "e": _b64(pub.e)})

    def close(self):
        self.server.shutdown()


def whoami(email: str, aal: str = "aal1") -> dict:
    return {"active": True, "authenticator_assurance_level": aal,
            "identity": {"id": "8f1c-" + email.split("@")[0], "traits": {"email": email}}}
