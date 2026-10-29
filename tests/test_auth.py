import base64
import json
import time

import pytest

from magicbox.config import Settings
from magicbox.server import MagicBoxServer
from magicbox.server.auth import rsa_verify
from fake_ory import FakeOry, whoami
from test_server import request

crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding  # noqa: E402


@pytest.fixture
def ory():
    o = FakeOry()
    yield o
    o.close()


def start(tmp_path, fake_llm, **kw):
    s = Settings(base_url=fake_llm.url, data_dir=str(tmp_path / "d"), use_radare2=False, use_capa=False, **kw)
    srv = MagicBoxServer(s, host="127.0.0.1", port=0)
    srv.start_background()
    return srv


# ---------------------------------------------------------------------------- Kratos

def test_kratos_login_flow(tmp_path, fake_llm, ory):
    ory.sessions["gut"] = whoami("analyst@firma.de")
    srv = start(tmp_path, fake_llm, auth_mode="kratos", kratos_public_url=ory.url,
                kratos_browser_url="https://auth.firma.de", public_url="https://magicbox.firma.de")
    try:
        # Ohne Sitzung: Oberfläche leitet zum Kratos-Login (Captcha/2FA macht Kratos bzw. dessen UI)
        status, _, res = request(srv, "GET", "/")
        assert status == 303
        assert res.getheader("Location") == ("https://auth.firma.de/self-service/login/browser?"
                                             "return_to=https%3A%2F%2Fmagicbox.firma.de%2F")
        status, data, _ = request(srv, "GET", "/api/jobs")
        assert status == 401 and data["login_url"].startswith("https://auth.firma.de/self-service/login/browser")

        cookie = {"Cookie": "mb_x=1; ory_kratos_session=gut"}
        assert request(srv, "GET", "/", headers=cookie)[0] == 200
        status, st, _ = request(srv, "GET", "/api/status", headers=cookie)
        assert st["user"] == {"name": "analyst@firma.de", "method": "kratos"} and st["auth_mode"] == "kratos"

        status, job, _ = request(srv, "POST", "/api/jobs?name=x.txt", body=b"hallo", headers=cookie)
        assert status == 201 and job["created_by"] == "analyst@firma.de"

        # Kratos wurde nur mit Ory-Cookies gefragt und das Ergebnis kurz gecacht
        assert ory.calls.count("/sessions/whoami") == 1

        status, _, res = request(srv, "GET", "/auth/logout", headers=cookie)
        assert status == 303 and res.getheader("Location").startswith("https://auth.example.de/self-service/logout")

        assert request(srv, "GET", "/api/jobs", headers={"Cookie": "ory_kratos_session=falsch"})[0] == 401
        # fremder Hostname ist hier kein Problem – die Anmeldung schützt
        assert request(srv, "GET", "/api/jobs", headers={**cookie, "Host": "magicbox.firma.de"})[0] == 200
    finally:
        srv.shutdown()


def test_kratos_allowlist_aal2_and_token(tmp_path, fake_llm, ory):
    ory.sessions["fremd"] = whoami("gast@andere.de")
    ory.sessions["chef"] = whoami("chef@firma.de", aal="aal1")
    ory.sessions["chef2fa"] = whoami("chef@firma.de", aal="aal2")
    srv = start(tmp_path, fake_llm, auth_mode="kratos", kratos_public_url=ory.url, auth_allowed=["@firma.de"],
                auth_require_aal2=True, web_token="skript-token")
    try:
        assert request(srv, "GET", "/api/jobs", headers={"Cookie": "ory_kratos_session=fremd"})[0] in (401, 403)
        status, data, _ = request(srv, "GET", "/api/jobs", headers={"Cookie": "ory_kratos_session=chef"})
        assert status == 401 and "aal=aal2" in data["login_url"]
        assert request(srv, "GET", "/api/jobs", headers={"Cookie": "ory_kratos_session=chef2fa"})[0] == 200
        # Skripte/CLI: Zugangsschlüssel funktioniert zusätzlich
        assert request(srv, "GET", "/api/jobs", headers={"Authorization": "Bearer skript-token"})[0] == 200
    finally:
        srv.shutdown()


def test_kratos_forbidden_identity(tmp_path, fake_llm, ory):
    ory.sessions["fremd"] = whoami("gast@andere.de", aal="aal2")
    srv = start(tmp_path, fake_llm, auth_mode="kratos", kratos_public_url=ory.url, auth_allowed=["chef@firma.de"])
    try:
        status, data, _ = request(srv, "GET", "/api/jobs", headers={"Cookie": "ory_kratos_session=fremd"})
        assert status == 403 and "gast@andere.de" in data["error"]
        assert request(srv, "GET", "/", headers={"Cookie": "ory_kratos_session=fremd"})[0] == 403
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------- Oathkeeper

def _jwt(key, claims: dict, kid="k1", alg="RS256") -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    head = enc({"alg": alg, "kid": kid, "typ": "JWT"})
    body = enc(claims)
    h = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512()}[alg]
    sig = key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), h)
    return f"{head}.{body}." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()


def test_oathkeeper_id_token(tmp_path, fake_llm, ory):
    key = crypto.generate_private_key(public_exponent=65537, key_size=2048)
    other = crypto.generate_private_key(public_exponent=65537, key_size=2048)
    ory.add_rsa_key(key, "k1")
    srv = start(tmp_path, fake_llm, auth_mode="oathkeeper", oathkeeper_jwks_url=ory.url + "/.well-known/jwks.json",
                oathkeeper_issuer="https://auth.firma.de/", oathkeeper_audience="magicbox",
                public_url="https://magicbox.firma.de")
    now = int(time.time())
    good = {"sub": "u1", "email": "analyst@firma.de", "iss": "https://auth.firma.de/", "aud": ["magicbox"],
            "exp": now + 300, "iat": now}
    try:
        def call(token):
            return request(srv, "GET", "/api/status", headers={"Authorization": f"Bearer {token}"})

        status, st, _ = call(_jwt(key, good))
        assert status == 200 and st["user"] == {"name": "analyst@firma.de", "method": "oathkeeper"}
        assert call(_jwt(key, good, alg="RS512"))[0] == 200
        assert call(_jwt(other, good))[0] == 401                              # falsche Signatur
        assert call(_jwt(key, {**good, "exp": now - 3600}))[0] == 401         # abgelaufen
        assert call(_jwt(key, {**good, "aud": ["anderer"]}))[0] == 401        # falsche Zielgruppe
        assert call(_jwt(key, {**good, "iss": "https://evil/"}))[0] == 401    # falscher Aussteller
        none_alg = _jwt(key, good).split(".")
        none_alg[0] = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
        assert call(".".join(none_alg))[0] == 401                            # alg=none abgelehnt
        status, data, _ = request(srv, "GET", "/api/status")                  # ohne Token (an Oathkeeper vorbei)
        assert status == 401 and data["login_url"] == "https://magicbox.firma.de"

        # Schlüsselrotation: neues kid wird nachgeladen
        ory.add_rsa_key(other, "k2")
        srv.auth._jwks_time -= 20
        assert call(_jwt(other, good, kid="k2"))[0] == 200
    finally:
        srv.shutdown()


@pytest.mark.parametrize("alg,h", [("RS256", "SHA256"), ("RS384", "SHA384"), ("RS512", "SHA512")])
def test_rsa_verify_matches_cryptography(alg, h):
    key = crypto.generate_private_key(public_exponent=65537, key_size=2048)
    msg = b"magic box"
    sig = key.sign(msg, padding.PKCS1v15(), getattr(hashes, h)())
    pub = key.public_key().public_numbers()
    assert rsa_verify(alg, pub.n, pub.e, msg, sig)
    assert not rsa_verify(alg, pub.n, pub.e, msg + b"!", sig)
    assert not rsa_verify("HS256", pub.n, pub.e, msg, sig)
