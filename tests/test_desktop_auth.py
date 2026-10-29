"""Anmeldung der nativen Desktop-App: System-Browser (Ory/OIDC) → Bestätigung → Loopback → API-Token."""

import base64
import hashlib
import re
import secrets
import urllib.parse

from test_auth import _cookie, _oidc_server, crypto, hydra, ory, start  # noqa: F401 – Fixtures
from test_server import request


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def form(srv, fields, cookie):
    body = urllib.parse.urlencode(fields).encode()
    return request(srv, "POST", "/auth/desktop", body=body,
                   headers={"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"})


def test_desktop_login_via_browser(tmp_path, fake_llm, hydra):
    srv = _oidc_server(tmp_path, fake_llm, hydra, auth_allowed=["yannick@hackdv.com"])
    try:
        assert request(srv, "GET", "/auth/info")[1]["login"] == "browser"
        verifier, challenge = pkce()
        start_path = f"/auth/desktop?port=51234&state=st4te-abc&challenge={challenge}"

        # 1. Ohne Browser-Sitzung → Login mit Rücksprung auf genau diese Seite
        status, _, res = request(srv, "GET", start_path)
        assert status == 303 and res.getheader("Location") == "/auth/login?" + urllib.parse.urlencode({"next": start_path})

        # 2. Login bei Hydra, Callback führt zurück zur Desktop-Seite
        status, _, res = request(srv, "GET", res.getheader("Location"))
        state_cookie = _cookie(res, "mb_oidc_state")
        cb = hydra.authorize(res.getheader("Location"), {"sub": "u-1", "email": "yannick@hackdv.com"})
        status, _, res = request(srv, "GET", cb.split(".com", 1)[1], headers={"Cookie": state_cookie})
        session = _cookie(res, "mb_session")
        assert res.getheader("Location") == start_path

        # 3. Bestätigungsseite mit CSRF-Token
        status, page, res = request(srv, "GET", start_path, headers={"Cookie": session})
        page = page.decode()
        assert status == 200 and "yannick@hackdv.com" in page and "Zulassen" in page
        assert "http://127.0.0.1:*" in res.getheader("Content-Security-Policy")
        csrf = re.search(r"name='csrf' value='([0-9a-f]+)'", page).group(1)
        fields = {"port": "51234", "state": "st4te-abc", "challenge": challenge, "csrf": csrf, "decision": "allow"}
        assert form(srv, {**fields, "csrf": "0" * 64}, session)[0] == 403
        assert form(srv, fields, "")[0] == 401  # ohne Browser-Sitzung keine Freigabe

        status, _, res = form(srv, fields, session)
        target = urllib.parse.urlsplit(res.getheader("Location"))
        assert status == 303 and target.netloc == "127.0.0.1:51234" and target.path == "/callback"
        q = dict(urllib.parse.parse_qsl(target.query))
        assert q["state"] == "st4te-abc"

        # 4. Code + verifier → API-Token; falscher verifier/zweiter Versuch scheitern
        status, err, _ = request(srv, "POST", "/auth/desktop/token", body={"code": q["code"], "verifier": "falsch" * 8})
        assert status == 400
        status, _, res = form(srv, fields, session)  # neuer Code (der alte ist verbraucht)
        code = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(res.getheader("Location")).query))["code"]
        status, tok, _ = request(srv, "POST", "/auth/desktop/token", body={"code": code, "verifier": verifier})
        assert status == 200 and tok["token"].startswith("mbd_") and tok["name"] == "yannick@hackdv.com"
        assert request(srv, "POST", "/auth/desktop/token", body={"code": code, "verifier": verifier})[0] == 400
        bearer = {"Authorization": f"Bearer {tok['token']}"}

        # 5. API mit Token (auch SSE-fähig), Aufträge tragen den Namen
        status, st, _ = request(srv, "GET", "/api/status", headers=bearer)
        assert status == 200 and st["user"] == {"name": "yannick@hackdv.com", "method": "desktop"}
        status, job, _ = request(srv, "POST", "/api/jobs?name=a.txt", body=b"x", headers=bearer)
        assert status == 201 and job["created_by"] == "yannick@hackdv.com"
        assert tok["token"] not in (tmp_path / "d" / "desktop_sessions.json").read_text()

        # 6. App-Token darf keine weiteren Tokens freigeben; Abmelden widerruft es
        assert request(srv, "GET", start_path, headers=bearer)[0] == 403
        assert request(srv, "POST", "/api/logout", headers=bearer)[1]["revoked"] is True
        status, data, _ = request(srv, "GET", "/api/status", headers=bearer)
        assert status == 401 and "Desktop-App" in data["error"]

        # 7. Ablehnen führt mit error zurück zur App
        status, _, res = form(srv, {**fields, "decision": "deny"}, session)
        assert "error=access_denied" in res.getheader("Location")
    finally:
        srv.shutdown()


def test_desktop_rejects_bad_requests(tmp_path, fake_llm):
    srv = start(tmp_path, fake_llm, web_token="geheim")
    try:
        assert request(srv, "GET", "/auth/info")[1]["login"] == "token"
        _, challenge = pkce()
        assert request(srv, "GET", f"/auth/desktop?port=80&state=abcdefgh&challenge={challenge}")[0] == 400
        assert request(srv, "GET", "/auth/desktop?port=5000&state=x&challenge=y")[0] == 400
        # Zugangsschlüssel-Modus: Schlüssel direkt als Bearer
        assert request(srv, "GET", "/api/status", headers={"Authorization": "Bearer geheim"})[0] == 200
        assert request(srv, "GET", "/api/status", headers={"Authorization": "Bearer mbd_erfunden"})[0] == 401
    finally:
        srv.shutdown()


def test_classic_report(tmp_path, fake_llm):
    from test_server import wait_done
    from samples import tiny_pe64
    srv = start(tmp_path, fake_llm)
    try:
        _, job, _ = request(srv, "POST", "/api/jobs?name=evil.exe", body=tiny_pe64())
        wait_done(srv, job["id"])
        status, page, _ = request(srv, "GET", f"/api/jobs/{job['id']}/report.classic")
        assert status == 200 and b"IE=edge" in page and b"Tahoma" in page and b"var(--" not in page
    finally:
        srv.shutdown()
