"""Führt scripts/easy-setup.sh (Rolle gateway) gegen nachgebaute Hydra-/Kratos-Admin-APIs aus.

nginx, certbot und systemctl werden durch Attrappen ersetzt – geprüft wird der echte Bash-Ablauf
(set -euo pipefail-Fallen, Wiederholbarkeit, API-Aufrufe, erzeugte Dateien).
"""

import json
import os
import shutil
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "easy-setup.sh"
pytestmark = pytest.mark.skipif(sys.platform != "linux" or shutil.which("bash") is None
                                or shutil.which("curl") is None or shutil.which("openssl") is None,
                                reason="braucht Linux mit bash, curl, openssl")


class FakeOryAdmin:
    def __init__(self):
        self.clients: dict[str, dict] = {}
        self.identities = {"i1": {"id": "i1", "traits": {"email": "yannick@hackdv.com"}},
                           "i2": {"id": "i2", "traits": {"email": "chef@hackdv.com", "groups": ["it"]}}}
        self.calls: list[str] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def j(self, obj, code=200):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def body(self):
                return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"null")

            def do_GET(self):
                u = urllib.parse.urlsplit(self.path)
                q = dict(urllib.parse.parse_qsl(u.query))
                outer.calls.append(f"GET {u.path}")
                if u.path == "/.well-known/openid-configuration":
                    return self.j({"issuer": "https://id.hackdv.com/"})
                if u.path == "/admin/clients":
                    return self.j(list(outer.clients.values()))
                if u.path.startswith("/admin/clients/"):
                    c = outer.clients.get(u.path.rsplit("/", 1)[1])
                    return self.j(c) if c else self.j({"error": "not found"}, 404)
                if u.path == "/admin/identities":
                    email = q.get("credentials_identifier")
                    return self.j([i for i in outer.identities.values() if i["traits"]["email"] == email])
                self.j({}, 404)

            def do_POST(self):
                b = self.body()
                outer.calls.append(f"POST {self.path}")
                assert len(b["client_secret"]) == 64  # Hex, keine Sonderzeichen
                outer.clients[b["client_id"]] = {k: v for k, v in b.items() if k != "client_secret"}
                self.j(outer.clients[b["client_id"]], 201)

            def do_PATCH(self):
                ops = self.body()
                outer.calls.append(f"PATCH {self.path}")
                kind, oid = self.path.split("/")[2], self.path.rsplit("/", 1)[1]
                obj = (outer.clients if kind == "clients" else outer.identities)[oid]
                for op in ops:
                    parts = op["path"].strip("/").split("/")
                    target = obj
                    for p in parts[:-1]:
                        target = target[p]
                    if parts[-1] == "-":
                        target.append(op["value"])
                    else:
                        target[parts[-1]] = op["value"]
                self.j(obj)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


@pytest.fixture
def env(tmp_path):
    ory = FakeOryAdmin()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for cmd in ("nginx", "systemctl", "apt-get"):
        stub = bin_dir / cmd
        stub.write_text(f'#!/bin/sh\necho "{cmd} $*" >> {tmp_path}/stubs.log\nexit 0\n')
        stub.chmod(0o755)
    # certbot-Attrappe: "plugins" listet $CERTBOT_PLUGINS, "certonly -d X" legt ein Zertifikat an
    certbot = bin_dir / "certbot"
    certbot.write_text(f"""#!/bin/sh
echo "certbot $*" >> {tmp_path}/stubs.log
if [ "$1" = plugins ]; then echo "$CERTBOT_PLUGINS"; exit 0; fi
prev=""
for a in "$@"; do
  if [ "$prev" = "-d" ]; then mkdir -p "$LE_LIVE/$a"; touch "$LE_LIVE/$a/fullchain.pem"; fi
  prev="$a"
done
exit 0
""")
    certbot.chmod(0o755)
    for d in ("avail", "enabled", "le/live/magicbox.hackdv.com", "le/renewal"):
        (tmp_path / d).mkdir(parents=True)
    (tmp_path / "le/live/magicbox.hackdv.com/fullchain.pem").write_text("x")
    (tmp_path / "setup.env").write_text(
        f'R640_IP="10.0.201.50"\nGATEWAY_IP="10.0.201.10"\nHYDRA_ADMIN="{ory.url}"\n'
        f'HYDRA_PUBLIC="{ory.url}"\nKRATOS_ADMIN="{ory.url}"\n')
    environ = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "SKIP_ROOT_CHECK": "1",
               "NGINX_AVAILABLE": str(tmp_path / "avail"), "NGINX_ENABLED": str(tmp_path / "enabled"),
               "LE_DIR": str(tmp_path / "le"), "LE_LIVE": str(tmp_path / "le/live"), "NO_PROXY": "127.0.0.1",
               "CERTBOT_PLUGINS": "* nginx\n* webroot"}
    environ.pop("SSH_CLIENT", None)
    yield ory, tmp_path, environ
    ory.server.shutdown()


def run_gateway(tmp_path, environ, answers=None, *extra):
    args = ["bash", str(SCRIPT), "gateway", "--env", str(tmp_path / "setup.env"), *extra]
    return subprocess.run(args, input=answers or "", capture_output=True, text=True, env=environ, timeout=60,
                          start_new_session=True)  # ohne Terminal: Antworten kommen von stdin


def test_gateway_setup_and_rerun(env):
    ory, tmp, environ = env
    # Enter für alle Vorschläge, post_logout ja, Gruppen für zwei Adressen + eine unbekannte, owa-gate (nicht vorhanden)
    answers = "\n" * 8 + "j\n" + "yannick@hackdv.com, chef@hackdv.com, wer@x.de\n"
    res = run_gateway(tmp, environ, answers)
    assert res.returncode == 0, res.stdout + res.stderr

    client = ory.clients["magicbox"]
    assert client["redirect_uris"] == ["https://magicbox.hackdv.com/auth/callback"]
    assert client["post_logout_redirect_uris"] == ["https://magicbox.hackdv.com/"]
    assert ory.identities["i1"]["traits"]["groups"] == ["magicbox"]
    assert ory.identities["i2"]["traits"]["groups"] == ["it", "magicbox"]
    assert "wer@x.de: keine Identität gefunden" in res.stdout

    site = (tmp / "avail" / "magicbox.conf").read_text()
    assert "proxy_pass http://10.0.201.50:8765;" in site and "proxy_buffering off;" in site
    assert (tmp / "enabled" / "magicbox.conf").is_symlink()
    stubs = (tmp / "stubs.log").read_text()
    assert "nginx -t" in stubs and "systemctl reload nginx" in stubs

    saved = (tmp / "setup.env").read_text()
    assert 'ISSUER="https://id.hackdv.com/"' in saved and 'SCOPES="openid email profile groups"' in saved
    assert oct((tmp / "setup.env").stat().st_mode)[-3:] == "600"
    secret = next(l for l in saved.splitlines() if l.startswith("CLIENT_SECRET="))

    # Zweiter Lauf mit --yes: nichts doppelt, Geheimnis bleibt, nginx unverändert
    calls_before = len([c for c in ory.calls if c.startswith(("POST", "PATCH"))])
    res = run_gateway(tmp, environ, "", "--yes")
    assert res.returncode == 0, res.stdout + res.stderr
    assert len([c for c in ory.calls if c.startswith(("POST", "PATCH"))]) == calls_before
    assert "nginx-Site unverändert" in res.stdout
    assert secret in (tmp / "setup.env").read_text()


def test_gateway_dry_run_changes_nothing(env):
    ory, tmp, environ = env
    res = run_gateway(tmp, environ, "", "--yes", "--dry-run")
    assert res.returncode == 0, res.stdout + res.stderr
    assert not ory.clients and not (tmp / "avail" / "magicbox.conf").exists()
    assert "[dry-run]" in res.stdout


def test_gateway_webroot_certificate_like_id_host(env):
    """Kein Zertifikat, certbot ohne nginx-Plugin, id.hackdv.com per Webroot → gleiches Verfahren nutzen."""
    ory, tmp, environ = env
    (tmp / "le/live/magicbox.hackdv.com/fullchain.pem").unlink()
    (tmp / "le/renewal/id.hackdv.com.conf").write_text(
        "[renewalparams]\nauthenticator = webroot\nwebroot_path = /var/www/acme,\n")
    environ["CERTBOT_PLUGINS"] = "* standalone\n* webroot"
    res = run_gateway(tmp, environ, "", "--yes")
    assert res.returncode == 0, res.stdout + res.stderr
    stubs = (tmp / "stubs.log").read_text()
    assert "certbot certonly --webroot -w /var/www/acme -d magicbox.hackdv.com" in stubs
    assert stubs.count("systemctl reload nginx") == 2  # erst Port 80 für Let's Encrypt, dann komplett
    site = (tmp / "avail/magicbox.conf").read_text()
    assert "location ^~ /.well-known/acme-challenge/ { root /var/www/acme; }" in site
    assert "listen 443 ssl;" in site and "return 301 https://$host$request_uri;" in site
    assert "Gateway fertig." in res.stdout


def test_gateway_without_certificate_keeps_secret_and_kratos_fallback(env):
    """Wie im echten Lauf: Kratos-URL falsch, kein nginx-Plugin, Installation abgelehnt."""
    ory, tmp, environ = env
    (tmp / "le/live/magicbox.hackdv.com/fullchain.pem").unlink()
    environ["CERTBOT_PLUGINS"] = "* standalone"
    env_file = (tmp / "setup.env")
    env_file.write_text(env_file.read_text().replace(f'KRATOS_ADMIN="{ory.url}"', 'KRATOS_ADMIN="http://127.0.0.1:9"'))
    # 8× Vorschläge, dann Ausweich-URL für Kratos, post_logout ja, nginx-Plugin NEIN, eine E-Mail
    answers = "\n" * 8 + f"{ory.url}\n" + "j\n" + "n\n" + "yannick@hackdv.com\n"
    res = run_gateway(tmp, environ, answers)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "keine Verbindung" in res.stdout and f"Kratos Admin API erreichbar ({ory.url})" in res.stdout
    assert ory.identities["i1"]["traits"]["groups"] == ["magicbox"]  # Gruppe trotz fehlendem Zertifikat gesetzt
    assert not (tmp / "avail/magicbox.conf").exists()
    assert "fehlt noch das Zertifikat" in res.stdout
    saved = env_file.read_text()
    assert "CLIENT_SECRET=" in saved and f'KRATOS_ADMIN="{ory.url}"' in saved
