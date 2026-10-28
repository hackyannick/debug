import http.client
import json
import time

import pytest

from magicbox.config import Settings
from magicbox.server import MagicBoxServer
from samples import tiny_pe64


@pytest.fixture
def server(tmp_path, fake_llm):
    s = Settings(base_url=fake_llm.url, data_dir=str(tmp_path / "data"), use_radare2=False, use_capa=False)
    srv = MagicBoxServer(s, host="127.0.0.1", port=0, config_path=tmp_path / "settings.json")
    srv.start_background()
    yield srv
    srv.shutdown()


def request(srv, method, path, body=None, headers=None):
    host, port = srv.httpd.server_address[:2]
    conn = http.client.HTTPConnection(host, port, timeout=10)
    h = {"X-MagicBox": "1", **(headers or {})}
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    conn.request(method, path, body=body, headers=h)
    res = conn.getresponse()
    data = res.read()
    ctype = res.getheader("Content-Type", "")
    conn.close()
    return res.status, (json.loads(data) if "json" in ctype else data), res


def wait_done(srv, job_id, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        _, job, _ = request(srv, "GET", f"/api/jobs/{job_id}")
        if job["status"] not in ("queued", "running"):
            return job
        time.sleep(0.1)
    raise AssertionError("Auftrag nicht fertig geworden")


def test_upload_analyze_and_report(server):
    status, job, _ = request(server, "POST", "/api/jobs?name=evil.exe&profile=malware", body=tiny_pe64())
    assert status == 201 and job["status"] == "queued" and "password" not in job
    job = wait_done(server, job["id"])
    assert job["status"] == "done", job
    assert job["risk"] in ("hoch", "mittel", "gering")
    assert job["llm_verdict"] == "unbedenklich"  # aus der Fake-KI-Antwort
    assert "Kurzfassung" in job["ai"] and job["log"]

    status, html, res = request(server, "GET", f"/api/jobs/{job['id']}/report")
    assert status == 200 and b"Analysebericht: evil.exe" in html
    assert "default-src 'none'" in res.getheader("Content-Security-Policy")
    status, csv_data, res = request(server, "GET", f"/api/jobs/{job['id']}/iocs.csv")
    assert status == 200 and csv_data.startswith(b"typ,wert,datei") and "attachment" in res.getheader("Content-Disposition")

    sample = server.manager.job_dir(job["id"]) / "sample" / "evil.exe"
    assert sample.exists() and not sample.stat().st_mode & 0o111  # nie ausführbar

    status, jobs, _ = request(server, "GET", "/api/jobs")
    assert [j["id"] for j in jobs] == [job["id"]]
    status, _, _ = request(server, "DELETE", f"/api/jobs/{job['id']}")
    assert status == 200 and not sample.exists()


def test_rerun_and_events(server):
    status, job, _ = request(server, "POST", "/api/jobs?name=a.py", body=b"print('hi')\n")
    wait_done(server, job["id"])
    host, port = server.httpd.server_address[:2]
    conn = http.client.HTTPConnection(host, port, timeout=10)
    conn.request("GET", "/api/events")
    res = conn.getresponse()
    assert res.getheader("Content-Type") == "text/event-stream"
    request(server, "POST", f"/api/jobs/{job['id']}/rerun")
    seen = set()
    deadline = time.time() + 15
    while time.time() < deadline and "done" not in seen:
        line = res.fp.readline().decode()
        if line.startswith("data: "):
            ev = json.loads(line[6:])
            if ev["type"] == "job":
                seen.add(ev["job"]["status"])
            seen.add(ev["type"])
    conn.close()
    assert {"running", "done", "log", "token"} <= seen


def test_security(server):
    # Ohne X-MagicBox-Header (z. B. Cross-Site-Formular) keine Aktionen
    status, data, _ = request(server, "POST", "/api/jobs?name=x", body=b"x", headers={"X-MagicBox": ""})
    assert status == 403
    # DNS-Rebinding: fremder Hostname wird ohne Token abgewiesen
    status, _, _ = request(server, "GET", "/api/jobs", headers={"Host": "attacker.example"})
    assert status == 403
    # Path Traversal bei statischen Dateien und Job-IDs
    assert request(server, "GET", "/static/../../config.py")[0] == 404
    assert request(server, "GET", "/api/jobs/../../etc")[0] == 404
    # Netzwerk-/Zugangseinstellungen sind über die API nicht änderbar
    request(server, "PUT", "/api/settings", body={"web_token": "x", "host": "0.0.0.0", "model": "neu:1b"})
    assert server.settings.web_token == "" and server.settings.host == "127.0.0.1" and server.settings.model == "neu:1b"


def test_token_auth(tmp_path, fake_llm):
    s = Settings(base_url=fake_llm.url, data_dir=str(tmp_path / "d"), web_token="geheim")
    srv = MagicBoxServer(s, host="127.0.0.1", port=0)
    srv.start_background()
    try:
        assert request(srv, "GET", "/api/jobs")[0] == 401
        assert request(srv, "GET", "/")[0] == 200  # Oberfläche selbst lädt (zeigt Login)
        assert request(srv, "POST", "/api/login", body={"token": "falsch"})[0] == 401
        status, _, res = request(srv, "POST", "/api/login", body={"token": "geheim"})
        cookie = res.getheader("Set-Cookie").split(";")[0]
        assert status == 200 and "HttpOnly" in res.getheader("Set-Cookie")
        assert request(srv, "GET", "/api/jobs", headers={"Cookie": cookie})[0] == 200
        assert request(srv, "GET", "/api/jobs", headers={"Authorization": "Bearer geheim"})[0] == 200
        status, _, res = request(srv, "GET", "/?token=geheim")
        assert status == 303 and res.getheader("Location") == "/"
    finally:
        srv.shutdown()


def test_restart_recovers_jobs(tmp_path, fake_llm):
    s = Settings(base_url=fake_llm.url, data_dir=str(tmp_path / "d"), use_radare2=False)
    srv = MagicBoxServer(s, host="127.0.0.1", port=0)
    srv.start_background()
    _, job, _ = request(srv, "POST", "/api/jobs?name=a.txt", body=b"hallo")
    wait_done(srv, job["id"])
    srv.shutdown()
    srv2 = MagicBoxServer(s, host="127.0.0.1", port=0)
    try:
        assert srv2.manager.get(job["id"]).status == "done"
    finally:
        srv2.shutdown()


def test_watch_folder(tmp_path, fake_llm):
    from magicbox.server.jobs import FolderWatcher, JobManager

    s = Settings(base_url=fake_llm.url, data_dir=str(tmp_path / "d"), use_llm=False)
    m = JobManager(s)
    inbox = tmp_path / "inbox"
    w = FolderWatcher(m, inbox)
    (inbox / "probe.ps1").write_text("Write-Host hi")
    w.scan()  # erster Blick: Datei merken
    assert not m.jobs
    w.scan()  # unverändert -> übernehmen
    assert [j.name for j in m.jobs.values()] == ["probe.ps1"]
    assert not (inbox / "probe.ps1").exists()
    m.stop()
