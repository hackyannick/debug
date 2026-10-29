"""Ausgepackte Electron-App mit eigenen npm-Paketen, Bundle-Auswertung, Gruppierung kleiner Dateien."""

import io
import json
import zipfile
from dataclasses import replace

from magicbox.analyzers.asar import first_party
from magicbox.analyzers.jsbundle import extract, interest
from magicbox.engine import Engine
from magicbox.llm.documenter import Documenter, group_small
from magicbox.model import AnalysisResult, Section
from magicbox.report.builder import build_markdown

FILLER = "var a=1;" * 20000  # minifiziert: eine riesige Zeile
MAIN = (FILLER + 'const e=require("electron");e.app.setAsDefaultProtocolClient("qobuzapp");'
        'new e.BrowserWindow({width:1200});new e.Tray("i.png");e.ipcMain.handle("player:play",()=>1);'
        'e.ipcMain.on("download:start",()=>2);localStorage.getItem("volume");process.env.QOBUZ_ENV;'
        'fetch("https://www.qobuz.com/api.json/0.2/track/getFileUrl?id=1");'
        'dispatch({type:"PLAYER/PLAY_TRACK"});alert("Unable to play this track right now");' + FILLER).encode()
UI = (FILLER + 'dispatch({type:"LIBRARY/ADD_ALBUM"});fetch("https://streaming.qobuz.com/file");'
      'show("Your offline library is full");' + FILLER).encode()


def app_zip() -> bytes:
    pkg = {"name": "Qobuz", "version": "8.3.0-b028", "main": "main-win32.js", "author": "Qobuz",
           "dependencies": {"@qobuz/qobuz-dwp-ui": "8.3.0", "castv2": "0.1.9", "sqlite3": "5.1.7"}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app/package.json", json.dumps(pkg))
        zf.writestr("app/main-win32.js", MAIN)
        for i in range(4):
            zf.writestr(f"app/sqlpatches/8.{i}.0.sql", f"BEGIN TRANSACTION;\nALTER TABLE Track ADD c{i} INTEGER;\nCOMMIT;\n")
        zf.writestr("app/node_modules/@qobuz/qobuz-dwp-ui/package.json", json.dumps({"name": "@qobuz/qobuz-dwp-ui", "version": "8.3.0"}))
        zf.writestr("app/node_modules/@qobuz/qobuz-dwp-ui/dist/bundle.js", UI)
        zf.writestr("app/node_modules/@qobuz/qobuz-dwp-ui/dist/assets/fonts/QobuzSans.ttf", b"\0" * 100)
        zf.writestr("app/node_modules/castv2/package.json", json.dumps({"name": "castv2", "version": "0.1.9",
                                                                       "description": "Chromecast CASTV2 protocol"}))
        zf.writestr("app/node_modules/castv2/index.js", "module.exports = {};\n")
    return buf.getvalue()


def test_first_party_packages():
    assert first_party({"name": "Qobuz", "dependencies": {"@qobuz/qobuz-dwp-ui": "1", "castv2": "1"}}) == {"@qobuz/qobuz-dwp-ui"}
    assert first_party({"name": "my-app", "author": {"name": "ACME Corp"},
                        "dependencies": {"acme-player-core": "1", "react": "1"}}) == {"acme-player-core"}


def test_unpacked_electron_app_with_own_packages(settings):
    r = Engine(replace(settings, profile="allgemein")).analyze_bytes("qobuz-app.zip", app_zip())
    assert r.description == "Electron-App (Programmordner)"  # require("electron") mitten im Bundle
    names = [c.name for c in r.children]
    assert names[:2] == ["app/package.json", "app/main-win32.js"]
    assert "app/node_modules/@qobuz/qobuz-dwp-ui/dist/bundle.js" in names  # eigenes Paket = App-Code
    assert not any("castv2/index.js" in n or n.endswith(".ttf") for n in names)
    listing = next(s for s in r.sections if s.title.startswith("Inhalt"))
    assert "castv2" not in str(listing.table.rows) and "fremder npm-Pakete" in listing.text
    npm = next(s for s in r.sections if s.title.startswith("Verwendete npm-Pakete"))
    assert [row[0] for row in npm.table.rows] == ["castv2"]

    main = next(c for c in r.children if c.name == "app/main-win32.js")
    titles = [s.title for s in main.sections]
    assert "Verwendete Techniken" in titles and "Auffällige Muster" not in titles  # Software-Profil
    assert "Quelltext (zur Lesbarkeit umbrochen)" in titles
    landkarte = next(s for s in main.sections if s.title.startswith("Bundle-Auswertung")).text
    for expected in ("player:play", "download:start", "qobuzapp", "volume", "QOBUZ_ENV",
                     "PLAYER/PLAY_TRACK", "Unable to play this track right now"):
        assert expected in landkarte, expected
    hosts = next(s for s in main.sections if s.title.startswith("Angesprochene Server"))
    assert hosts.table.rows[0][0] == "www.qobuz.com"

    md = build_markdown(r)
    assert max(len(line) for line in md.splitlines()) < 2000  # Riesenzeilen im Bericht gekürzt


def test_extract_and_interest():
    facts = extract(MAIN.decode())
    assert "Fenster (BrowserWindow)" in facts["apis"] and "Infobereich-Symbol (Tray)" in facts["apis"]
    assert facts["ipc"] == {"player:play": "handle", "download:start": "on"}
    assert interest('ipcMain.handle("x",f);fetch("https://a.example.org/b")') > interest("var a=1;" * 50)


def test_small_files_grouped_and_bundles_chunked(fake_llm, settings):
    r = Engine(replace(settings, profile="allgemein")).analyze_bytes("qobuz-app.zip", app_zip())
    groups = group_small(r.children)
    sql = [item for item, members in groups if members]
    assert len(sql) == 1 and sql[0].name == "app/sqlpatches/*.sql (4 Dateien)"
    s = replace(settings, use_llm=True, base_url=fake_llm.url, profile="allgemein", context_tokens=4096,
                max_code_chunks=4, max_llm_children=6)
    Documenter(s).document(r)
    prompts = [req["messages"][1]["content"] for req in fake_llm.requests]
    chunk_prompts = [p for p in prompts if "Hier ist Teil" in p]
    assert 0 < len(chunk_prompts) <= 4
    assert any("ipcMain" in p for p in chunk_prompts)  # der aufschlussreiche Teil wurde gewählt
    assert sum("sqlpatches/*.sql" in p for p in prompts) >= 1
    first_sql = next(c for c in r.children if c.name.endswith("8.0.0.sql"))
    assert first_sql.llm_doc.startswith("*Gemeinsame Einschätzung für 4 Dateien")


def test_report_lists_named_functions_only():
    from magicbox.analyzers.radare2 import UNNAMED
    assert "fcn.180038b90".startswith(UNNAMED) and not "method.juce::AudioSourcePlayer.virtual_8".startswith(UNNAMED)


def test_app_wide_map_reaches_the_overall_doc(fake_llm, settings):
    r = Engine(replace(settings, profile="allgemein")).analyze_bytes("qobuz-app.zip", app_zip())
    overall = next(s for s in r.sections if s.title == "Funktionslandkarte der gesamten App")
    assert "player:play" in overall.text and "LIBRARY/ADD_ALBUM" in overall.text  # aus beiden Bundles
    hosts = next(s for s in r.sections if s.title.startswith("Angesprochene Server") and "gesamte App" in s.title)
    assert [row[1] for row in hosts.table.rows[:2]] == ["eigener Dienst", "eigener Dienst"]  # qobuz.com zuerst
    s = replace(settings, use_llm=True, base_url=fake_llm.url, profile="allgemein", max_code_chunks=0,
                max_llm_children=1)
    Documenter(s).document(r)
    final = fake_llm.requests[-1]["messages"][1]["content"]
    assert "Funktionslandkarte der gesamten App" in final and "player:play" in final


def test_map_filters_library_noise():
    text = ('fetch("https://momentjs.com/guides/#/warnings/");open("https://www.facebook.com/sharer.php");'
            'fetch("https://www.qobuz.com/api.json/0.2/track/get");x="node:process";y="xlink:href";'
            'z="PLAYER/PLAY_TRACK";a="Sentry SDK should be initialized before the Electron app is ready";'
            'b="Your offline library is full";c="Tem certeza de que deseja sair?";d="YYYY/MM/DD"') * 30
    facts = extract(text, {"qobuz"})
    assert set(facts["hosts"]) == {"www.qobuz.com", "www.facebook.com"}
    assert facts["hosts"]["www.qobuz.com"]["kind"] == "eigener Dienst"
    assert facts["actions"] == ["PLAYER/PLAY_TRACK"]
    assert facts["texts"][0] == "Your offline library is full" and not any("Tem certeza" in t for t in facts["texts"])


def test_channel_grouping_and_sql_detection():
    from magicbox.analyzers.identify import detect
    from magicbox.analyzers.jsbundle import group_channels
    lines = group_channels(["player-play-music", "player-pause-music", "chromecast-scan", "notify-error"])
    assert lines == ["player (2): pause-music, play-music", "weitere (2): chromecast-scan, notify-error"]
    assert detect(b"BEGIN TRANSACTION;\nCREATE TABLE x (id INT);\nCOMMIT;\n", "qobuz.sqlite") == \
        ("source", "Quelltext/Skript (sql)")
