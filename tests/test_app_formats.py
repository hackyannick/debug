"""Electron/ASAR, Installer, Laufzeit-Erkennung, Bibliotheksfilter, saubere Strings und Gegenprüfung der KI."""

import io
import json
import struct
import zipfile
from dataclasses import replace

from magicbox.analyzers.apis import categorize
from magicbox.analyzers.libs import library_of
from magicbox.analyzers.radare2 import _real_size
from magicbox.analyzers.strings import _is_noise, classify
from magicbox.engine import Engine
from magicbox.llm.documenter import facts_text, verification_note
from magicbox.model import AnalysisResult, Section, Table
from magicbox.report.builder import rule_based_summary
from samples import tiny_pe64


def make_asar(files: dict[str, bytes]) -> bytes:
    """Baut ein ASAR-Archiv wie Electron (@electron/asar)."""
    tree, blobs, offset = {"files": {}}, [], 0
    for path, data in files.items():
        node = tree
        *dirs, name = path.split("/")
        for d in dirs:
            node = node["files"].setdefault(d, {"files": {}})
        node["files"][name] = {"size": len(data), "offset": str(offset)}
        blobs.append(data)
        offset += len(data)
    raw = json.dumps(tree).encode()
    padded = raw + b"\0" * (-len(raw) % 4)
    pickle = struct.pack("<II", 4 + len(padded), len(raw)) + padded
    return struct.pack("<II", 4, len(pickle)) + pickle + b"".join(blobs)


APP = {
    "package.json": json.dumps({"name": "qobuz-desktop", "productName": "Qobuz", "version": "8.3.0",
                                "description": "Hi-Res Musik-Streaming", "main": "dist/main.js",
                                "author": {"name": "Qobuz"}, "dependencies": {"axios": "^1.6.0"}}).encode(),
    "dist/main.js": b"const { app, BrowserWindow } = require('electron');\nfunction createPlayer() {\n"
                    b"  return new BrowserWindow({ width: 1200 });\n}\napp.whenReady().then(createPlayer);\n",
    "dist/player.js": b"function play(trackId) {\n  return fetch('https://www.qobuz.com/api.json/0.2/track/get?id=' + trackId);\n}\n",
    "assets/logo.png": b"\x89PNG\r\n\x1a\n" + b"\0" * 32,
    "node_modules/axios/package.json": json.dumps({"name": "axios", "version": "1.6.2",
                                                   "description": "Promise based HTTP client"}).encode(),
    "node_modules/axios/index.js": b"module.exports = function axios() {};\n",
}


def test_asar_documents_the_real_app(settings):
    r = Engine(replace(settings, profile="allgemein")).analyze_bytes("app.asar", make_asar(APP))
    assert r.kind == "asar"
    assert r.product["Produkt"] == "Qobuz" and r.product["Version"] == "8.3.0" and r.product["Hersteller"] == "Qobuz"
    names = [c.name for c in r.children]
    assert names[:2] == ["package.json", "dist/main.js"]  # Steckbrief und Startdatei zuerst
    assert "dist/player.js" in names and not any("node_modules" in n or n.endswith(".png") for n in names)
    npm = next(s for s in r.sections if s.title.startswith("Verwendete npm-Pakete"))
    assert npm.table.rows == [["axios", "1.6.2", "Promise based HTTP client"]]
    assert "Produkt laut Datei: Produkt: Qobuz" in facts_text(r, 20000)


def test_installer_and_zip_find_the_asar(settings):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("lib/net45/resources/app.asar", make_asar(APP))
        zf.writestr("lib/net45/Qobuz.exe", tiny_pe64())
    setup = tiny_pe64() + buf.getvalue() + b"\0" * (70 * 1024)  # selbstentpackend: ZIP hinter dem PE
    r = Engine(replace(settings, max_archive_depth=4)).analyze_bytes("QobuzSetup.exe", setup)
    assert any(s.title.startswith("Installer") for s in r.sections)
    asar = [n for n in r.walk() if n.kind == "asar"]
    assert asar and asar[0].product["Produkt"] == "Qobuz"


def test_electron_runtime_detected_and_explained(settings):
    exe = tiny_pe64() + b"\0ELECTRON_RUN_AS_NODE\0electron.asar\0Mozilla/5.0 Electron/34.2.0 Safari\0"
    r = Engine(replace(settings, profile="allgemein")).analyze_bytes("Qobuz.exe", exe)
    assert r.runtime == "Electron 34.2.0"
    summary = rule_based_summary(r)
    assert "Electron 34.2.0" in summary and "app.asar" in summary
    assert not any(s.title.startswith("Disassembly") for s in r.sections)  # nur Laufzeit – übersprungen


def test_library_symbols_and_function_sizes():
    for name in ("sym.electron.exe__StopTrackingHeapObjects_HeapProfiler_v8__QEAAXXZ", "??0Isolate@v8@@QEAA@XZ",
                 "sym.electron.exe_uv_open_osfhandle", "sym.electron.exe_napi_wrap", "av_frame_alloc", "SSL_read"):
        assert library_of(name), name
    for name in ("main", "fcn.140f89210", "sym.qobuz_play", "SendMessageW", "sym.app_net_send"):
        assert library_of(name) is None, name
    assert _real_size({"size": 76230004, "realsz": 120}) == 120
    assert _real_size({"size": 76230004}) == 0 and _real_size({"size": 300}) == 300


def test_capabilities_match_whole_names():
    caps = categorize(["SendMessageW", "SystemTimeToFileTime", "ConnectNamedPipe", "send", "waveOutOpen",
                       "CreateWindowExW"])
    assert caps["Netzwerk"] == ["send"] and "Prozesse starten" not in caps
    assert caps["Audio/Multimedia"] == ["waveOutOpen"] and caps["Benutzeroberfläche"] == ["CreateWindowExW"]


def test_strings_without_code_garbage():
    for junk in ("tJH9W wDH", "Decoder H", "ded dataH", "1 200 OKH", "D$@H9D$ sOH", "HcM0HcE LcE8f", "tersA"):
        assert _is_noise(junk), junk
    for good in ("Failed to load module", "SendMessageW", "Qobuz Desktop", "user-agent: %s", "libcef.dll"):
        assert not _is_noise(good), good
    cats = classify(["9.9.9.9)H", "Krypto: tersA", "Connecting to %s failed"])
    assert cats == {"IP-Adresse": ["9.9.9.9"], "Format-String": ["Connecting to %s failed"]}


def test_verification_flags_invented_dlls():
    r = AnalysisResult("/x", "x.exe", 1)
    r.add(Section("Importierte Bibliotheken & Funktionen", table=Table(["DLL", "Anzahl", "Funktionen"],
                                                                       [["KERNEL32.dll", "1", "CreateFileW"]])))
    r.children.append(AnalysisResult("/y", "y.dll", 1, llm_doc="nutzt msvcr120.dll"))  # KI-Text ist kein Beleg
    note = verification_note(r, "Bibliotheken: kernel32.dll, msvcr120.dll und ucrtbased.dll")
    assert "`msvcr120.dll`" in note and "`ucrtbased.dll`" in note and "kernel32" not in note
    assert verification_note(r, "nutzt KERNEL32.dll") == ""


def test_llm_reads_app_code_before_runtime(fake_llm, settings):
    from magicbox.llm.documenter import Documenter
    root = AnalysisResult("/s", "QobuzSetup.exe", 10, kind="pe", profile="allgemein")
    electron = AnalysisResult("/e", "Qobuz.exe", 178_000_000, kind="pe", runtime="Electron 34.2.0")
    dll = AnalysisResult("/d", "libGLESv2.dll", 7_000_000, kind="pe", runtime="Chromium/Electron-Baustein")
    asar = AnalysisResult("/a", "app.asar", 900_000, kind="asar")
    asar.children = [AnalysisResult("/a/m", "dist/main.js", 50_000, kind="source")]
    root.children = [electron, dll, asar]
    s = replace(settings, use_llm=True, base_url=fake_llm.url, profile="allgemein", max_llm_children=4)
    Documenter(s).document(root)
    order = [r["messages"][1]["content"].split("„")[1].split("“")[0] for r in fake_llm.requests[:-1]]
    assert order[:2] == ["app.asar", "dist/main.js"] and set(order[2:]) == {"libGLESv2.dll", "Qobuz.exe"}
