"""Software-Profil ohne Malware-Prüfungen; Basisregeln ohne Fehlalarme bei Browser-/Electron-Programmen."""

from dataclasses import replace

import pytest

from magicbox.engine import Engine
from magicbox.pipeline import run
from samples import tiny_pe64

STEALER_LIKE = (b"\x00".join([b"Login Data", b"\\Google\\Chrome\\User Data", b"wallet.dat",
                              b"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                              b"http://203.0.113.9/gate.php"]) + b"\x00" * 64)


def test_software_profile_skips_malware_checks(settings):
    pytest.importorskip("yara")
    malware = Engine(replace(settings, profile="malware")).analyze_bytes("x.bin", STEALER_LIKE)
    assert malware.detections and malware.iocs and any(f.severity == "high" for f in malware.findings)

    logs = []
    soft = Engine(replace(settings, profile="allgemein"), log=logs.append).analyze_bytes("x.bin", STEALER_LIKE)
    assert soft.profile == "allgemein"
    assert not soft.detections and not soft.iocs
    assert all(f.severity == "info" for f in soft.findings)
    assert not any(s.title.startswith("YARA") for s in soft.sections)
    assert any("Software-Profil" in line and "yara" in line for line in logs)


def test_software_report_and_prompt(fake_llm, tmp_path):
    exe = tmp_path / "tool.exe"
    exe.write_bytes(tiny_pe64())
    from magicbox.config import Settings
    s = Settings(base_url=fake_llm.url, output_dir=str(tmp_path / "out"), use_radare2=False, use_capa=False,
                 profile="allgemein")
    outcome = run(exe, s)
    md = outcome.files.markdown.read_text(encoding="utf-8")
    assert "Software-Dokumentation" in md and "Indikatoren (IOCs)" not in md and "## Auffälligkeiten" not in md
    assert "Gefährliche Merkmale" not in md and "Keine kritischen" not in md
    system = fake_llm.requests[-1]["messages"][0]["content"]
    prompt = fake_llm.requests[-1]["messages"][1]["content"]
    assert "keine Sicherheitsanalyse" in system
    assert "Sicherheitsbewertung" not in prompt and "Einstufung" not in prompt
    assert "[HOCH]" not in prompt and "[MITTEL]" not in prompt


def test_basic_rules_ignore_browser_internals(settings):
    """Chromium/Electron enthält Login Data, Local State, decrypt, VMware … – das ist kein Stealer."""
    pytest.importorskip("yara")
    browser_like = b"\x00".join([
        b"Login Data", b"Web Data", b"Local State", b"encrypted_key", b"decrypt", b"private key", b".onion",
        b"bitcoin", b"ransom", b"VMware", b"QEMU", b"VirtualBox", b"DownloadFile", b"invoke-expression", b"IEX",
        b"-nop"]) + b"\x00" * 64
    r = Engine(replace(settings, profile="malware")).analyze_bytes("electron-app.bin", browser_like)
    assert not [d for d in r.detections if d.startswith("MB_")], r.detections
