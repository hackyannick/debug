"""Erkennung und Aufruf externer Werkzeuge (radare2, upx, 7z, capa, ilspycmd …)."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from magicbox.config import Settings

# Zusätzliche Suchorte: neben dem Python-Interpreter (venv/bin, z. B. capa aus pip) und dotnet-Tools
EXTRA_DIRS = [Path(sys.executable).parent, Path.home() / ".dotnet" / "tools"]


def which(name: str) -> str | None:
    if not name:
        return None
    if os.sep in name or (os.altsep and os.altsep in name):
        return name if Path(name).is_file() and os.access(name, os.X_OK) else None
    found = shutil.which(name)
    if found:
        return found
    for d in EXTRA_DIRS:
        for candidate in (d / name, d / f"{name}.exe"):
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate)
    return None


def run(cmd: list[str], timeout: int, cwd: str | None = None) -> subprocess.CompletedProcess:
    """Führt ein Werkzeug ohne Shell aus. Ausgabe wird als Text (fehlertolerant) zurückgegeben."""
    env = dict(os.environ, DOTNET_CLI_TELEMETRY_OPTOUT="1", DOTNET_NOLOGO="1")
    env.setdefault("DOTNET_ROLL_FORWARD", "Major")  # ilspycmd läuft so auch auf neueren .NET-Runtimes
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout, cwd=cwd, env=env,
                          stdin=subprocess.DEVNULL)


@dataclass
class ToolInfo:
    key: str
    name: str
    purpose: str
    path: str | None
    hint: str


def _py_module(name: str) -> str | None:
    try:
        __import__(name)
        return f"Python-Modul {name}"
    except ImportError:
        return None


def status(s: Settings) -> list[ToolInfo]:
    r2 = which(s.radare2_path) or which("radare2")
    seven = which(s.sevenzip_path) or which("7zz") or which("7za")
    return [
        ToolInfo("radare2", "radare2", "Funktionserkennung & Pseudocode", r2, "apt install radare2"),
        ToolInfo("upx", "UPX", "Entpacken UPX-gepackter Programme", which(s.upx_path), "apt install upx-ucl"),
        ToolInfo("7z", "7-Zip", "7z/RAR-Archive und AES-verschlüsselte ZIPs", seven, "apt install p7zip-full"),
        ToolInfo("capa", "capa (Mandiant)", "Fähigkeiten + MITRE ATT&CK", which(s.capa_path),
                 "Standalone-Binary von github.com/mandiant/capa/releases"),
        ToolInfo("yara", "YARA", "Erkennung von Malware-Familien per Regeln", _py_module("yara"), "pip install yara-python"),
        ToolInfo("ilspy", "ILSpy (ilspycmd)", ".NET-Dekompilierung nach C#", which(s.ilspy_path),
                 "dotnet tool install -g ilspycmd"),
        ToolInfo("dnfile", "dnfile", ".NET-Metadaten (Klassen, Methoden, Strings)", _py_module("dnfile"), "pip install dnfile"),
        ToolInfo("olevba", "oletools", "Office-Makros (VBA/XLM) extrahieren", _py_module("oletools"), "pip install oletools"),
        ToolInfo("pyzipper", "pyzipper", "AES-verschlüsselte ZIPs", _py_module("pyzipper"), "pip install pyzipper"),
    ]
