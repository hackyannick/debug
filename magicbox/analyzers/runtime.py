"""Erkennt die Laufzeitumgebung eines Programms (Electron, PyInstaller, Go …) und sagt, wo die eigentliche
Programmlogik liegt. Läuft vor radare2, damit teure Disassembly bei reinen Laufzeit-Hüllen entfallen kann."""

from __future__ import annotations

import re
from dataclasses import dataclass

from magicbox.model import AnalysisResult, Section

from .base import Analyzer, Context


@dataclass
class Runtime:
    name: str
    markers: tuple[bytes, ...]
    min_hits: int
    hint: str
    shell_only: bool = False  # die Datei ist nur die Laufzeit – Code-Analyse bringt nichts zur App selbst
    version_re: bytes = b""


RUNTIMES = (
    Runtime("Electron", (b"electron.asar", b"ELECTRON_RUN_AS_NODE", b"electron.exe", b"electron::", b"ElectronMain"), 2,
            "Die .exe ist die Electron-Laufzeit (Chromium + Node.js) und bei allen Electron-Apps nahezu gleich. Die "
            "eigentliche Programmlogik liegt als JavaScript in resources\\app.asar neben der .exe. Für eine Doku der "
            "App diese Datei, den Installer oder den Programmordner (als ZIP) hochladen.",
            shell_only=True, version_re=rb"Electron/(\d+\.\d+\.\d+)"),
    Runtime("Chromium Embedded Framework (CEF)", (b"libcef.dll", b"cef_initialize", b"CefInitialize"), 1,
            "Die Oberfläche ist eine eingebettete Web-Anwendung (HTML/JavaScript), meist in Unterordnern oder "
            "Ressourcen neben der .exe.", version_re=rb"CEF (\d+\.\d+\.\d+)"),
    Runtime("NW.js", (b"nw.exe", b"nwjs", b"node-webkit"), 2,
            "Die Programmlogik liegt als JavaScript in package.nw bzw. im Programmordner.", shell_only=True),
    Runtime("Node.js-Einzeldatei (pkg/SEA)", (b"pkg/prelude/bootstrap.js", b"NODE_SEA_BLOB", b"PAYLOAD_POSITION"), 1,
            "Der JavaScript-Code ist in die Datei eingebettet (Snapshot/Payload); die Funktionen der .exe sind Node.js."),
    Runtime("PyInstaller (Python)", (b"PYZ-00.pyz", b"_MEIPASS", b"pyi-runtime-tmpdir", b"Py_SetPythonHome"), 2,
            "Der Python-Code steckt komprimiert im angehängten Archiv. Mit pyinstxtractor entpacken und die "
            ".pyc-Dateien hochladen – die .exe selbst ist nur der Python-Starter.", shell_only=True),
    Runtime("Go", (b"Go build ID:", b"runtime.gopanic", b"runtime.goexit"), 2,
            "Go-Programme sind statisch gelinkt: Funktionen mit runtime.*, net/http.*, crypto/* usw. stammen aus der "
            "Go-Standardbibliothek; die eigenen Funktionen stehen meist unter main.*.", version_re=rb"go(1\.\d+(?:\.\d+)?)"),
    Runtime("Rust", (b"/rustc/", b"RUST_BACKTRACE", b"rust_panic"), 2,
            "Rust-Programme enthalten die Standardbibliothek (std::, core::, alloc::) statisch."),
    Runtime("Qt", (b"Qt5Core", b"Qt6Core", b"QObject", b"qt_plugin_instance"), 2,
            "Die Oberfläche nutzt das Qt-Framework (Funktionen mit Q…/qt_… stammen aus Qt)."),
    Runtime("Delphi/C++Builder", (b"Embarcadero", b"Borland", b"TApplication", b"System.SysUtils"), 2,
            "Delphi-Programme enthalten die VCL/RTL statisch; Formulare liegen als RCDATA-Ressourcen (DFM)."),
    Runtime("AutoIt", (b"AU3!EA06", b"AutoIt v3"), 1,
            "Das AutoIt-Skript ist in die .exe eingebettet (z. B. mit Exe2Aut/AutoIt-Ripper extrahierbar).",
            shell_only=True),
)


# Mitgelieferte Bausteine von Chromium/Electron/CEF – Fremdcode, Disassembly lohnt nicht
COMPONENT_FILES = {
    "libegl.dll", "libglesv2.dll", "ffmpeg.dll", "vk_swiftshader.dll", "vulkan-1.dll", "d3dcompiler_47.dll",
    "dxcompiler.dll", "dxil.dll", "chrome_elf.dll", "libcef.dll", "squirrel.exe", "update.exe", "elevate.exe",
    "libffmpeg.so", "libegl.so", "libglesv2.so", "libvk_swiftshader.so", "libvulkan.so.1", "chrome-sandbox",
    "chrome_crashpad_handler", "crashpad_handler.exe",
}
# Laufzeiten, bei denen die Datei selbst nicht die Programmlogik enthält
SHELL_RUNTIMES = {"Electron", "NW.js", "PyInstaller (Python)", "AutoIt", "Chromium/Electron-Baustein"}


def is_shell(result: AnalysisResult) -> bool:
    return any(result.runtime.startswith(name) for name in SHELL_RUNTIMES)


def detect(data: bytes) -> list[tuple[Runtime, str]]:
    found = []
    for rt in RUNTIMES:
        hits = sum(1 for m in rt.markers if m in data)
        if hits >= rt.min_hits:
            version = ""
            if rt.version_re:
                m = re.search(rt.version_re, data)
                version = m.group(1).decode(errors="replace") if m else ""
            found.append((rt, version))
    return found


class RuntimeAnalyzer(Analyzer):
    name = "runtime"
    kinds = ("pe", "elf", "macho")

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        if ctx.path.name.lower() in COMPONENT_FILES:
            result.runtime = "Chromium/Electron-Baustein"
            ctx.facts["runtime"], ctx.facts["runtime_shell"] = result.runtime, True
            result.add(Section("Laufzeitumgebung", kv={
                "Laufzeitumgebung": result.runtime,
                "Wo liegt die Programmlogik?": f"{ctx.path.name} ist ein mitgelieferter Standard-Baustein "
                                               "(Grafik, Video, Updater, Absturzberichte) – nicht Teil der App-Logik.",
            }, llm_priority=3))
            return
        found = detect(ctx.data)
        if not found:
            return
        rt, version = found[0]
        result.runtime = f"{rt.name} {version}".strip()
        ctx.facts["runtime"] = rt.name
        ctx.facts["runtime_shell"] = rt.shell_only
        kv = {"Laufzeitumgebung": result.runtime, "Wo liegt die Programmlogik?": rt.hint}
        if len(found) > 1:
            kv["Außerdem erkannt"] = ", ".join(f"{r.name} {v}".strip() for r, v in found[1:])
        if rt.shell_only:
            kv["Hinweis zur Analyse"] = ("Disassembly/Pseudocode wurden übersprungen – sie würden nur die Laufzeit "
                                         "beschreiben, nicht dieses Programm.")
        result.add(Section("Laufzeitumgebung", kv=kv, llm_priority=0))
        result.find("info", f"{rt.name}-Programm", "Details unter „Laufzeitumgebung“"
                    + (" – die Datei enthält nur die Laufzeit, nicht die Programmlogik." if rt.shell_only else "."))
