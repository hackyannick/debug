"""Startpunkt der gebündelten Desktop-App (PyInstaller).

    MagicBox.exe                       – App starten (Server aus Installer/Einstellungen)
    MagicBox.exe --server URL          – mit einem bestimmten Server verbinden
    MagicBox.exe --local               – eingebauten lokalen Server nutzen
    MagicBox.exe --selftest DATEI      – Build prüfen (ohne Fenster), Ergebnis als JSON in DATEI
"""

from __future__ import annotations

import json
import sys
import traceback


def selftest(out_path: str) -> int:
    """Prüft im fertigen Bundle, dass alle Bausteine geladen werden und eine Analyse durchläuft."""
    result: dict = {"ok": False}
    try:
        import PySide6.QtWebEngineWidgets  # noqa: F401 – Chromium-Engine im Bundle?

        from magicbox import __version__
        from magicbox.analyzers.yara_scan import BUILTIN_RULES
        from magicbox.config import Settings
        from magicbox.engine import Engine
        from magicbox.report.builder import build_html, build_markdown
        from magicbox.server import MagicBoxServer

        settings = Settings(use_llm=False, use_radare2=False, use_capa=False)
        with open(sys.executable, "rb") as f:  # sich selbst analysieren: PE (Windows) bzw. ELF
            data = f.read()
        r = Engine(settings).analyze_bytes("selbst", data)
        html = build_html(build_markdown(r), "test")
        srv = MagicBoxServer(Settings(data_dir=str(__import__("tempfile").mkdtemp()), use_llm=False),
                             host="127.0.0.1", port=0, token="x")
        srv.shutdown()
        result = {
            "ok": not r.errors and len(html) > 1000,
            "version": __version__, "kind": r.kind, "description": r.description, "tools": r.tools,
            "errors": r.errors, "yara_rules": sorted(p.name for p in BUILTIN_RULES.glob("*.yar")),
        }
    except Exception:  # noqa: BLE001
        result["error"] = traceback.format_exc()
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1, ensure_ascii=False)
    return 0 if result["ok"] else 1


def main() -> int:
    args = sys.argv[1:]
    if args[:1] == ["--selftest"]:
        return selftest(args[1] if len(args) > 1 else "magicbox-selftest.json")
    server = None
    if "--local" in args:
        server = ""
    if "--server" in args:
        i = args.index("--server")
        server = args[i + 1] if i + 1 < len(args) else ""
    from magicbox.gui.app import main as gui_main

    return gui_main(server_url=server)


if __name__ == "__main__":
    sys.exit(main())
