"""Kommandozeile: magicbox [gui] | analyze DATEI… | watch ORDNER | check | models"""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from pathlib import Path

from magicbox import __version__
from magicbox.config import Settings
from magicbox.llm.client import LLMClient, LLMError
from magicbox.pipeline import Callbacks, run


def _settings(args) -> Settings:
    s = Settings.load()
    for attr in ("base_url", "model", "provider", "output_dir", "language"):
        val = getattr(args, attr, None)
        if val:
            setattr(s, attr, val)
    if getattr(args, "no_llm", False):
        s.use_llm = False
    if getattr(args, "context", None):
        s.context_tokens = args.context
    return s


def _callbacks(args) -> Callbacks:
    stream = getattr(args, "stream", False)
    return Callbacks(
        log=lambda m: print(m, file=sys.stderr),
        token=(lambda t: print(t, end="", flush=True, file=sys.stderr)) if stream else None,
    )


def cmd_analyze(args) -> int:
    s = _settings(args)
    rc = 0
    for p in args.paths:
        path = Path(p)
        if not path.exists():
            print(f"Nicht gefunden: {path}", file=sys.stderr)
            rc = 2
            continue
        outcome = run(path, s, _callbacks(args))
        print(outcome.files.html)
        if args.open:
            import webbrowser
            webbrowser.open(outcome.files.html.as_uri())
    return rc


def cmd_watch(args) -> int:
    """Überwacht einen Ordner (z. B. eine Netzwerkfreigabe auf dem R640): Datei rein → Bericht raus."""
    s = _settings(args)
    inbox = Path(args.folder).expanduser()
    done = inbox / "_erledigt"
    inbox.mkdir(parents=True, exist_ok=True)
    done.mkdir(exist_ok=True)
    if not args.output_dir:
        s.output_dir = str(inbox / "_berichte")
    print(f"👀 Überwache {inbox} – Berichte landen in {s.output_dir} (Strg+C zum Beenden)", file=sys.stderr)
    seen: dict[Path, tuple[int, float]] = {}
    try:
        while True:
            for entry in sorted(inbox.iterdir()):
                if entry.name.startswith(("_", ".")) or entry.name.endswith((".part", ".crdownload", ".tmp")):
                    continue
                st = entry.stat()
                sig = (st.st_size, st.st_mtime)
                if seen.get(entry) != sig:  # erst verarbeiten, wenn sich die Datei nicht mehr ändert
                    seen[entry] = sig
                    continue
                try:
                    outcome = run(entry, s, _callbacks(args))
                    print(outcome.files.html)
                except Exception as exc:  # weiterlaufen, auch wenn eine Datei scheitert
                    print(f"✖ {entry.name}: {exc}", file=sys.stderr)
                target = done / entry.name
                if target.exists():
                    target = done / f"{entry.stem}_{int(time.time())}{entry.suffix}"
                shutil.move(str(entry), target)
                seen.pop(entry, None)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


def cmd_check(args) -> int:
    s = _settings(args)
    try:
        print(LLMClient(s).check())
        return 0
    except LLMError as exc:
        print(f"✖ {exc}", file=sys.stderr)
        return 1


def cmd_models(args) -> int:
    s = _settings(args)
    try:
        for m in LLMClient(s).list_models():
            print(m)
        return 0
    except LLMError as exc:
        print(f"✖ {exc}", file=sys.stderr)
        return 1


def cmd_gui(_args) -> int:
    from magicbox.gui.app import main as gui_main
    return gui_main()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="magicbox", description="Magic Box – Datei rein, verständliche Doku raus.")
    p.add_argument("--version", action="version", version=f"magicbox {__version__}")
    sub = p.add_subparsers(dest="cmd")

    def llm_opts(sp):
        sp.add_argument("--url", dest="base_url", help="LLM-Server, z. B. http://r640:11434")
        sp.add_argument("--model", help="Modellname, z. B. qwen2.5-coder:7b")
        sp.add_argument("--provider", choices=["ollama", "openai"])
        sp.add_argument("--context", type=int, help="Kontextgröße in Tokens")

    a = sub.add_parser("analyze", help="Datei(en) oder Ordner analysieren")
    a.add_argument("paths", nargs="+")
    a.add_argument("-o", "--out", dest="output_dir", help="Ausgabeordner für Berichte")
    a.add_argument("--no-llm", action="store_true", help="Nur technische Analyse, ohne KI")
    a.add_argument("--language", help="Sprache der Doku (Standard: Deutsch)")
    a.add_argument("--stream", action="store_true", help="KI-Ausgabe live anzeigen")
    a.add_argument("--open", action="store_true", help="Bericht danach im Browser öffnen")
    llm_opts(a)
    a.set_defaults(func=cmd_analyze)

    w = sub.add_parser("watch", help="Ordner überwachen (Drop-Folder-Modus)")
    w.add_argument("folder")
    w.add_argument("-o", "--out", dest="output_dir")
    w.add_argument("--no-llm", action="store_true")
    w.add_argument("--language")
    w.add_argument("--interval", type=float, default=3.0)
    w.add_argument("--stream", action="store_true")
    llm_opts(w)
    w.set_defaults(func=cmd_watch)

    c = sub.add_parser("check", help="Verbindung zum LLM-Server testen")
    llm_opts(c)
    c.set_defaults(func=cmd_check)
    m = sub.add_parser("models", help="Verfügbare Modelle auflisten")
    llm_opts(m)
    m.set_defaults(func=cmd_models)
    g = sub.add_parser("gui", help="Desktop-Oberfläche starten (Standard)")
    g.set_defaults(func=cmd_gui)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not getattr(args, "func", None):
        return cmd_gui(args)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
