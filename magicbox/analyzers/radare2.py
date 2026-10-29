"""Optionale Tiefenanalyse mit radare2: Funktionsliste und Pseudo-C (``pdc``).

radare2 wird nur genutzt, wenn es installiert ist (``r2`` im PATH oder in den
Einstellungen hinterlegt). Die Datei wird dafür temporär auf die Platte geschrieben,
aber niemals ausgeführt.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile

from magicbox.model import AnalysisResult, Section, Table

from .base import Analyzer, Context, clip
from .libs import describe, library_of

SEP = "---MAGICBOX-FN---"
UNNAMED = ("fcn.", "sub.", "loc.", "entry")
BORING = ("sym.imp.", "loc.imp.", "sym._init", "sym._fini", "sym.deregister_tm_clones", "sym.register_tm_clones",
          "sym.__do_global_dtors_aux", "sym.frame_dummy", "sym.__libc_csu", "sym._start", "entry.init", "entry.fini")


def _real_size(f: dict) -> int:
    size = f.get("realsz")
    if not isinstance(size, int) or size <= 0:
        size = f.get("size", 0) if isinstance(f.get("size"), int) else 0
        if size > 1024 * 1024:  # unplausibel für eine einzelne Funktion
            size = 0
    return size


def find_r2(configured: str) -> str | None:
    return shutil.which(configured or "r2") or shutil.which("radare2")


def _run(r2: str, path: str, commands: str, timeout: int) -> str:
    proc = subprocess.run(
        [r2, "-2", "-q", "-e", "scr.color=0", "-e", "bin.cache=true", "-e", "scr.interactive=false",
         "-c", commands, path],
        capture_output=True, text=True, timeout=timeout, errors="replace",
    )
    return proc.stdout


class Radare2Analyzer(Analyzer):
    name = "radare2"
    slow_hint = "Funktionsanalyse und Pseudocode laufen"
    kinds = ("pe", "elf", "macho")

    def matches(self, ctx: Context, result: AnalysisResult) -> bool:
        if ctx.facts.get("runtime_shell"):  # z. B. Electron: Code wäre nur die Laufzeit, nicht das Programm
            return False
        return super().matches(ctx, result) and ctx.settings.use_radare2 and find_r2(ctx.settings.radare2_path) is not None

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        r2 = find_r2(ctx.settings.radare2_path)
        fd, tmp = tempfile.mkstemp(prefix="magicbox_", suffix=".bin")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(ctx.data)
            timeout = 300 if len(ctx.data) < 20 * 1024 * 1024 else 900
            # aaa ist gründlicher, aber bei großen Binaries sehr langsam
            level = "aaa" if len(ctx.data) < 3 * 1024 * 1024 else "aa"
            try:
                funcs = json.loads(_run(r2, tmp, f"{level};aflj", timeout) or "[]")
            except (json.JSONDecodeError, subprocess.TimeoutExpired) as exc:
                result.errors.append(f"radare2-Analyse fehlgeschlagen: {exc.__class__.__name__}")
                return
            if not funcs:
                return
            result.tools.append("radare2")
            ctx.facts["radare2"] = True

            # radare2 ≥ 6 nennt die Adresse "addr", ältere Versionen "offset"
            # "size" ist bei radare2 die Spanne vom ersten bis zum letzten Block (bei großen Binaries teils
            # zig MB); "realsz" ist die tatsächliche Codegröße
            funcs = [{**f, "addr": f.get("addr", f.get("offset")), "realsz": _real_size(f)} for f in funcs
                     if isinstance(f, dict) and isinstance(f.get("addr", f.get("offset")), int)]
            libs: dict[str, int] = {}
            own = []
            for f in funcs:
                if f.get("name", "").startswith(BORING):
                    continue
                lib = library_of(f.get("name", ""))
                if lib:
                    libs[lib] = libs.get(lib, 0) + 1
                else:
                    own.append(f)
            # Tabelle nur mit benannten Funktionen – fcn.<adresse> sagt im Bericht nichts aus
            named = [f for f in own if not f["name"].startswith(UNNAMED)]
            rows = [[f["name"], hex(f["addr"]), str(f["realsz"]), str(f.get("nbbs", ""))]
                    for f in sorted(named, key=lambda f: -f["realsz"])[:150]]
            notes = [f"{len(own) - len(named)} weitere Funktionen ohne Namen (fcn.*, z. B. durch entfernte Symbole) "
                     "sind nicht aufgeführt."] if len(own) > len(named) else []
            if libs:
                from collections import Counter
                notes.append(f"Ohne {sum(libs.values())} Funktionen bekannter Bibliotheken ({describe(Counter(libs))}) – "
                             "diese gehören nicht zur eigentlichen Programmlogik.")
            result.add(Section(f"Funktionen (radare2, {len(funcs)} erkannt, {len(named)} benannte eigene)",
                               table=Table(["Name", "Adresse", "Größe (Bytes)", "Blöcke"], rows, total=len(named))
                               if rows else None, text=" ".join(notes), llm_priority=2))

            library_file = ctx.path.name.lower().endswith((".dll", ".node", ".so", ".dylib", ".sys"))
            targets = self._pick(own, ctx.settings.max_disasm_functions, skip_entry=library_file)
            cmds = [level] + [f"?e {SEP}{f['name']}@{f['addr']:#x};pdc @ {f['addr']}" for f in targets]
            try:
                out = _run(r2, tmp, ";".join(cmds), timeout)
            except subprocess.TimeoutExpired:
                result.errors.append("radare2-Dekompilierung: Zeitlimit überschritten")
                return
            blocks = []
            for chunk in out.split(SEP)[1:]:
                header, _, body = chunk.partition("\n")
                body = "\n".join(l for l in body.splitlines() if l.strip())
                if body:
                    blocks.append(f"// ===== {header.strip()} =====\n{clip(body, 6000)}")
            if blocks:
                result.add(Section("Pseudocode (radare2 pdc)", code="\n\n".join(blocks), code_lang="c", llm_priority=2))
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    @staticmethod
    def _pick(funcs: list[dict], limit: int, skip_entry: bool = False) -> list[dict]:
        """Einstiegspunkte zuerst – außer bei Bibliotheken (DLL/.node): dort sind main/entry0 nur Startcode der
        C-Laufzeit; aussagekräftiger sind die benannten Methoden."""
        by_name = {f["name"]: f for f in funcs}
        starts = () if skip_entry else ("main", "sym.main", "entry0", "sym.WinMain", "sym._main", "sym.DllMain")
        picked = [by_name[n] for n in starts if n in by_name]
        if skip_entry:
            funcs = [f for f in funcs if f["name"] not in ("main", "entry0") and f.get("realsz", 0) >= 32]
        # benannte Funktionen zuerst (aussagekräftiger), dann nach Größe
        rest = sorted((f for f in funcs if f not in picked),
                      key=lambda f: (f.get("name", "").startswith(UNNAMED), -f.get("realsz", 0)))
        return (picked + rest)[:limit]
