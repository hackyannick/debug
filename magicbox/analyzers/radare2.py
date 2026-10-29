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

SEP = "---MAGICBOX-FN---"
BORING = ("sym.imp.", "loc.imp.", "sym._init", "sym._fini", "sym.deregister_tm_clones", "sym.register_tm_clones",
          "sym.__do_global_dtors_aux", "sym.frame_dummy", "sym.__libc_csu", "sym._start", "entry.init", "entry.fini")


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
            funcs = [{**f, "addr": f.get("addr", f.get("offset"))} for f in funcs
                     if isinstance(f, dict) and isinstance(f.get("addr", f.get("offset")), int)]
            own = [f for f in funcs if not f.get("name", "").startswith(BORING)]
            rows = [[f["name"], hex(f["addr"]), str(f.get("size", 0)), str(f.get("nbbs", "")),
                     str(len(f.get("callrefs", []) or []))]
                    for f in sorted(own, key=lambda f: -f.get("size", 0))[:300]]
            result.add(Section(f"Funktionen (radare2, {len(funcs)} erkannt, {len(own)} eigene)",
                               table=Table(["Name", "Adresse", "Größe", "Blöcke", "Aufrufe"], rows, total=len(own)),
                               llm_priority=2))

            targets = self._pick(own, ctx.settings.max_disasm_functions)
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
    def _pick(funcs: list[dict], limit: int) -> list[dict]:
        by_name = {f["name"]: f for f in funcs}
        picked = [by_name[n] for n in ("main", "sym.main", "entry0", "sym.WinMain", "sym._main", "sym.DllMain")
                  if n in by_name]
        rest = sorted((f for f in funcs if f not in picked), key=lambda f: -f.get("size", 0))
        return (picked + rest)[:limit]
