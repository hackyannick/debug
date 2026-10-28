"""Automatisches Entpacken bekannter Packer (derzeit UPX) – das Ergebnis wird als Kind-Datei weiter analysiert."""

from __future__ import annotations

import os
import subprocess
import tempfile

from magicbox import tools
from magicbox.model import AnalysisResult, Section

from .base import Analyzer, Context, clip


def is_upx(data: bytes, result: AnalysisResult) -> bool:
    if any(f.title == "Packer erkannt: UPX" for f in result.findings):
        return True
    head = data[:4096]
    return b"UPX!" in head or (b"UPX0" in head and b"UPX1" in head)


class UPXUnpacker(Analyzer):
    name = "upx"
    kinds = ("pe", "elf", "macho")

    def matches(self, ctx: Context, result: AnalysisResult) -> bool:
        return super().matches(ctx, result) and is_upx(ctx.data, result)

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        upx = tools.which(ctx.settings.upx_path)
        if not upx:
            result.find("info", "UPX-Entpacken nicht möglich", "upx ist nicht installiert – analysiert wurde nur die gepackte Hülle.")
            return
        with tempfile.TemporaryDirectory(prefix="magicbox_upx_") as tmp:
            src, dst = os.path.join(tmp, "packed.bin"), os.path.join(tmp, "unpacked.bin")
            with open(src, "wb") as f:
                f.write(ctx.data)
            try:
                proc = tools.run([upx, "-d", "-q", "-o", dst, src], timeout=ctx.settings.tool_timeout_s)
            except subprocess.TimeoutExpired:
                result.errors.append("upx: Zeitlimit überschritten")
                return
            if proc.returncode != 0 or not os.path.exists(dst):
                msg = clip((proc.stderr or proc.stdout).strip(), 300)
                result.find("medium", "UPX-Entpacken fehlgeschlagen",
                            f"{msg} – evtl. wurde der UPX-Header absichtlich manipuliert (häufig bei Malware).")
                return
            with open(dst, "rb") as f:
                unpacked = f.read()
        result.tools.append("upx")
        result.add(Section("Entpackt (UPX)", kv={"Gepackt": f"{len(ctx.data):,} Bytes", "Entpackt": f"{len(unpacked):,} Bytes"},
                           llm_priority=0))
        result.find("info", "Mit UPX entpackt", "Die entpackte Datei wird als eigener Eintrag analysiert.")
        if ctx.recurse is not None:
            child = ctx.recurse(f"{ctx.path.name} [UPX-entpackt]", unpacked)
            if child is not None:
                result.children.append(child)
