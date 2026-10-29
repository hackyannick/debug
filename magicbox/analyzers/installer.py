"""Installer und selbstentpackende Programme: eingebettete Pakete finden und mit analysieren.

* Squirrel (viele Electron-Apps): das .nupkg (ZIP) liegt als Ressource in Setup.exe
* angehängte ZIP-/7z-Archive (Overlay hinter dem PE)
* NSIS (z. B. electron-builder): wird mit 7-Zip ausgepackt
* Inno Setup: nur Hinweis (Entpacken mit innoextract)
"""

from __future__ import annotations

import struct

from magicbox import tools
from magicbox.model import AnalysisResult, Section

from .archive import ArchiveAnalyzer
from .base import Analyzer, Context, human_size

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None

ARCHIVE_MAGIC = {b"PK\x03\x04": "zip", b"7z\xbc\xaf\x27\x1c": "7z", b"Rar!": "rar"}
MIN_PAYLOAD = 64 * 1024


def _trim(blob: bytes, kind: str) -> bytes:
    """Schneidet Daten hinter dem Archiv ab (z. B. die Authenticode-Signatur am Dateiende)."""
    if kind == "zip":
        end = blob.rfind(b"PK\x05\x06")
        if end >= 0 and end + 22 <= len(blob):
            comment = struct.unpack_from("<H", blob, end + 20)[0]
            return blob[:end + 22 + comment]
    elif kind == "7z" and len(blob) >= 32:
        next_offset, next_size = struct.unpack_from("<QQ", blob, 12)
        total = 32 + next_offset + next_size
        if total <= len(blob):
            return blob[:total]
    return blob


def _archive_kind(blob: bytes) -> str | None:
    for magic, kind in ARCHIVE_MAGIC.items():
        if blob.startswith(magic):
            return kind
    return None


class InstallerAnalyzer(Analyzer):
    name = "installer"
    kinds = ("pe",)

    def matches(self, ctx: Context, result: AnalysisResult) -> bool:
        return super().matches(ctx, result) and pefile is not None and ctx.recurse is not None

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        if ctx.depth >= ctx.settings.max_archive_depth:
            return
        pe = pefile.PE(data=ctx.data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        payloads: list[tuple[str, bytes]] = []
        kv: dict[str, str] = {}

        # 1. Archive in Ressourcen (Squirrel: Typ "DATA")
        for rtype in getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None).entries if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE") else []:
            tname = pefile.RESOURCE_TYPE.get(rtype.id, str(rtype.name or rtype.id))
            for rid in getattr(rtype, "directory", None).entries if hasattr(rtype, "directory") else []:
                for lang in getattr(rid, "directory", None).entries if hasattr(rid, "directory") else []:
                    size = lang.data.struct.Size
                    if size < MIN_PAYLOAD:
                        continue
                    blob = pe.get_data(lang.data.struct.OffsetToData, size)
                    kind = _archive_kind(blob)
                    blob = _trim(blob, kind) if kind else blob
                    if kind:
                        label = str(rid.name or rid.id)
                        squirrel = str(tname).upper() == "DATA" and kind == "zip"
                        name = f"{'squirrel-paket.nupkg' if squirrel else f'ressource-{tname}-{label}.{kind}'}"
                        payloads.append((name, blob))
                        kv["Installer-Typ" if squirrel else f"Ressource {tname}/{label}"] = (
                            "Squirrel (Paket als Ressource)" if squirrel else f"{kind.upper()}-Archiv, {human_size(size)}")

        # 2. Angehängte Daten hinter dem PE (Overlay)
        start = pe.get_overlay_data_start_offset()
        if start:
            overlay = ctx.data[start:]
            kind = _archive_kind(overlay)
            if kind and len(overlay) >= MIN_PAYLOAD:
                overlay = _trim(overlay, kind)
                payloads.append((f"angehängt.{kind}", overlay))
                kv["Angehängtes Archiv"] = f"{kind.upper()}, {human_size(len(overlay))} (selbstentpackend)"
            elif b"NullsoftInst" in overlay[:1024 * 1024]:
                kv["Installer-Typ"] = "NSIS (Nullsoft) – mit 7-Zip ausgepackt"
                self._nsis(ctx, result, kv)
            elif b"Inno Setup Setup Data" in ctx.data or b"Inno Setup Messages" in ctx.data:
                kv["Installer-Typ"] = "Inno Setup – Inhalt mit innoextract entpacken und hochladen"

        for name, blob in payloads:
            child = ctx.recurse(name, blob)
            if child is not None:
                result.children.append(child)
        if kv:
            result.add(Section("Installer / eingebettete Pakete", kv=kv, llm_priority=0))
            result.find("info", "Installer bzw. eingebettetes Paket", "; ".join(f"{k}: {v}" for k, v in kv.items()))

    @staticmethod
    def _nsis(ctx: Context, result: AnalysisResult, kv: dict[str, str]) -> None:
        if not (tools.which(ctx.settings.sevenzip_path) or tools.which("7zz") or tools.which("7za")):
            kv["Installer-Typ"] = "NSIS (Nullsoft) – zum Auspacken 7-Zip installieren (apt install p7zip-full)"
            return
        members = ArchiveAnalyzer()._sevenzip(ctx, result)
        for name, _size, data in members:
            if data is None or name.startswith("$PLUGINSDIR/") and not name.lower().endswith((".7z", ".zip")):
                continue  # NSIS-Plugins (System.dll …) sind Installer-Technik, nicht die App
            child = ctx.recurse(name, data)
            if child is not None:
                result.children.append(child)
