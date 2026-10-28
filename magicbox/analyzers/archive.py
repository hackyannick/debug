"""Archive & Container (ZIP/JAR/APK/Office, TAR, GZIP, BZIP2, XZ) – rekursiv und sicher im Speicher."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import tarfile
import zipfile

from magicbox.model import AnalysisResult, Section, Table

from .base import Analyzer, Context, human_size
from .strings import extract_strings


def _container_type(names: set[str]) -> str | None:
    if "AndroidManifest.xml" in names and any(n.endswith(".dex") for n in names):
        return "Android-App (APK)"
    if "META-INF/MANIFEST.MF" in names or any(n.endswith(".class") for n in names):
        return "Java-Archiv (JAR/WAR)"
    if "[Content_Types].xml" in names:
        if any(n.startswith("word/") for n in names):
            return "Word-Dokument (DOCX)"
        if any(n.startswith("xl/") for n in names):
            return "Excel-Arbeitsmappe (XLSX)"
        if any(n.startswith("ppt/") for n in names):
            return "PowerPoint (PPTX)"
        return "Office Open XML"
    if any(n.endswith(".dist-info/WHEEL") for n in names):
        return "Python-Wheel"
    if any(n.endswith(".nuspec") for n in names):
        return "NuGet-Paket"
    if "manifest.json" in names and any(n.endswith(".js") for n in names):
        return "Browser-Erweiterung / Web-Paket"
    return None


class ArchiveAnalyzer(Analyzer):
    name = "archive"
    kinds = ("zip", "tar", "gzip", "bzip2", "xz")

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        s = ctx.settings
        if result.kind in ("gzip", "bzip2", "xz"):
            self._stream(ctx, result)
            return
        members: list[tuple[str, int, bytes | None]] = []
        try:
            if result.kind == "zip":
                members = self._zip(ctx, result)
            else:
                members = self._tar(ctx, result)
        except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as exc:
            result.errors.append(f"Archiv beschädigt: {exc}")
            return

        names = {m[0] for m in members}
        ctype = _container_type(names)
        if ctype:
            result.description = ctype
        rows = [[n, human_size(sz)] for n, sz, _ in members[:500]]
        result.add(Section(f"Inhalt ({len(members)} Einträge)",
                           table=Table(["Pfad", "Größe"], rows, total=len(members)), llm_priority=1))

        if ctype == "Android-App (APK)":
            manifest = next((d for n, _, d in members if n == "AndroidManifest.xml" and d), None)
            if manifest:
                perms = sorted({x for x in extract_strings(manifest) if x.startswith("android.permission.")})
                if perms:
                    result.add(Section("Android-Berechtigungen", text="\n".join(perms), llm_priority=0))
                    risky = [p for p in perms if any(k in p for k in (
                        "SMS", "CALL", "CONTACTS", "LOCATION", "RECORD_AUDIO", "CAMERA", "ACCESSIBILITY",
                        "SYSTEM_ALERT", "INSTALL_PACKAGES", "READ_PHONE"))]
                    if risky:
                        result.find("medium", "Sensible Android-Berechtigungen", ", ".join(risky))
        if any(n.lower().endswith("vbaproject.bin") for n in names):
            result.find("high", "Office-Makros (VBA) enthalten", "Das Dokument enthält VBA-Makros.")

        if ctx.recurse is None or ctx.depth >= s.max_archive_depth:
            if members:
                result.find("info", "Inhalt nicht rekursiv analysiert",
                            f"Maximale Verschachtelungstiefe ({s.max_archive_depth}) erreicht.")
            return
        for name, _, data in members:
            if data is None or name.endswith("/"):
                continue
            child = ctx.recurse(name, data)
            if child is not None:
                result.children.append(child)

    # ------------------------------------------------------------------
    def _budget(self, ctx: Context):
        state = {"bytes": 0, "count": 0}
        s = ctx.settings

        def take(size: int) -> bool:
            if state["count"] >= s.max_archive_members or state["bytes"] + size > s.max_extract_bytes:
                return False
            state["count"] += 1
            state["bytes"] += size
            return True

        return take

    def _zip(self, ctx: Context, result: AnalysisResult):
        take = self._budget(ctx)
        out, skipped, encrypted = [], 0, 0
        with zipfile.ZipFile(io.BytesIO(ctx.data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                data = None
                if info.flag_bits & 0x1:
                    encrypted += 1
                elif take(info.file_size):
                    try:
                        data = zf.read(info)
                    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError) as exc:
                        result.errors.append(f"{info.filename}: {exc}")
                else:
                    skipped += 1
                out.append((info.filename, info.file_size, data))
                ratio = info.file_size / max(1, info.compress_size)
                if ratio > 200 and info.file_size > 50 * 1024 * 1024:
                    result.find("high", "Verdacht auf ZIP-Bombe", f"{info.filename}: Kompressionsrate {ratio:.0f}:1")
        if encrypted:
            result.find("low", "Passwortgeschützte Einträge", f"{encrypted} Dateien sind verschlüsselt und wurden nicht analysiert.")
        if skipped:
            result.find("info", "Limit erreicht", f"{skipped} Einträge wurden wegen Größen-/Anzahl-Limits nicht entpackt.")
        return out

    def _tar(self, ctx: Context, result: AnalysisResult):
        take = self._budget(ctx)
        out, skipped = [], 0
        with tarfile.open(fileobj=io.BytesIO(ctx.data), mode="r:*") as tf:
            for m in tf:
                if not m.isfile():
                    if m.issym() or m.islnk():
                        out.append((f"{m.name} -> {m.linkname}", 0, None))
                    continue
                data = None
                if take(m.size):
                    f = tf.extractfile(m)
                    data = f.read() if f else None
                else:
                    skipped += 1
                out.append((m.name, m.size, data))
        if skipped:
            result.find("info", "Limit erreicht", f"{skipped} Einträge wurden wegen Größen-/Anzahl-Limits nicht entpackt.")
        return out

    def _stream(self, ctx: Context, result: AnalysisResult) -> None:
        opener = {"gzip": gzip.GzipFile, "bzip2": bz2.BZ2File, "xz": lzma.LZMAFile}[result.kind]
        limit = ctx.settings.max_extract_bytes
        try:
            with opener(fileobj=io.BytesIO(ctx.data)) as f:
                data = f.read(limit + 1)
        except (OSError, EOFError, lzma.LZMAError) as exc:
            result.errors.append(f"Entpacken fehlgeschlagen: {exc}")
            return
        if len(data) > limit:
            result.find("medium", "Entpackte Daten zu groß", f"Mehr als {human_size(limit)} – abgebrochen.")
            return
        inner = ctx.path.name
        for ext in (".gz", ".tgz", ".bz2", ".xz", ".txz"):
            if inner.lower().endswith(ext):
                inner = inner[: -len(ext)] + (".tar" if ext in (".tgz", ".txz") else "")
                break
        else:
            inner += ".entpackt"
        result.add(Section("Komprimierter Inhalt", kv={"Entpackt": inner, "Größe entpackt": human_size(len(data))},
                           llm_priority=1))
        if ctx.recurse is not None and ctx.depth < ctx.settings.max_archive_depth:
            child = ctx.recurse(inner, data)
            if child is not None:
                result.children.append(child)
