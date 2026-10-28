"""Archive & Container (ZIP/JAR/APK/Office, TAR, GZIP, BZIP2, XZ) – rekursiv und sicher im Speicher."""

from __future__ import annotations

import bz2
import gzip
import io
import lzma
import os
import subprocess
import tarfile
import tempfile
import zipfile
import zlib

from magicbox import tools
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


def _rmtree(path: str) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def tools_tail(proc) -> str:
    text = (proc.stderr or proc.stdout).strip().splitlines()
    return text[-1][:300] if text else f"Exit-Code {proc.returncode}"


class _PasswordOpener:
    """Probiert bekannte Passwörter (z. B. „infected“) für verschlüsselte ZIP-Einträge – ZipCrypto und AES."""

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.passwords = list(dict.fromkeys(ctx.settings.archive_passwords))
        self.used: str | None = None
        self._aes = None

    def _candidates(self):
        if self.used:
            yield self.used
        yield from (p for p in self.passwords if p != self.used)

    def read(self, zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes | None:
        for pw in self._candidates():
            try:
                data = zf.read(info, pwd=pw.encode())
                self.used = pw
                return data
            except NotImplementedError:  # AES (WinZip/7-Zip) – Standardbibliothek kann das nicht
                return self._read_aes(info)
            except (RuntimeError, zipfile.BadZipFile, zlib.error, OSError):
                continue
        return None

    def _read_aes(self, info: zipfile.ZipInfo) -> bytes | None:
        try:
            import pyzipper
        except ImportError:
            return self._read_7z(info)
        if self._aes is None:
            self._aes = pyzipper.AESZipFile(io.BytesIO(self.ctx.data))
        for pw in self._candidates():
            try:
                data = self._aes.read(info.filename, pwd=pw.encode())
                self.used = pw
                return data
            except (RuntimeError, zipfile.BadZipFile, zlib.error, OSError, NotImplementedError):
                continue
        return None

    def _read_7z(self, info: zipfile.ZipInfo) -> bytes | None:
        exe = tools.which(self.ctx.settings.sevenzip_path) or tools.which("7zz") or tools.which("7za")
        if not exe:
            return None
        with tempfile.TemporaryDirectory(prefix="magicbox_zip_") as tmp:
            archive = os.path.join(tmp, "a.zip")
            with open(archive, "wb") as f:
                f.write(self.ctx.data)
            for pw in self._candidates():
                try:  # Binärausgabe über stdout -> nicht tools.run (das dekodiert Text)
                    proc = subprocess.run([exe, "e", "-so", "-bd", f"-p{pw}", archive, info.filename],
                                          capture_output=True, timeout=120, stdin=subprocess.DEVNULL)
                except subprocess.TimeoutExpired:
                    return None
                if proc.returncode == 0:
                    self.used = pw
                    return proc.stdout
        return None


class ArchiveAnalyzer(Analyzer):
    name = "archive"
    kinds = ("zip", "tar", "gzip", "bzip2", "xz", "7z", "rar")

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        s = ctx.settings
        if result.kind in ("gzip", "bzip2", "xz"):
            self._stream(ctx, result)
            return
        members: list[tuple[str, int, bytes | None]] = []
        try:
            if result.kind == "zip":
                members = self._zip(ctx, result)
            elif result.kind in ("7z", "rar"):
                members = self._sevenzip(ctx, result)
            else:
                members = self._tar(ctx, result)
        except (zipfile.BadZipFile, tarfile.TarError, EOFError, OSError) as exc:
            result.errors.append(f"Archiv beschädigt: {exc}")
            return

        names = {m[0] for m in members}
        ctype = _container_type(names) if result.kind == "zip" else None
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
        out, skipped, locked = [], 0, []
        opener = _PasswordOpener(ctx)
        with zipfile.ZipFile(io.BytesIO(ctx.data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                data = None
                if not take(info.file_size):
                    skipped += 1
                elif info.flag_bits & 0x1:
                    data = opener.read(zf, info)
                    if data is None:
                        locked.append(info.filename)
                else:
                    try:
                        data = zf.read(info)
                    except NotImplementedError:
                        data = opener.read(zf, info)  # z. B. Deflate64 – evtl. kann 7-Zip helfen
                    except (zipfile.BadZipFile, RuntimeError, OSError, zlib.error) as exc:
                        result.errors.append(f"{info.filename}: {exc}")
                out.append((info.filename, info.file_size, data))
                ratio = info.file_size / max(1, info.compress_size)
                if ratio > 200 and info.file_size > 50 * 1024 * 1024:
                    result.find("high", "Verdacht auf ZIP-Bombe", f"{info.filename}: Kompressionsrate {ratio:.0f}:1")
        if opener.used:
            result.find("info", "Passwortgeschütztes Archiv geöffnet", f"Passwort: „{opener.used}“")
        if locked:
            result.find("low", "Passwortgeschützte Einträge",
                        f"{len(locked)} Datei(en) ließen sich mit keinem bekannten Passwort öffnen "
                        "(Passwort beim Hochladen angeben oder in den Einstellungen ergänzen).")
        if skipped:
            result.find("info", "Limit erreicht", f"{skipped} Einträge wurden wegen Größen-/Anzahl-Limits nicht entpackt.")
        return out

    def _sevenzip(self, ctx: Context, result: AnalysisResult):
        """7z/RAR (und Fallback für exotische ZIPs) über die 7-Zip-Kommandozeile, inkl. Passwortversuche."""
        exe = tools.which(ctx.settings.sevenzip_path) or tools.which("7zz") or tools.which("7za")
        if not exe:
            result.find("info", f"{result.kind.upper()}-Archiv nicht entpackt", "7-Zip ist nicht installiert (apt install p7zip-full).")
            return []
        limit, max_members = ctx.settings.max_extract_bytes, ctx.settings.max_archive_members
        with tempfile.TemporaryDirectory(prefix="magicbox_7z_") as tmp:
            archive = os.path.join(tmp, "archiv")
            with open(archive, "wb") as f:
                f.write(ctx.data)
            outdir = os.path.join(tmp, "out")
            for pw in [None] + list(ctx.settings.archive_passwords):
                pw_arg = f"-p{pw}" if pw else "-pMAGICBOX-KEIN-PASSWORT"
                try:
                    listing = tools.run([exe, "l", "-slt", "-bd", pw_arg, archive], timeout=120)
                except subprocess.TimeoutExpired:
                    result.errors.append("7-Zip: Zeitlimit beim Auflisten")
                    return []
                sizes = [int(l.split("=", 1)[1]) for l in listing.stdout.splitlines()
                         if l.startswith("Size = ") and l.split("=", 1)[1].strip().isdigit()]
                if sum(sizes) > limit:
                    result.find("medium", "Archiv zu groß zum Entpacken", f"{sum(sizes):,} Bytes entpackt – Limit {limit:,}.")
                    return []
                try:
                    proc = tools.run([exe, "x", "-y", "-bd", "-snl-", pw_arg, f"-o{outdir}", archive],
                                     timeout=ctx.settings.tool_timeout_s)
                except subprocess.TimeoutExpired:
                    result.errors.append("7-Zip: Zeitlimit beim Entpacken")
                    return []
                if proc.returncode == 0:
                    if pw:
                        result.find("info", "Passwortgeschütztes Archiv geöffnet", f"Passwort: „{pw}“")
                    break
                _rmtree(outdir)
                if "Wrong password" not in proc.stdout + proc.stderr and "Can not open encrypted" not in proc.stdout + proc.stderr:
                    result.errors.append(f"7-Zip: {tools_tail(proc)}")
                    return []
            else:
                result.find("low", "Passwortgeschütztes Archiv", "Mit keinem bekannten Passwort zu öffnen.")
                return []
            result.tools.append("7z")
            out, total = [], 0
            for dirpath, _dirs, files in os.walk(outdir):
                for fn in sorted(files):
                    full = os.path.join(dirpath, fn)
                    rel = os.path.relpath(full, outdir).replace(os.sep, "/")
                    if os.path.islink(full):
                        out.append((f"{rel} -> (Symlink)", 0, None))
                        continue
                    size = os.path.getsize(full)
                    data = None
                    if len(out) < max_members and total + size <= limit:
                        with open(full, "rb") as f:
                            data = f.read()
                        total += size
                    out.append((rel, size, data))
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
