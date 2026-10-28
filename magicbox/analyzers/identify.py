"""Dateityp-Erkennung über Magic Bytes, Hashes und Entropie."""

from __future__ import annotations

import hashlib
import struct

from magicbox.model import AnalysisResult, Section

from .base import Analyzer, Context, fast_entropy, human_size

SOURCE_EXTENSIONS = {
    ".py": "python", ".pyw": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".jsx": "javascript", ".java": "java", ".kt": "kotlin",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".cs": "csharp", ".go": "go",
    ".rs": "rust", ".rb": "ruby", ".php": "php", ".pl": "perl", ".lua": "lua", ".sh": "bash",
    ".bash": "bash", ".zsh": "bash", ".ps1": "powershell", ".psm1": "powershell", ".bat": "batch",
    ".cmd": "batch", ".vbs": "vbscript", ".sql": "sql", ".swift": "swift", ".scala": "scala",
    ".html": "html", ".htm": "html", ".css": "css", ".xml": "xml", ".json": "json", ".yaml": "yaml",
    ".yml": "yaml", ".toml": "toml", ".ini": "ini", ".cfg": "ini", ".conf": "ini", ".md": "markdown",
    ".txt": "text", ".csv": "csv", ".asm": "asm", ".s": "asm", ".r": "r", ".dart": "dart",
    ".groovy": "groovy", ".gradle": "groovy", ".dockerfile": "dockerfile", ".tf": "hcl",
}

SHEBANGS = {
    "python": "python", "node": "javascript", "bash": "bash", "sh": "bash", "zsh": "bash",
    "perl": "perl", "ruby": "ruby", "php": "php", "pwsh": "powershell", "lua": "lua",
}


def _looks_like_text(data: bytes) -> bool:
    sample = data[:65536]
    if not sample:
        return True
    if b"\x00" in sample:
        # UTF-16 mit BOM ist ok
        return sample[:2] in (b"\xff\xfe", b"\xfe\xff")
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError as exc:
        if exc.start >= len(sample) - 4:  # abgeschnittenes Multibyte-Zeichen am Ende
            return True
    printable = sum(32 <= b < 127 or b in (9, 10, 13) or b >= 0xA0 for b in sample)
    return printable / len(sample) > 0.95


def detect(data: bytes, name: str) -> tuple[str, str]:
    """Liefert (kind, Beschreibung)."""
    lower = name.lower()
    head = data[:64]

    if head[:2] == b"MZ":
        if len(data) > 0x40:
            off = struct.unpack_from("<I", data, 0x3C)[0]
            if off + 4 <= len(data) and data[off:off + 4] == b"PE\0\0":
                return "pe", "Windows PE (EXE/DLL/SYS)"
        return "dos", "DOS-Executable (MZ)"
    if head[:4] == b"\x7fELF":
        return "elf", "ELF (Linux/Unix-Binary)"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        return "macho", "Mach-O (macOS/iOS-Binary)"
    if head[:4] == b"\xca\xfe\xba\xbe" and len(data) >= 8:
        # Java-Class und Fat-Mach-O teilen sich die Magic. Fat: kleine Anzahl Architekturen.
        n = struct.unpack_from(">I", data, 4)[0]
        if n < 30:
            return "macho", "Mach-O Universal Binary (Fat)"
        return "java-class", "Java Class-Datei"
    if head[:4] == b"dex\n":
        return "dex", "Android DEX (Dalvik Bytecode)"
    if head[:4] == b"\0asm":
        return "wasm", "WebAssembly-Modul"
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06":
        return "zip", "ZIP-Archiv"
    if head[:2] == b"\x1f\x8b":
        return "gzip", "GZIP-komprimiert"
    if head[:3] == b"BZh":
        return "bzip2", "BZIP2-komprimiert"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz", "XZ-komprimiert"
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar", "TAR-Archiv"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z", "7-Zip-Archiv"
    if head[:4] == b"Rar!":
        return "rar", "RAR-Archiv"
    if head[:5] == b"{\\rtf" or head[:4] == b"{\\rt":
        return "rtf", "RTF-Dokument"
    if head[:5] == b"%PDF-":
        return "pdf", "PDF-Dokument"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole", "OLE/Compound File (altes Office, MSI …)"
    if head[:16] == b"SQLite format 3\0":
        return "sqlite", "SQLite-Datenbank"
    if head[:8] == b"\x89PNG\r\n\x1a\n":
        return "image", "PNG-Bild"
    if head[:3] == b"\xff\xd8\xff":
        return "image", "JPEG-Bild"
    if head[:6] in (b"GIF87a", b"GIF89a"):
        return "image", "GIF-Bild"
    if lower.endswith((".pyc", ".pyo")) and head[2:4] == b"\r\n":
        return "pyc", "Python-Bytecode (.pyc)"
    if _looks_like_text(data):
        lang = source_language(data, name)
        if lang and lang not in ("text", "csv", "markdown"):
            return "source", f"Quelltext/Skript ({lang})"
        return "text", "Textdatei"
    return "unknown", "Unbekanntes Binärformat"


def source_language(data: bytes, name: str) -> str:
    lower = name.lower()
    for ext, lang in SOURCE_EXTENSIONS.items():
        if lower.endswith(ext):
            return lang
    if lower in ("dockerfile", "makefile"):
        return lower
    first = data[:200].split(b"\n", 1)[0]
    if first.startswith(b"#!"):
        interp = first[2:].decode("latin-1").strip().split()
        if interp:
            prog = interp[-1] if interp[0].endswith("env") and len(interp) > 1 else interp[0]
            prog = prog.rsplit("/", 1)[-1]
            for key, lang in SHEBANGS.items():
                if prog.startswith(key):
                    return lang
            return "bash"
    return ""


class IdentifyAnalyzer(Analyzer):
    name = "identify"

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        data = ctx.data
        result.kind, result.description = detect(data, ctx.path.name)
        result.hashes = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        result.entropy = round(fast_entropy(data), 3)

        if result.entropy > 7.5 and result.kind not in ("zip", "gzip", "bzip2", "xz", "7z", "rar", "image"):
            result.find("medium", "Sehr hohe Entropie",
                        f"Entropie {result.entropy:.2f}/8 – Inhalt ist vermutlich komprimiert, verschlüsselt oder gepackt.")

        result.add(Section(
            "Datei-Steckbrief",
            kv={
                "Name": ctx.path.name,
                "Größe": f"{human_size(len(data))} ({len(data):,} Bytes)".replace(",", "."),
                "Typ": result.description,
                "Entropie": f"{result.entropy:.2f} / 8.0",
                "MD5": result.hashes["md5"],
                "SHA-256": result.hashes["sha256"],
            },
            llm_priority=0,
        ))
