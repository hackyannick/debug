"""Electron-Archive (``app.asar``): hier liegt die eigentliche Programmlogik einer Electron-App (JavaScript/HTML).

Aufbau: 16 Byte Kopf (Pickle) → JSON-Verzeichnis ``{"files": {...}}`` → Dateiinhalte hintereinander.
Eigene Dateien werden einzeln analysiert; ``node_modules`` (Fremdbibliotheken) nur aufgelistet.
"""

from __future__ import annotations

import json
import posixpath
import struct

from magicbox.model import AnalysisResult, Section, Table

from .base import Analyzer, Context, clip, human_size

CODE_EXT = (".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".html", ".htm", ".json", ".vue", ".svelte", ".css", ".node")
SKIP_EXT = (".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".mp3",
            ".wav", ".ogg", ".mp4", ".webm")


def parse(data: bytes) -> tuple[dict, int]:
    """→ (Verzeichnis, Startoffset der Dateiinhalte)."""
    if len(data) < 16:
        raise ValueError("zu kurz für ein ASAR-Archiv")
    _, header_size, _, json_len = struct.unpack_from("<4I", data, 0)
    header = json.loads(data[16:16 + json_len].decode("utf-8"))
    return header, 8 + header_size


def walk(node: dict, prefix: str = ""):
    """Liefert (Pfad, Eintrag) für alle Dateien."""
    for name, entry in (node.get("files") or {}).items():
        path = posixpath.join(prefix, name) if prefix else name
        if "files" in entry:
            yield from walk(entry, path)
        else:
            yield path, entry


def read(data: bytes, base: int, entry: dict) -> bytes | None:
    if entry.get("unpacked") or "link" in entry:
        return None
    try:
        offset, size = base + int(entry["offset"]), int(entry["size"])
    except (KeyError, TypeError, ValueError):
        return None
    if offset < 0 or offset + size > len(data):
        return None
    return data[offset:offset + size]


class AsarAnalyzer(Analyzer):
    name = "asar"
    kinds = ("asar",)

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        s = ctx.settings
        try:
            header, base = parse(ctx.data)
        except (ValueError, struct.error, UnicodeDecodeError) as exc:
            result.errors.append(f"ASAR nicht lesbar: {exc}")
            return
        entries = list(walk(header))
        own = [(p, e) for p, e in entries if "node_modules/" not in f"/{p}"]
        modules = [(p, e) for p, e in entries if "node_modules/" in f"/{p}"]
        unpacked = [p for p, e in entries if e.get("unpacked")]

        entry = dict(entries).get("package.json")
        pkg = package_info(read(ctx.data, base, entry) if entry else None, result)
        main = posixpath.normpath(pkg.get("main", "index.js")) if pkg else "index.js"

        kv = {"Dateien gesamt": str(len(entries)), "Eigene Dateien": str(len(own)),
              "Fremdbibliotheken (node_modules)": str(len(modules))}
        if unpacked:
            kv["Ausgelagert (app.asar.unpacked)"] = f"{len(unpacked)} Datei(en), z. B. {clip(', '.join(unpacked[:5]), 200)}"
        result.add(Section("ASAR-Archiv (Electron-App)", kv=kv, llm_priority=0))
        rows = [[p, human_size(int(e.get("size", 0) or 0))] for p, e in own[:500]]
        result.add(Section(f"Eigene Dateien ({len(own)})", table=Table(["Pfad", "Größe"], rows, total=len(own)),
                           llm_priority=1))
        modules_table([(p, read(ctx.data, base, e)) for p, e in modules if is_manifest(p)], pkg, result)

        if ctx.recurse is None or ctx.depth >= s.max_archive_depth:
            return

        budget, taken = s.max_extract_bytes, 0
        ranked = sorted(own, key=lambda item: rank(item[0], int(item[1].get("size", 0) or 0), "", main))
        for path, entry in ranked[: s.max_archive_members]:
            if path.lower().endswith(SKIP_EXT):
                continue
            blob = read(ctx.data, base, entry)
            if blob is None or taken + len(blob) > budget:
                continue
            taken += len(blob)
            child = ctx.recurse(path, blob)
            if child is not None:
                result.children.append(child)


# ---------------------------------------------------------------------- gemeinsam für ASAR und App-Ordner (ZIP)

def rank(path: str, size: int, root: str, main: str) -> tuple:
    """Reihenfolge: package.json, Startdatei, Code, Rest – jeweils größte zuerst."""
    rel = path[len(root):] if path.startswith(root) else path
    low = rel.lower()
    return (low != "package.json", posixpath.normpath(rel) != main, not low.endswith(CODE_EXT), -size)


def is_manifest(path: str) -> bool:
    """node_modules/<paket>/package.json bzw. node_modules/@scope/<paket>/package.json (nicht verschachtelt)."""
    if path.count("node_modules/") != 1:
        return False
    parts = path.split("node_modules/")[-1].split("/")
    n = 2 if parts[0].startswith("@") else 1
    return parts[n:] == ["package.json"]


def node_app_root(names) -> str | None:
    """Ordner mit der obersten package.json außerhalb von node_modules (z. B. "resources/app/") – sonst None."""
    roots = [n[: -len("package.json")] for n in names
             if n.endswith("package.json") and (n == "package.json" or n.endswith("/package.json"))
             and "node_modules/" not in n]
    return min(roots, key=lambda r: (r.count("/"), len(r))) if roots else None


def wanted(name: str) -> bool:
    """Was aus einem App-Ordner gelesen werden soll: eigene Dateien und die Steckbriefe der npm-Pakete."""
    if "node_modules/" in name:
        return is_manifest(name)
    return not name.lower().endswith(SKIP_EXT)


def package_info(blob: bytes | None, result: AnalysisResult) -> dict:
    if not blob:
        return {}
    try:
        pkg = json.loads(blob.decode("utf-8-sig"))
    except (ValueError, UnicodeDecodeError):
        return {}
    if not isinstance(pkg, dict):
        return {}
    author = pkg.get("author")
    if isinstance(author, dict):
        author = author.get("name", "")
    kv = {k: clip(str(v), 300) for k, v in (
        ("Name", pkg.get("productName") or pkg.get("name")), ("Paketname", pkg.get("name")),
        ("Version", pkg.get("version")), ("Beschreibung", pkg.get("description")), ("Autor", author),
        ("Startdatei (main)", pkg.get("main")), ("Homepage", pkg.get("homepage")), ("Lizenz", pkg.get("license")),
    ) if v}
    result.add(Section("App-Steckbrief (package.json)", kv=kv, llm_priority=0))
    for key, label in (("Name", "Produkt"), ("Version", "Version"), ("Beschreibung", "Beschreibung"),
                       ("Autor", "Hersteller")):
        if kv.get(key):
            result.product[label] = kv[key]
    scripts = pkg.get("scripts")
    if isinstance(scripts, dict) and scripts:
        result.add(Section("npm-Skripte", kv={k: clip(str(v), 200) for k, v in list(scripts.items())[:30]},
                           llm_priority=3))
    return pkg


def is_electron(pkg: dict) -> bool:
    deps = {**(pkg.get("dependencies") or {}), **(pkg.get("devDependencies") or {})} if pkg else {}
    return any(k in deps for k in ("electron", "electron-builder", "electron-updater", "@electron/remote"))


def modules_table(manifests: list[tuple[str, bytes | None]], pkg: dict, result: AnalysisResult) -> None:
    """Fremdbibliotheken: Name + Version + Beschreibung aus node_modules/<paket>/package.json."""
    rows = []
    for path, blob in manifests:
        parts = path.split("node_modules/")[-1].split("/")
        name = "/".join(parts[: 2 if parts[0].startswith("@") else 1])
        try:
            info = json.loads(blob.decode("utf-8-sig")) if blob else {}
        except (ValueError, UnicodeDecodeError):
            info = {}
        if not isinstance(info, dict):
            info = {}
        rows.append([name, str(info.get("version", "")), clip(str(info.get("description", "")), 120)])
    if not rows and pkg and isinstance(pkg.get("dependencies"), dict):
        rows = [[d, str(v), ""] for d, v in pkg["dependencies"].items()]
    if rows:
        rows.sort(key=lambda r: r[0])
        result.add(Section(f"Verwendete npm-Pakete ({len(rows)})",
                           table=Table(["Paket", "Version", "Beschreibung"], rows[:300], total=len(rows)),
                           llm_priority=1))
