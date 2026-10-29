"""Einfache Deobfuskation: kodierte PowerShell-Befehle, Base64- und Hex-Blobs dekodieren.

Gefundene Inhalte werden als eigene „Dateien“ rekursiv analysiert – so landet z. B. eine in einem Skript
versteckte EXE oder ein zweites Skript-Stadium automatisch im Bericht.
"""

from __future__ import annotations

import base64
import binascii
import re

from magicbox.model import AnalysisResult, Section, Table

from .base import Analyzer, Context, clip
from .identify import detect
from .source import _decode

PS_ENC = re.compile(r"-(?:e|ec|en|enc|enco|encodedcommand)\s+[\"']?([A-Za-z0-9+/]{16,}={0,2})", re.I)
B64_BLOB = re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")
HEX_BLOB = re.compile(r"(?<![A-Za-z0-9+/])(?:[0-9a-fA-F]{2}){64,}(?![A-Za-z0-9+/])")
MAX_DECODED = 8


def _b64(s: str) -> bytes | None:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _interesting(data: bytes) -> str | None:
    """Gibt den erkannten Typ zurück, wenn sich die dekodierten Daten lohnen."""
    if len(data) < 16:
        return None
    kind, desc = detect(data, "decoded")
    if kind in ("text", "source"):
        sample = data[:4096]
        ascii_ratio = sum(32 <= b < 127 or b in (9, 10, 13) for b in sample) / len(sample)
        return desc if ascii_ratio > 0.9 else None
    return desc if kind != "unknown" else None


class DeobfuscationAnalyzer(Analyzer):
    name = "deobfuscate"
    malware_only = True
    kinds = ()

    def matches(self, ctx: Context, result: AnalysisResult) -> bool:
        # Text/Skripte direkt; sonst nur extrahierter Text (.NET-String-Literale, Makro-Code …)
        return result.kind in ("source", "text") or bool(ctx.facts.get("extra_strings"))

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        if result.kind in ("source", "text"):
            text = _decode(ctx.data)
        else:
            text = "\n".join(ctx.facts.get("extra_strings", []))
        found: list[tuple[str, str, bytes]] = []  # (Methode, Vorschau, Daten)
        seen: set[bytes] = set()

        for m in PS_ENC.finditer(text):
            raw = _b64(m.group(1))
            if raw:
                cmd = raw.decode("utf-16-le", "replace")
                found.append(("PowerShell -EncodedCommand", cmd, cmd.encode()))
                seen.add(raw)
        for m in B64_BLOB.finditer(text):
            raw = _b64(m.group())
            if raw and raw not in seen:
                desc = _interesting(raw)
                if desc:
                    found.append((f"Base64 → {desc}", "", raw))
                    seen.add(raw)
        for m in HEX_BLOB.finditer(text):
            try:
                raw = bytes.fromhex(m.group())
            except ValueError:
                continue
            desc = _interesting(raw)
            if desc and raw not in seen:
                found.append((f"Hex → {desc}", "", raw))
                seen.add(raw)
            if len(found) >= MAX_DECODED:
                break

        if not found:
            return
        rows = []
        for i, (method, preview, raw) in enumerate(found[:MAX_DECODED], 1):
            if not preview:
                preview = raw[:120].decode("latin-1").translate({c: "." for c in range(32)})
            rows.append([str(i), method, f"{len(raw):,}", clip(preview.replace("\n", " "), 200)])
        result.add(Section("Dekodierte/versteckte Inhalte", table=Table(["#", "Methode", "Bytes", "Vorschau"], rows),
                           llm_priority=0))
        result.find("medium", "Versteckte (kodierte) Inhalte gefunden",
                    f"{len(found)} kodierte Abschnitte dekodiert – siehe eingebettete Einträge.")
        if ctx.recurse is None:
            return
        for i, (method, _preview, raw) in enumerate(found[:MAX_DECODED], 1):
            ext = ".ps1" if method.startswith("PowerShell") else ".bin"
            child = ctx.recurse(f"{ctx.path.name} [dekodiert #{i}]{ext}", raw)
            if child is not None:
                result.children.append(child)
