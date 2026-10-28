"""Extraktion und Klassifizierung von Zeichenketten aus Binärdaten."""

from __future__ import annotations

import re

from magicbox.model import AnalysisResult, Section, Table

from .base import Analyzer, Context, clip

ASCII_RE = re.compile(rb"[\x20-\x7e\t]{5,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){5,}")

CATEGORIES: list[tuple[str, re.Pattern[str]]] = [
    ("URL", re.compile(r"\b(?:https?|ftp|wss?)://[^\s\"'<>]{4,}", re.I)),
    ("IP-Adresse", re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?::\d{1,5})?\b")),
    ("E-Mail", re.compile(r"\b[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")),
    ("Registry", re.compile(r"\b(?:HKEY_[A-Z_]+|HKLM|HKCU|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run)\\?", re.I)),
    ("Windows-Pfad", re.compile(r"(?<![A-Za-z])[A-Za-z]:\\[^\s\"*?<>|]{3,}|%[A-Z]+%\\", re.I)),
    ("Unix-Pfad", re.compile(r"(?:^|\s)(?:/(?:etc|usr|var|tmp|home|bin|sbin|opt|proc|dev|lib|root|Library|Users|System)/[\w./-]*)")),
    ("Krypto/Secrets", re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?(?:PRIVATE|PUBLIC) KEY|password|passwd|secret|api[_-]?key|token|bearer|aes|sha256|rsa", re.I)),
    ("Shell/Befehl", re.compile(r"\b(?:cmd\.exe|powershell|/bin/sh|/bin/bash|wget |curl |chmod |schtasks|reg add|net user|vssadmin|bcdedit|rundll32|regsvr32)", re.I)),
    ("Dateiendung", re.compile(r"\b[\w-]+\.(?:dll|exe|sys|so|dylib|bat|ps1|vbs|js|jar|py|dat|cfg|ini|json|db|log)\b", re.I)),
    ("Format-String", re.compile(r"%(?:\d+)?[sdxXuplf]")),
]

MAX_STRINGS = 20000


def extract_strings(data: bytes, limit: int = MAX_STRINGS) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for regex, enc in ((ASCII_RE, "ascii"), (UTF16_RE, "utf-16-le")):
        for m in regex.finditer(data):
            s = m.group().decode(enc, "replace").strip()
            if len(s) >= 5 and s not in seen:
                seen.add(s)
                out.append(s)
                if len(out) >= limit:
                    return out
    return out


def _is_noise(s: str) -> bool:
    """Filtert typischen Binär-Müll (z. B. 'AAAAAA', '@@@@@', zufällige Opcodes)."""
    if len(set(s)) <= 2:
        return True
    alnum = sum(c.isalnum() for c in s)
    if alnum / len(s) < 0.55:
        return True
    # Viele Wechsel zwischen Groß-/Kleinbuchstaben/Ziffern ohne Vokale -> Rauschen
    letters = [c for c in s if c.isalpha()]
    if len(s) < 8 and letters and not any(c in "aeiouAEIOU" for c in letters):
        return True
    return False


WELL_KNOWN_IPS = {"1.1.1.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "127.0.0.1", "0.0.0.0"}


def _plausible_ip(s: str) -> bool:
    """Versionsnummern wie 1.2.0.14 sehen aus wie IPs – diese aussortieren."""
    for m in CATEGORIES[1][1].finditer(s):
        ip = m.group().split(":")[0]
        if ip in WELL_KNOWN_IPS:
            return True
        octets = [int(x) for x in ip.split(".")]
        if "version" in s.lower() or octets[0] == 0 or (octets[0] < 10 and all(o <= 20 for o in octets)):
            continue
        return True
    return False


def classify(strings: list[str]) -> dict[str, list[str]]:
    cats: dict[str, list[str]] = {}
    for s in strings:
        for name, rx in CATEGORIES:
            if rx.search(s) and (name != "IP-Adresse" or _plausible_ip(s)):
                bucket = cats.setdefault(name, [])
                if len(bucket) < 60:
                    bucket.append(s)
    return cats


class StringsAnalyzer(Analyzer):
    name = "strings"
    kinds = ("pe", "elf", "macho", "dos", "unknown", "java-class", "dex", "wasm", "pyc", "ole", "sqlite", "pdf")

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        strings = extract_strings(ctx.data)
        useful = [s for s in strings if not _is_noise(s)]
        ctx.facts["strings"] = useful
        cats = classify(useful)

        if cats:
            rows = [[name, str(len(items)), clip(" · ".join(items[:6]), 300)] for name, items in cats.items()]
            result.add(Section("Auffällige Zeichenketten (kategorisiert)",
                               table=Table(["Kategorie", "Anzahl", "Beispiele"], rows), llm_priority=1))
            ctx.facts["string_categories"] = cats
            if "URL" in cats or "IP-Adresse" in cats:
                result.find("info", "Netzwerkadressen im Binary",
                            ", ".join((cats.get("URL", []) + cats.get("IP-Adresse", []))[:5]))
            if any("PRIVATE KEY" in s for s in cats.get("Krypto/Secrets", [])):
                result.find("high", "Privater Schlüssel eingebettet", "Die Datei enthält einen PEM-Private-Key.")

        # Die „interessantesten“ Strings: länger, lesbar, mit Leerzeichen (Meldungen, Texte)
        ranked = sorted(useful, key=lambda s: (-(" " in s), -min(len(s), 80)))
        sample = [clip(s, 160) for s in ranked[:250]]
        result.add(Section(
            f"Zeichenketten (Auswahl, {len(sample)} von {len(useful)} lesbaren)",
            code="\n".join(sample), code_lang="text", llm_priority=4,
        ))
