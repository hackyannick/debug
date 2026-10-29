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
    ("Krypto/Secrets", re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?(?:PRIVATE|PUBLIC) KEY|\b(?:password|passwd|secret|"
                                  r"api[_-]?key|access[_-]?token|token|bearer|aes-?\d{3}|sha-?256|rsa)\b", re.I)),
    ("Shell/Befehl", re.compile(r"\b(?:cmd\.exe|powershell|/bin/sh|/bin/bash|wget |curl |chmod |schtasks|reg add|net user|vssadmin|bcdedit|rundll32|regsvr32)", re.I)),
    ("Dateiendung", re.compile(r"\b[\w-]+\.(?:dll|exe|sys|so|dylib|bat|ps1|vbs|js|jar|py|dat|cfg|ini|json|db|log)\b", re.I)),
    ("Format-String", re.compile(r"[A-Za-z]{3,}[^%]{0,40}%(?:\d+)?[sdxXuplf]\b|%(?:\d+)?[sdxXuplf][^%]{0,40}[A-Za-z]{3,}")),
]

MAX_STRINGS = 20000
WINDOWS = 16  # große Dateien: gleichmäßig verteilt lesen statt nur den Anfang (meist Code)
# Ein mov-Befehl mit 8-Byte-Konstante hinterlässt Textstücke wie "Decoder H" / "ded dataH" (H = REX.W-Präfix)
_IMMEDIATE_RE = re.compile(r"^.{6,8}[HILM]$")
_CODE_RE = re.compile(r"[HL][9;]|[DL]\$|\$[0-9A-F@]|[A-Za-z]\d[A-Za-z]\d|\bt[A-Z][A-Z0-9]|u[A-Z]{2}\b|[HL]c[A-Z]|\s[A-Z]\d$")


def extract_strings(data: bytes, limit: int = MAX_STRINGS) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    if len(data) > 32 * 1024 * 1024:
        step = len(data) // WINDOWS
        windows = [(i * step, i * step + step) for i in range(WINDOWS)]
        per_window = max(1, limit // WINDOWS)
    else:
        windows, per_window = [(0, len(data))], limit
    for start, end in windows:
        chunk, found = data[start:end], 0
        for regex, enc in ((ASCII_RE, "ascii"), (UTF16_RE, "utf-16-le")):
            for m in regex.finditer(chunk):
                s = m.group().decode(enc, "replace").strip()
                if len(s) >= 5 and s not in seen:
                    seen.add(s)
                    out.append(s)
                    found += 1
                    if found >= per_window or len(out) >= limit:
                        break
            if found >= per_window or len(out) >= limit:
                break
    return out


def _is_noise(s: str) -> bool:
    """Filtert typischen Binär-Müll (z. B. 'AAAAAA', '@@@@@', zufällige Opcodes, Code-Fragmente)."""
    if len(set(s)) <= 2:
        return True
    alnum = sum(c.isalnum() for c in s)
    if alnum / len(s) < 0.55:
        return True
    if not re.search(r"[A-Za-z]{3,}", s):
        return True
    if _IMMEDIATE_RE.match(s) and any(c.islower() or c == " " for c in s[:-1]):
        return True
    if len(s) <= 6 and s[-1].isupper() and s[-2].islower():  # z. B. "tersA"
        return True
    if len(s) < 24 and _CODE_RE.search(s) and not re.search(r"[A-Za-z]{5,}", s):
        return True
    # Viele Wechsel zwischen Groß-/Kleinbuchstaben/Ziffern ohne Vokale -> Rauschen
    letters = [c for c in s if c.isalpha()]
    if len(s) < 8 and letters and not any(c in "aeiouAEIOU" for c in letters):
        return True
    return False


WELL_KNOWN_IPS = {"1.1.1.1": "Cloudflare-DNS", "1.0.0.1": "Cloudflare-DNS", "8.8.8.8": "Google-DNS",
                  "8.8.4.4": "Google-DNS", "9.9.9.9": "Quad9-DNS", "149.112.112.112": "Quad9-DNS",
                  "208.67.222.222": "OpenDNS", "127.0.0.1": "eigener Rechner", "0.0.0.0": "beliebige Adresse"}


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


_WORD_RE = re.compile(r"[A-Za-zÄÖÜäöüß][a-zäöüß'’]{1,14}[,.:;!?)]?")


def _readability(s: str) -> tuple:
    """Sortierschlüssel: natürliche Sätze/Meldungen zuerst, aneinandergeklebte Bezeichner-Tabellen zuletzt."""
    tokens = s.split()
    words = sum(1 for t in tokens if _WORD_RE.fullmatch(t.strip("(\"'")))
    density = words / max(1.0, len(s) / 7)  # in normalem Text ~ ein Wort pro 6–7 Zeichen
    natural = words >= 2 and density >= 0.45
    return (not natural, -min(words, 10), -min(len(s), 80))


# Für diese Kategorien nur den gefundenen Wert zeigen, nicht die ganze Zeichenkette
VALUE_ONLY = {"URL", "IP-Adresse", "E-Mail"}


def classify(strings: list[str]) -> dict[str, list[str]]:
    cats: dict[str, list[str]] = {}
    for s in strings:
        for name, rx in CATEGORIES:
            m = rx.search(s)
            if not m or (name == "IP-Adresse" and not _plausible_ip(s)):
                continue
            value = m.group().rstrip(".,;:)'\"") if name in VALUE_ONLY else s
            bucket = cats.setdefault(name, [])
            if len(bucket) < 60 and value not in bucket:
                bucket.append(value)
    return cats


def describe_address(value: str) -> str:
    ip = value.split(":")[0]
    return f"{value} ({WELL_KNOWN_IPS[ip]})" if ip in WELL_KNOWN_IPS else value


class StringsAnalyzer(Analyzer):
    name = "strings"
    kinds = ("pe", "elf", "macho", "dos", "unknown", "java-class", "dex", "wasm", "pyc", "ole", "sqlite", "pdf")

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        data = ctx.data
        cert = ctx.facts.get("cert_range")
        if cert and 0 < cert[0] < len(data):  # Signatur ausblenden (DigiCert-OCSP-URLs usw.)
            data = data[:cert[0]] + data[cert[0] + cert[1]:]
        strings = extract_strings(data)
        useful = [s for s in strings if not _is_noise(s)]
        ctx.facts["strings"] = useful
        cats = classify(useful)

        if cats:
            rows = [[name, str(len(items)), clip(" · ".join(items[:6]), 300)] for name, items in cats.items()]
            result.add(Section("Auffällige Zeichenketten (kategorisiert)",
                               table=Table(["Kategorie", "Anzahl", "Beispiele"], rows), llm_priority=1))
            ctx.facts["string_categories"] = cats
            if "URL" in cats or "IP-Adresse" in cats:
                addresses = [describe_address(v) for v in (cats.get("URL", []) + cats.get("IP-Adresse", []))[:6]]
                result.find("info", "Netzwerkadressen im Binary",
                            ", ".join(addresses) + " – Zeichenketten, kein Beleg für tatsächliche Verbindungen "
                            "(bekannte DNS-Server stammen meist aus eingebauten Bibliotheken).")
            if any("PRIVATE KEY" in s for s in cats.get("Krypto/Secrets", [])):
                result.find("high", "Privater Schlüssel eingebettet", "Die Datei enthält einen PEM-Private-Key.")

        # Die „interessantesten“ Strings: lesbare Wörter, Leerzeichen (Meldungen, Texte), nicht zu kurz
        ranked = sorted(useful, key=_readability)
        sample = [clip(s, 160) for s in ranked[:250]]
        result.add(Section(
            f"Zeichenketten (Auswahl, {len(sample)} von {len(useful)} lesbaren)",
            code="\n".join(sample), code_lang="text", llm_priority=4,
        ))
