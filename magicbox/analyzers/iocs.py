"""Extraktion von Indicators of Compromise (IOCs): URLs, Domains, IPs, E-Mails, Registry, Pfade, Wallets, Hashes."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from magicbox.model import AnalysisResult

from .base import Analyzer, Context
from .source import _decode
from .strings import _plausible_ip

TLDS = ("com|net|org|info|biz|io|co|me|ru|su|cn|tk|ml|ga|cf|gq|pw|cc|ws|xyz|top|online|site|club|shop|live|app|dev|"
        "link|onion|de|at|ch|uk|fr|it|nl|pl|ua|br|in|ir|kp|tr|us|eu|to|gg|ly|vn|kr|jp|tw|hk|sg|pk|ng|za|"
        "cloud|host|space|website|tech|store|fun|icu|buzz|monster|rest|cyou|cfd|sbs|lol|bond")
URL_RE = re.compile(r"\b(?:https?|ftp|wss?|tcp|udp)://[^\s\"'<>`|\\^{}]{3,}", re.I)
DOMAIN_RE = re.compile(rf"(?<![@\w.-])((?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{TLDS}))(?![\w.-]*\()(?![\w-])")
IP_RE = re.compile(r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b")
REG_RE = re.compile(r"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)|HKLM|HKCU)\\[^\s\"'<>|]{3,}", re.I)
REG_SOFT_RE = re.compile(r"\bSoftware\\(?:Microsoft|Classes|Wow6432Node|Policies)\\[^\s\"'<>|]{3,}", re.I)
WINPATH_RE = re.compile(r"(?:%(?:APPDATA|LOCALAPPDATA|TEMP|TMP|USERPROFILE|PROGRAMDATA|WINDIR|SYSTEMROOT|PUBLIC)%|"
                        r"(?<![A-Za-z])[A-Za-z]:)\\[^\s\"'<>|*?]{3,}", re.I)
BTC_RE = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
XMR_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{64}|[a-fA-F0-9]{40}|[a-fA-F0-9]{32})\b")

CODE_PREFIXES = ("system.", "microsoft.", "java.", "javax.", "android.", "androidx.", "org.apache.", "com.google.",
                 "com.android.", "this.", "self.", "window.", "document.", "console.", "math.", "json.", "os.",
                 "sys.", "re.", "np.", "pd.", "kotlin.", "dalvik.", "sun.", "jdk.", "schemas.microsoft.com",
                 "schemas.openxmlformats.org", "www.w3.org", "purl.org", "ns.adobe.com")
BENIGN_DOMAINS = ("w3.org", "schemas.microsoft.com", "openxmlformats.org", "xmlsoap.org", "adobe.com/xap",
                  "purl.org", "apache.org/xml", "microsoft.com/pki", "digicert.com", "verisign.com", "symantec.com",
                  "globalsign.com", "sectigo.com", "usertrust.com", "comodoca.com", "entrust.net", "thawte.com",
                  "upx.sf.net", "upx.github.io")


def _clean_url(u: str) -> str:
    return u.rstrip(".,;:)]}'\"")


def extract(text: str, aggressive: bool) -> dict[str, list[str]]:
    """``aggressive`` = auch fehleranfällige Typen (Hashes, Legacy-Bitcoin) – nur für Text/Quelltext sinnvoll."""
    out: dict[str, list[str]] = {}

    def add(kind: str, value: str):
        lst = out.setdefault(kind, [])
        if value not in lst:
            lst.append(value)

    urls = [_clean_url(u) for u in URL_RE.findall(text)]
    for u in urls:
        add("URL", u)
        host = urlsplit(u).hostname or ""
        if host and not IP_RE.fullmatch(host):
            add("Domain", host.lower())
    for d in DOMAIN_RE.findall(text):
        if d.startswith(CODE_PREFIXES) or any(d.endswith(b) for b in BENIGN_DOMAINS):
            continue
        if not any(len(label) >= 3 for label in d.split(".")[:-1]):
            continue
        add("Domain", d)
    for line_ip in IP_RE.findall(text):
        if line_ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255") and _plausible_ip(line_ip):
            add("IPv4", line_ip)
    for e in EMAIL_RE.findall(text):
        add("E-Mail", e)
    full_keys = [r.rstrip("\\") for r in REG_RE.findall(text)]
    for r in full_keys + [k.rstrip("\\") for k in REG_SOFT_RE.findall(text)]:
        if not any(r != k and k.lower().endswith(r.lower()) for k in full_keys):
            add("Registry", r)
    for p in WINPATH_RE.findall(text):
        add("Dateipfad", p)
    for w in XMR_RE.findall(text):
        add("Krypto-Wallet", w)
    for w in BTC_RE.findall(text):
        if w.startswith("bc1") or aggressive:
            add("Krypto-Wallet", w)
    if aggressive:
        for h in HASH_RE.findall(text):
            if any(c.isdigit() for c in h) and any(c.isalpha() for c in h):
                add("Hash", h.lower())
    # Domains, die nur Teil einer E-Mail sind, nicht doppelt führen
    mail_domains = {e.split("@", 1)[1].lower() for e in out.get("E-Mail", [])}
    if "Domain" in out:
        out["Domain"] = [d for d in out["Domain"] if d not in mail_domains or d in {urlsplit(u).hostname for u in urls}]
        if not out["Domain"]:
            del out["Domain"]
    return out


class IOCAnalyzer(Analyzer):
    name = "iocs"
    malware_only = True

    def matches(self, ctx: Context, result: AnalysisResult) -> bool:
        return result.kind not in ("directory", "image", "zip", "tar", "gzip", "bzip2", "xz", "7z", "rar")

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        if result.kind in ("source", "text", "rtf"):
            text = _decode(ctx.data)
            aggressive = True
        else:
            text = "\n".join(ctx.facts.get("strings", []) + ctx.facts.get("extra_strings", []))
            aggressive = False
        for kind, values in extract(text, aggressive).items():
            for v in values:
                result.add_ioc(kind, v)
