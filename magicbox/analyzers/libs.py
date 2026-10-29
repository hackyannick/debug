"""Erkennt Funktionen/Symbole bekannter Bibliotheken und Laufzeitumgebungen.

Große Programme (Electron, Chromium, Qt …) bestehen zu 99 % aus mitgelinkten Bibliotheken. Deren Funktionen sind für
die Doku eines Programms wertlos – Pseudocode, Exporte und KI-Kontext sollen sich auf den eigenen Code konzentrieren.
"""

from __future__ import annotations

import re
from collections import Counter

# Namensräume in C++-Symbolen: MSVC-dekoriert (…@v8@@), radare2 (…_v8__…), demangled (v8::…)
_NAMESPACES = {
    "V8 (JavaScript-Engine)": ("v8", "cppgc", "v8_inspector"),
    "Node.js": ("node",),
    "Chromium": ("base", "blink", "mojo", "gin", "content", "net", "url", "gfx", "ui", "skia", "absl", "perfetto",
                 "partition_alloc", "__cr", "webrtc", "cricket", "rtc"),
    "C++-Standardbibliothek": ("std", "__1"),
    "Qt": ("qt", "qtprivate"),
    "Boost": ("boost",),
    "ICU": ("icu", "icu_74", "icu_73", "icu_72"),
}
# C-Bibliotheken über Funktionspräfixe (nach Entfernen von sym./fcn./<datei>_)
_PREFIXES = {
    "libuv (Node.js)": ("uv_",),
    "N-API (Node.js)": ("napi_", "node_api_"),
    "zlib": ("cr_z_", "z_", "deflate", "inflate", "adler32", "crc32", "compress2", "uncompress"),
    "OpenSSL/BoringSSL": ("ssl_", "evp_", "crypto_", "bn_", "x509_", "rsa_", "ec_key_", "err_", "bio_", "openssl_"),
    "FFmpeg": ("av_", "avcodec_", "avformat_", "avutil_", "swr_", "sws_", "avio_"),
    "SQLite": ("sqlite3_",),
    "libpng": ("png_",),
    "libjpeg": ("jpeg_",),
    "libxml2": ("xml", "htmlparse"),
    "libcurl": ("curl_",),
    "C-Laufzeit (CRT)": ("__scrt", "__acrt", "__vcrt", "_initterm", "__security_", "_crt", "__std_", "__report_",
                         "__guard", "__chkstk", "_alloca"),
}
_NS_RE = {label: re.compile(r"(?:^|[@_:.])(?:" + "|".join(map(re.escape, toks)) + r")(?:@@|__|::|@|$)", re.I)
          for label, toks in _NAMESPACES.items()}
_STRIP_RE = re.compile(r"^(?:sym\.|fcn\.|imp\.|dbg\.|method\.)*(?:[\w-]+\.(?:exe|dll|so|dylib)_+)?", re.I)


def library_of(name: str) -> str | None:
    """Bibliothek, zu der ein Symbol gehört – oder None (eigener/unbekannter Code)."""
    if not name:
        return None
    for label, rx in _NS_RE.items():
        if rx.search(name):
            return label
    core = _STRIP_RE.sub("", name).lstrip("_?").lower()
    for label, prefixes in _PREFIXES.items():
        if core.startswith(prefixes):
            return label
    return None


def split_library(names: list[str]) -> tuple[list[str], Counter]:
    """Trennt eigene Symbole von Bibliothekssymbolen; liefert (eigene, Zähler je Bibliothek)."""
    own, libs = [], Counter()
    for n in names:
        lib = library_of(n)
        if lib:
            libs[lib] += 1
        else:
            own.append(n)
    return own, libs


def describe(libs: Counter) -> str:
    return ", ".join(f"{label}: {n}" for label, n in libs.most_common())
