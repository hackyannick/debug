"""Parser für Java-Class-Dateien: Klassen, Methoden, Felder, Referenzen und Konstanten."""

from __future__ import annotations

import struct

from magicbox.model import AnalysisResult, Section, Table

from .base import Analyzer, Context, clip

ACC = [(0x0001, "public"), (0x0002, "private"), (0x0004, "protected"), (0x0008, "static"),
       (0x0010, "final"), (0x0020, "synchronized"), (0x0100, "native"), (0x0400, "abstract")]
CLASS_ACC = [(0x0001, "public"), (0x0010, "final"), (0x0200, "interface"), (0x0400, "abstract"),
             (0x2000, "annotation"), (0x4000, "enum")]
JAVA_VERSIONS = {45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4", 49: "5", 50: "6", 51: "7", 52: "8"}

INTERESTING = ("java/net/", "java/lang/Runtime", "java/lang/ProcessBuilder", "java/lang/reflect/",
               "javax/crypto/", "java/security/", "java/io/File", "java/sql/", "javax/script/",
               "java/lang/ClassLoader", "sun/misc/Unsafe")


def _desc_to_java(desc: str) -> str:
    """Wandelt einen JVM-Deskriptor wie ``(ILjava/lang/String;)V`` in lesbare Form."""
    prim = {"B": "byte", "C": "char", "D": "double", "F": "float", "I": "int", "J": "long",
            "S": "short", "Z": "boolean", "V": "void"}

    def parse(i: int) -> tuple[str, int]:
        dims = 0
        while desc[i] == "[":
            dims += 1
            i += 1
        if desc[i] == "L":
            end = desc.index(";", i)
            t = desc[i + 1:end].replace("/", ".").rsplit(".", 1)[-1]
            i = end + 1
        else:
            t = prim.get(desc[i], desc[i])
            i += 1
        return t + "[]" * dims, i

    try:
        if not desc.startswith("("):
            return parse(0)[0]
        args, i = [], 1
        while desc[i] != ")":
            t, i = parse(i)
            args.append(t)
        ret, _ = parse(i + 1)
        return f"{ret} ({', '.join(args)})"
    except (IndexError, ValueError):
        return desc


def _method_sig(mods: str, name: str, desc: str) -> str:
    ret, _, args = _desc_to_java(desc).partition(" (")
    if name == "<init>":
        return f"{mods} <Konstruktor>({args[:-1]})".strip()
    if name == "<clinit>":
        return "static { … }  // statischer Initialisierer"
    return f"{mods} {ret} {name}({args[:-1]})".strip()


def parse_class(data: bytes) -> dict:
    if data[:4] != b"\xca\xfe\xba\xbe":
        raise ValueError("keine Class-Datei")
    minor, major, count = struct.unpack_from(">HHH", data, 4)
    off = 10
    cp: list = [None] * count
    i = 1
    while i < count:
        tag = data[off]
        off += 1
        if tag == 1:
            ln = struct.unpack_from(">H", data, off)[0]
            cp[i] = ("utf8", data[off + 2:off + 2 + ln].decode("utf-8", "replace"))
            off += 2 + ln
        elif tag in (3, 4):
            off += 4
        elif tag in (5, 6):
            off += 8
            i += 1
        elif tag in (7, 8, 16, 19, 20):
            cp[i] = (tag, struct.unpack_from(">H", data, off)[0])
            off += 2
        elif tag in (9, 10, 11, 12, 17, 18):
            cp[i] = (tag, struct.unpack_from(">HH", data, off))
            off += 4
        elif tag == 15:
            off += 3
        else:
            raise ValueError(f"Unbekannter Konstanten-Tag {tag}")
        i += 1

    def utf8(idx: int) -> str:
        e = cp[idx] if 0 < idx < count else None
        return e[1] if e and e[0] == "utf8" else ""

    def cls(idx: int) -> str:
        e = cp[idx] if 0 < idx < count else None
        return utf8(e[1]) if e and e[0] == 7 else ""

    access, this_c, super_c, n_if = struct.unpack_from(">HHHH", data, off)
    off += 8
    interfaces = [cls(struct.unpack_from(">H", data, off + 2 * k)[0]) for k in range(n_if)]
    off += 2 * n_if

    def members(off: int):
        n = struct.unpack_from(">H", data, off)[0]
        off += 2
        out = []
        for _ in range(n):
            acc, name_i, desc_i, n_attr = struct.unpack_from(">HHHH", data, off)
            off += 8
            for _ in range(n_attr):
                ln = struct.unpack_from(">I", data, off + 2)[0]
                off += 6 + ln
            mods = " ".join(m for f, m in ACC if acc & f)
            out.append((mods, utf8(name_i), utf8(desc_i)))
        return out, off

    fields, off = members(off)
    methods, off = members(off)
    strings = [utf8(e[1]) for e in cp if e and e[0] == 8]
    refs = sorted({cls(e[1][0]) for e in cp if e and e[0] in (9, 10, 11)} - {""})
    called = sorted({f"{cls(e[1][0])}.{utf8(cp[e[1][1]][1][0])}" for e in cp
                     if e and e[0] in (10, 11) and cp[e[1][1]]})
    return {
        "version": f"{major}.{minor}", "java": JAVA_VERSIONS.get(major, str(major - 44)),
        "name": cls(this_c).replace("/", "."), "super": cls(super_c).replace("/", "."),
        "interfaces": [x.replace("/", ".") for x in interfaces],
        "access": " ".join(m for f, m in CLASS_ACC if access & f),
        "fields": fields, "methods": methods, "strings": strings, "refs": refs, "calls": called,
    }


class JavaClassAnalyzer(Analyzer):
    name = "java"
    kinds = ("java-class",)

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        try:
            info = parse_class(ctx.data)
        except (ValueError, struct.error, IndexError) as exc:
            result.errors.append(f"Class-Datei nicht lesbar: {exc}")
            return
        result.description = f"Java-Klasse {info['name']}"
        result.add(Section("Java-Klasse", kv={
            "Klasse": info["name"], "Erbt von": info["super"],
            "Interfaces": ", ".join(info["interfaces"]) or "–", "Modifier": info["access"] or "–",
            "Class-Version": f"{info['version']} (Java {info['java']})",
        }, llm_priority=0))
        sig = [_method_sig(mods, name, desc) for mods, name, desc in info["methods"]]
        fields = [f"{mods} {_desc_to_java(desc)} {name}".strip() for mods, name, desc in info["fields"]]
        outline = "\n".join(["// Felder"] + fields + ["", "// Methoden"] + sig)
        result.add(Section("Klassenstruktur (rekonstruiert)", code=outline, code_lang="java", llm_priority=0))
        if info["calls"]:
            result.add(Section("Aufgerufene Methoden", text=clip(", ".join(c.replace("/", ".") for c in info["calls"]), 5000),
                               llm_priority=1))
        if info["strings"]:
            result.add(Section("String-Konstanten", code="\n".join(clip(s, 200) for s in info["strings"][:200]),
                               code_lang="text", llm_priority=2))
        hits = sorted({r for r in info["refs"] if r.startswith(INTERESTING)})
        if hits:
            result.add(Section("Sicherheitsrelevante APIs",
                               table=Table(["Klasse"], [[h.replace("/", ".")] for h in hits]), llm_priority=0))
            if any(h.startswith(("java/lang/Runtime", "java/lang/ProcessBuilder")) for h in hits):
                result.find("low", "Startet externe Prozesse", "Nutzt Runtime.exec/ProcessBuilder.")
            if any(h.startswith("java/lang/ClassLoader") or h.startswith("sun/misc/Unsafe") for h in hits):
                result.find("medium", "Dynamisches Nachladen von Code", "Nutzt ClassLoader/Unsafe.")
