"""Analyse von Windows-PE-Dateien (EXE, DLL, SYS) mit ``pefile``."""

from __future__ import annotations

import datetime as dt
from collections import Counter

from magicbox.model import AnalysisResult, Section, Table

from . import disasm
from .apis import CAPABILITIES, SECURITY_ONLY, categorize
from .base import Analyzer, Context, clip, entropy
from .libs import describe, library_of

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None

MACHINES = {0x14C: ("x86 (32 Bit)", "x86"), 0x8664: ("x86-64 (64 Bit)", "x64"),
            0x1C0: ("ARM", "arm"), 0x1C4: ("ARM Thumb-2", "thumb"), 0xAA64: ("ARM64", "arm64")}
SUBSYSTEMS = {1: "Native (Treiber)", 2: "Windows GUI", 3: "Windows Konsole", 9: "Windows CE",
              10: "EFI-Anwendung", 11: "EFI Boot-Treiber", 12: "EFI Runtime-Treiber"}
PACKER_SECTIONS = {
    "UPX0": "UPX", "UPX1": "UPX", ".aspack": "ASPack", ".adata": "ASPack", ".petite": "Petite",
    ".nsp0": "NsPack", ".MPRESS1": "MPRESS", ".themida": "Themida", ".vmp0": "VMProtect",
    ".vmp1": "VMProtect", ".enigma1": "Enigma", "PEC2": "PECompact",
}


class PEAnalyzer(Analyzer):
    name = "pe"
    kinds = ("pe",)

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        if pefile is None:
            result.errors.append("pefile ist nicht installiert – PE-Details übersprungen.")
            return
        pe = pefile.PE(data=ctx.data, fast_load=True)
        pe.parse_data_directories()
        result.tools.append("pefile")

        fh, oh = pe.FILE_HEADER, pe.OPTIONAL_HEADER
        machine_desc, arch = MACHINES.get(fh.Machine, (hex(fh.Machine), None))
        ctx.facts["arch"] = arch
        is_dll = pe.is_dll()
        is_driver = oh.Subsystem == 1 or pe.is_driver()
        clr = oh.DATA_DIRECTORY[14].VirtualAddress != 0
        ctx.facts["dotnet"] = clr
        try:
            ts = dt.datetime.fromtimestamp(fh.TimeDateStamp, dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        except (OverflowError, OSError, ValueError):
            ts = hex(fh.TimeDateStamp)

        kind = "Treiber (.sys)" if is_driver else "DLL (Bibliothek)" if is_dll else "Programm (EXE)"
        if clr:
            kind += " – .NET/Managed Code"
            result.find("info", ".NET-Assembly",
                        "Managed Code: Klassen, Methoden und String-Literale lassen sich fast vollständig rekonstruieren.")
        result.description = f"Windows PE – {kind}"

        kv = {
            "Art": kind,
            "Architektur": machine_desc,
            "Subsystem": SUBSYSTEMS.get(oh.Subsystem, str(oh.Subsystem)),
            "Kompiliert (Zeitstempel)": ts,
            "Einstiegspunkt (RVA)": hex(oh.AddressOfEntryPoint),
            "Image Base": hex(oh.ImageBase),
            "Imphash": pe.get_imphash() or "–",
            "Digitale Signatur": "vorhanden" if oh.DATA_DIRECTORY[4].Size else "keine",
        }
        dll_chars = oh.DllCharacteristics
        kv["Schutzmechanismen"] = ", ".join(
            name for flag, name in ((0x40, "ASLR"), (0x100, "DEP/NX"), (0x4000, "CFG"), (0x400, "kein SEH"))
            if dll_chars & flag) or "keine"
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks:
            kv["TLS-Callbacks"] = "ja – Thread-Local-Storage-Callbacks (nicht TLS/SSL): Code läuft vor dem Einstiegspunkt"
            result.find("low", "TLS-Callbacks", "Thread-Local-Storage-Callbacks: Code wird bereits vor main/WinMain "
                        "ausgeführt – üblich in großen C++-Programmen, manchmal Anti-Debug-Trick.")
        result.add(Section("PE-Header", kv=kv, llm_priority=0))
        if oh.DATA_DIRECTORY[4].Size:
            result.product["Digitale Signatur"] = "vorhanden (Authenticode, Gültigkeit nicht geprüft)"

        self._version_info(pe, result)
        self._sections(pe, result)
        imports = self._imports(pe, result)
        exports = self._exports(pe, result)
        self._resources(pe, result)
        self._code(pe, ctx, result, arch, imports, exports)

    # ------------------------------------------------------------------
    def _version_info(self, pe, result: AnalysisResult) -> None:
        info: dict[str, str] = {}
        for fileinfo in getattr(pe, "FileInfo", []) or []:
            for entry in fileinfo:
                for st in getattr(entry, "StringTable", []) or []:
                    for k, v in st.entries.items():
                        key, val = k.decode(errors="replace"), v.decode(errors="replace").strip()
                        if val:
                            info[key] = clip(val, 200)
        if info:
            result.add(Section("Versionsinformationen (Ressource)", kv=info, llm_priority=0))
            for key, label in (("ProductName", "Produkt"), ("FileDescription", "Beschreibung"),
                               ("CompanyName", "Hersteller"), ("ProductVersion", "Version"),
                               ("FileVersion", "Dateiversion"), ("OriginalFilename", "Originaler Dateiname")):
                if info.get(key) and info[key] not in result.product.values():
                    result.product[label] = info[key]

    def _sections(self, pe, result: AnalysisResult) -> None:
        rows = []
        for s in pe.sections:
            name = s.Name.rstrip(b"\0").decode(errors="replace")
            ent = entropy(s.get_data()[:2 * 1024 * 1024])
            flags = "".join(c for f, c in ((0x40000000, "R"), (0x80000000, "W"), (0x20000000, "X"))
                            if s.Characteristics & f)
            rows.append([name, hex(s.VirtualAddress), f"{s.Misc_VirtualSize:,}", f"{s.SizeOfRawData:,}",
                         f"{ent:.2f}", flags])
            if name in PACKER_SECTIONS:
                result.find("medium", f"Packer erkannt: {PACKER_SECTIONS[name]}",
                            f"Sektion {name} deutet auf {PACKER_SECTIONS[name]} hin – der eigentliche Code ist komprimiert.")
            if "W" in flags and "X" in flags:
                result.find("medium", f"Sektion {name} ist schreib- und ausführbar",
                            "Typisch für selbstentpackenden oder selbstmodifizierenden Code.")
            if ent > 7.2 and s.SizeOfRawData > 4096:
                result.find("low", f"Sektion {name} hat hohe Entropie ({ent:.2f})",
                            "Inhalt ist vermutlich komprimiert oder verschlüsselt.")
        result.add(Section("Sektionen", table=Table(
            ["Name", "RVA", "Virt. Größe", "Rohgröße", "Entropie", "Rechte"], rows), llm_priority=2))

    def _imports(self, pe, result: AnalysisResult) -> dict[int, str]:
        iat: dict[int, str] = {}
        rows, all_funcs = [], []
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = entry.dll.decode(errors="replace")
            funcs = []
            for imp in entry.imports:
                fn = imp.name.decode(errors="replace") if imp.name else f"Ordinal {imp.ordinal}"
                funcs.append(fn)
                iat[imp.address] = f"{dll}!{fn}"
            all_funcs.extend(funcs)
            rows.append([dll, str(len(funcs)), clip(", ".join(funcs), 600)])
        if rows:
            result.add(Section("Importierte Bibliotheken & Funktionen",
                               table=Table(["DLL", "Anzahl", "Funktionen"], rows), llm_priority=1))
        elif not getattr(pe, "DIRECTORY_ENTRY_IMPORT", None):
            result.find("medium", "Keine Imports", "Eine EXE ohne Imports ist fast immer gepackt oder lädt alles dynamisch.")
        if 0 < len(all_funcs) <= 10 and any(f.lower().startswith(("loadlibrary", "getprocaddress")) for f in all_funcs):
            result.find("medium", "Minimale Importtabelle",
                        "Nur wenige Imports inkl. LoadLibrary/GetProcAddress – typisch für Packer/Loader.")
        add_capabilities(result, all_funcs)
        return iat

    def _exports(self, pe, result: AnalysisResult) -> dict[int, str]:
        exports: dict[int, str] = {}
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return exports
        own_rows, lib_counts = [], Counter()
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = sym.name.decode(errors="replace") if sym.name else f"#{sym.ordinal}"
            lib = library_of(name)
            if lib:
                lib_counts[lib] += 1
                continue
            exports[sym.address] = name
            own_rows.append([str(sym.ordinal), name, hex(sym.address)])
        total = len(own_rows) + sum(lib_counts.values())
        text = ""
        if lib_counts:
            text = (f"{total} Exporte, davon {sum(lib_counts.values())} aus bekannten Bibliotheken "
                    f"({describe(lib_counts)}) – z. B. die Node.js/V8-Schnittstelle für native Module; "
                    "aufgeführt sind nur die übrigen.")
        result.add(Section("Exportierte Funktionen (API der DLL)", text=text,
                           table=Table(["Ordinal", "Name", "RVA"], own_rows[:300], total=len(own_rows)) if own_rows else None,
                           llm_priority=1))
        return exports

    def _resources(self, pe, result: AnalysisResult) -> None:
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return
        rows = []
        for rtype in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            tname = pefile.RESOURCE_TYPE.get(rtype.id, str(rtype.name or rtype.id))
            count, size = 0, 0
            for rid in getattr(rtype, "directory", None).entries if hasattr(rtype, "directory") else []:
                for lang in getattr(rid, "directory", None).entries if hasattr(rid, "directory") else []:
                    count += 1
                    size += lang.data.struct.Size
            rows.append([str(tname).replace("RT_", ""), str(count), f"{size:,}"])
            if tname == "RT_RCDATA" and size > 100_000:
                result.find("low", "Große eingebettete Rohdaten (RCDATA)",
                            f"{size:,} Bytes – könnte eine eingebettete Datei/Payload sein.")
        if rows:
            result.add(Section("Ressourcen", table=Table(["Typ", "Anzahl", "Bytes"], rows), llm_priority=3))

    def _code(self, pe, ctx: Context, result: AnalysisResult, arch: str | None,
              iat: dict[int, str], exports: dict[int, str]) -> None:
        if not disasm.available(arch) or ctx.facts.get("dotnet") or ctx.facts.get("runtime_shell"):
            return  # .NET: Einstiegspunkt ist nur ein Sprung in die CLR – C# kommt vom .NET-Analyzer
        base = pe.OPTIONAL_HEADER.ImageBase
        names = dict(iat)
        names.update({base + rva: name for rva, name in exports.items()})
        targets = []
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if ep:
            targets.append(("Einstiegspunkt", ep))
        for rva, name in list(exports.items())[: max(0, ctx.settings.max_disasm_functions - 1)]:
            targets.append((name, rva))
        blocks = []
        for label, rva in targets:
            try:
                code = pe.get_data(rva, 1024)
            except pefile.PEFormatError:
                continue
            text = disasm.disassemble(code, base + rva, arch, names=names)
            if text:
                blocks.append(f"; ===== {label} @ {base + rva:#x} =====\n{text}")
        if blocks:
            result.tools.append("capstone")
            result.add(Section("Disassembly (Einstiegspunkt & Exporte)", code="\n\n".join(blocks),
                               code_lang="asm", llm_priority=5 if ctx.facts.get("radare2") else 3))


def add_capabilities(result: AnalysisResult, functions: list[str]) -> None:
    caps = categorize(functions)
    if result.profile == "allgemein":  # Software-Doku: nur Funktionsbereiche, keine Sicherheitsbewertung
        caps = {c: f for c, f in caps.items() if c not in SECURITY_ONLY}
    if not caps:
        return
    rows = []
    for cat, funcs in caps.items():
        sev, expl, _ = CAPABILITIES[cat]
        rows.append([cat, expl, clip(", ".join(funcs), 300)])
        if sev in ("medium", "high"):
            result.find(sev, f"Fähigkeit: {cat}", f"{expl} ({clip(', '.join(funcs[:6]), 200)})")
    result.add(Section("Abgeleitete Fähigkeiten (aus Imports)",
                       table=Table(["Fähigkeit", "Bedeutung", "Belegt durch"], rows), llm_priority=0))
