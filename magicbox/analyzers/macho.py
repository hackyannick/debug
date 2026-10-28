"""Schlanker Mach-O-Parser (macOS/iOS) ohne externe Abhängigkeiten."""

from __future__ import annotations

import struct

from magicbox.model import AnalysisResult, Section, Table

from .base import Analyzer, Context

CPU = {7: "x86", 0x01000007: "x86-64", 12: "ARM", 0x0100000C: "ARM64", 0x0200000C: "ARM64_32", 18: "PowerPC"}
FILETYPES = {1: "Objektdatei", 2: "Programm", 6: "Dynamische Bibliothek (.dylib)", 8: "Bundle/Plugin",
             7: "Dynamic Linker", 11: "Kernel-Erweiterung (kext)"}
LC_SEGMENT, LC_SEGMENT_64, LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_ID_DYLIB = 0x1, 0x19, 0xC, 0x80000018, 0xD
LC_MAIN, LC_CODE_SIGNATURE, LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64, LC_RPATH = 0x80000028, 0x1D, 0x21, 0x2C, 0x8000001C


def _cstr(data: bytes, off: int) -> str:
    end = data.find(b"\0", off)
    return data[off:end if end >= 0 else None].decode(errors="replace")


class MachOAnalyzer(Analyzer):
    name = "macho"
    kinds = ("macho",)

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        data = ctx.data
        if data[:4] == b"\xca\xfe\xba\xbe":
            n = struct.unpack_from(">I", data, 4)[0]
            rows, slices = [], []
            for i in range(n):
                cpu, _sub, off, size, _align = struct.unpack_from(">IIIII", data, 8 + i * 20)
                rows.append([CPU.get(cpu, hex(cpu)), hex(off), f"{size:,}"])
                slices.append((off, size))
            result.add(Section("Universal Binary – enthaltene Architekturen",
                               table=Table(["Architektur", "Offset", "Größe"], rows), llm_priority=0))
            if not slices:
                return
            off, size = slices[-1]  # meist arm64 oder x86_64
            data = data[off:off + size]
        try:
            self._thin(data, result)
        except struct.error as exc:
            result.errors.append(f"Mach-O beschädigt oder abgeschnitten: {exc}")

    def _thin(self, data: bytes, result: AnalysisResult) -> None:
        magic = data[:4]
        is64 = magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
        end = "<" if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe") else ">"
        cpu, _sub, ftype, ncmds, _sizecmds, flags = struct.unpack_from(end + "IIIIII", data, 4)
        off = 32 if is64 else 28
        dylibs, rpaths, segments = [], [], []
        kv = {
            "Art": FILETYPES.get(ftype, str(ftype)),
            "Architektur": CPU.get(cpu, hex(cpu)),
            "PIE": "ja" if flags & 0x200000 else "nein",
        }
        for _ in range(min(ncmds, 2000)):
            cmd, size = struct.unpack_from(end + "II", data, off)
            if size < 8:
                break
            if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
                name_off = struct.unpack_from(end + "I", data, off + 8)[0]
                dylibs.append(_cstr(data, off + name_off))
            elif cmd == LC_ID_DYLIB:
                kv["Install-Name"] = _cstr(data, off + struct.unpack_from(end + "I", data, off + 8)[0])
            elif cmd == LC_RPATH:
                rpaths.append(_cstr(data, off + struct.unpack_from(end + "I", data, off + 8)[0]))
            elif cmd in (LC_SEGMENT, LC_SEGMENT_64):
                segname = data[off + 8:off + 24].rstrip(b"\0").decode(errors="replace")
                if cmd == LC_SEGMENT_64:
                    vmaddr, vmsize, _fo, fsize = struct.unpack_from(end + "QQQQ", data, off + 24)
                else:
                    vmaddr, vmsize, _fo, fsize = struct.unpack_from(end + "IIII", data, off + 24)
                segments.append([segname, hex(vmaddr), f"{vmsize:,}", f"{fsize:,}"])
            elif cmd == LC_MAIN:
                kv["Einstiegspunkt (Offset)"] = hex(struct.unpack_from(end + "Q", data, off + 8)[0])
            elif cmd == LC_CODE_SIGNATURE:
                kv["Code-Signatur"] = "vorhanden"
            elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                cryptid = struct.unpack_from(end + "I", data, off + 16)[0]
                if cryptid:
                    kv["Verschlüsselt"] = "ja (FairPlay)"
                    result.find("medium", "Verschlüsseltes App-Store-Binary",
                                "Der Code ist mit FairPlay verschlüsselt – statische Analyse nur eingeschränkt möglich.")
            off += size
        kv.setdefault("Code-Signatur", "keine")
        result.add(Section("Mach-O-Header", kv=kv, llm_priority=0))
        if dylibs:
            result.add(Section("Gelinkte Bibliotheken/Frameworks", text="\n".join(dylibs), llm_priority=0))
        if rpaths:
            result.add(Section("RPATHs", text="\n".join(rpaths), llm_priority=3))
        if segments:
            result.add(Section("Segmente", table=Table(["Name", "VM-Adresse", "VM-Größe", "Dateigröße"], segments),
                               llm_priority=3))
