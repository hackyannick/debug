"""Analyse von ELF-Dateien (Linux/Unix) mit ``pyelftools``."""

from __future__ import annotations

import io

from magicbox.model import AnalysisResult, Section, Table

from . import disasm
from .base import Analyzer, Context, clip, entropy
from .pe import add_capabilities

try:
    from elftools.common.exceptions import ELFError
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
except ImportError:  # pragma: no cover
    ELFFile = None

ARCH = {"EM_386": ("x86 (32 Bit)", "x86"), "EM_X86_64": ("x86-64", "x64"), "EM_ARM": ("ARM (32 Bit)", "arm"),
        "EM_AARCH64": ("ARM64", "arm64"), "EM_MIPS": ("MIPS", None), "EM_RISCV": ("RISC-V", None),
        "EM_PPC": ("PowerPC", None), "EM_PPC64": ("PowerPC64", None)}
TYPES = {"ET_EXEC": "Programm (statische Adresse)", "ET_DYN": "Shared Object / PIE-Programm",
         "ET_REL": "Objektdatei (.o)", "ET_CORE": "Core-Dump"}


class ELFAnalyzer(Analyzer):
    name = "elf"
    kinds = ("elf",)

    def analyze(self, ctx: Context, result: AnalysisResult) -> None:
        if ELFFile is None:
            result.errors.append("pyelftools ist nicht installiert – ELF-Details übersprungen.")
            return
        try:
            elf = ELFFile(io.BytesIO(ctx.data))
        except ELFError as exc:
            result.errors.append(f"ELF konnte nicht gelesen werden: {exc}")
            return
        result.tools.append("pyelftools")

        machine_desc, arch = ARCH.get(elf["e_machine"], (elf["e_machine"], None))
        ctx.facts["arch"] = arch
        etype = TYPES.get(elf["e_type"], elf["e_type"])

        interp, needed, soname, runpath = None, [], None, None
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_INTERP":
                interp = seg.get_interp_name()
        dyn = elf.get_section_by_name(".dynamic")
        if isinstance(dyn, DynamicSection):
            for tag in dyn.iter_tags():
                if tag.entry.d_tag == "DT_NEEDED":
                    needed.append(tag.needed)
                elif tag.entry.d_tag == "DT_SONAME":
                    soname = tag.soname
                elif tag.entry.d_tag in ("DT_RPATH", "DT_RUNPATH"):
                    runpath = getattr(tag, "runpath", None) or getattr(tag, "rpath", None)

        symbols, imported, exported = self._symbols(elf)
        has_symtab = elf.get_section_by_name(".symtab") is not None

        is_pie = elf["e_type"] == "ET_DYN" and interp is not None
        if elf["e_type"] == "ET_DYN" and interp is None:
            result.description = "ELF – Shared Library (.so)"
        elif elf["e_type"] == "ET_EXEC" or is_pie:
            result.description = "ELF – ausführbares Programm" + (" (statisch gelinkt)" if not interp else "")
        else:
            result.description = f"ELF – {etype}"

        kv = {
            "Art": etype,
            "Architektur": f"{machine_desc}, {elf.elfclass} Bit, {'Little' if elf.little_endian else 'Big'} Endian",
            "Einstiegspunkt": hex(elf["e_entry"]),
            "Interpreter": interp or "– (statisch gelinkt oder Bibliothek)",
            "Debug-Symbole": "vorhanden" if has_symtab else "entfernt (stripped)",
        }
        if elf.has_dwarf_info():
            kv["DWARF-Debuginfo"] = "vorhanden (Quelltext-Zeilen/Typen rekonstruierbar)"
        if soname:
            kv["SONAME"] = soname
        if runpath:
            kv["RPATH/RUNPATH"] = runpath
            result.find("low", "RPATH gesetzt", f"Bibliotheken werden zusätzlich aus {runpath} geladen.")
        kv["Härtung"] = self._hardening(elf, imported, is_pie)
        comment = elf.get_section_by_name(".comment")
        if comment is not None:
            kv["Compiler"] = clip(comment.data().replace(b"\0", b" ").decode(errors="replace").strip(), 200)
        result.add(Section("ELF-Header", kv=kv, llm_priority=0))

        if needed:
            result.add(Section("Benötigte Bibliotheken", text=", ".join(needed), llm_priority=0))

        rows = []
        for sec in elf.iter_sections():
            if not sec.name:
                continue
            flags = sec["sh_flags"]
            perm = "".join(c for f, c in ((2, "A"), (1, "W"), (4, "X")) if flags & f)
            ent = entropy(sec.data()[:1024 * 1024]) if sec["sh_type"] != "SHT_NOBITS" else 0.0
            rows.append([sec.name, sec["sh_type"].replace("SHT_", ""), hex(sec["sh_addr"]), f"{sec['sh_size']:,}",
                         f"{ent:.2f}", perm])
        if rows:
            result.add(Section("Sektionen", table=Table(["Name", "Typ", "Adresse", "Größe", "Entropie", "Flags"], rows),
                               llm_priority=3))
        elif elf["e_shnum"] == 0:
            result.find("medium", "Keine Sektionstabelle", "Sektionen wurden entfernt – häufig bei gepackten Binaries (z. B. UPX).")
        if b"UPX!" in ctx.data[:4096] or b"$Info: This file is packed with the UPX" in ctx.data:
            result.find("medium", "Packer erkannt: UPX", "Mit `upx -d` lässt sich die Datei meist entpacken.")

        if imported:
            result.add(Section("Importierte Funktionen", text=clip(", ".join(sorted(imported)), 6000), llm_priority=1))
            add_capabilities(result, sorted(imported))
        if exported:
            names = sorted(exported)
            result.add(Section("Exportierte/definierte Funktionen",
                               table=Table(["Funktion"], [[n] for n in names[:300]], total=len(names)),
                               llm_priority=2))
        self._code(elf, ctx, result, arch, symbols)

    # ------------------------------------------------------------------
    def _symbols(self, elf):
        """Gibt (Funktionen {addr: (name, size)}, importierte Namen, definierte Funktionsnamen) zurück."""
        funcs: dict[int, tuple[str, int]] = {}
        imported: set[str] = set()
        exported: set[str] = set()
        for secname in (".dynsym", ".symtab"):
            sec = elf.get_section_by_name(secname)
            if not isinstance(sec, SymbolTableSection):
                continue
            for sym in sec.iter_symbols():
                if not sym.name or sym["st_info"]["type"] != "STT_FUNC":
                    continue
                name = sym.name.split("@")[0]
                if sym["st_shndx"] == "SHN_UNDEF":
                    imported.add(name)
                elif sym["st_value"]:
                    funcs[sym["st_value"]] = (name, sym["st_size"])
                    if sym["st_info"]["bind"] in ("STB_GLOBAL", "STB_WEAK"):
                        exported.add(name)
        return funcs, imported, exported

    def _hardening(self, elf, imported: set[str], is_pie: bool) -> str:
        nx, relro, bindnow = True, False, False
        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_GNU_STACK":
                nx = not seg["p_flags"] & 1
            elif seg["p_type"] == "PT_GNU_RELRO":
                relro = True
        dyn = elf.get_section_by_name(".dynamic")
        if isinstance(dyn, DynamicSection):
            for tag in dyn.iter_tags():
                if tag.entry.d_tag == "DT_BIND_NOW" or (tag.entry.d_tag == "DT_FLAGS_1" and tag.entry.d_val & 1):
                    bindnow = True
        parts = [
            f"PIE {'ja' if is_pie else 'nein'}",
            f"NX {'ja' if nx else 'nein'}",
            "Full RELRO" if relro and bindnow else "Partial RELRO" if relro else "kein RELRO",
            f"Stack-Canary {'ja' if '__stack_chk_fail' in imported else 'nein'}",
            f"FORTIFY {'ja' if any(n.endswith('_chk') for n in imported) else 'nein'}",
        ]
        return ", ".join(parts)

    def _code(self, elf, ctx: Context, result: AnalysisResult, arch: str | None,
              symbols: dict[int, tuple[str, int]]) -> None:
        if not disasm.available(arch):
            return
        names = {addr: name for addr, (name, _) in symbols.items()}
        names.update(self._plt_names(elf))
        targets = []
        by_name = {name: addr for addr, (name, _) in symbols.items()}
        for preferred in ("main", "_start"):
            if preferred in by_name:
                targets.append((preferred, by_name[preferred]))
        if not targets:
            targets.append(("Einstiegspunkt", elf["e_entry"]))
        # danach die größten eigenen Funktionen (meist die interessante Logik)
        skip = {"_start", "_init", "_fini", "frame_dummy", "register_tm_clones", "deregister_tm_clones",
                "__do_global_dtors_aux", "__libc_csu_init", "__libc_csu_fini", "main"}
        biggest = sorted(((size, addr, name) for addr, (name, size) in symbols.items()
                          if name not in skip and size > 0), reverse=True)
        for _, addr, name in biggest[: max(0, ctx.settings.max_disasm_functions - len(targets))]:
            targets.append((name, addr))

        blocks = []
        for label, addr in targets:
            code = self._read_va(elf, addr, 1200)
            if not code:
                continue
            text = disasm.disassemble(code, addr, arch, max_insns=100, names=names)
            if text:
                blocks.append(f"; ===== {label} @ {addr:#x} =====\n{text}")
        if blocks:
            result.tools.append("capstone")
            result.add(Section("Disassembly (wichtigste Funktionen)", code="\n\n".join(blocks),
                               code_lang="asm", llm_priority=5 if ctx.facts.get("radare2") else 3))

    @staticmethod
    def _read_va(elf, addr: int, size: int) -> bytes:
        for seg in elf.iter_segments():
            if seg["p_type"] != "PT_LOAD":
                continue
            start = seg["p_vaddr"]
            if start <= addr < start + seg["p_filesz"]:
                off = addr - start
                return seg.data()[off:off + size]
        return b""

    @staticmethod
    def _plt_names(elf) -> dict[int, str]:
        """Ordnet PLT-Einträge (x86/x64) den importierten Funktionen zu – für lesbare call-Ziele."""
        names: dict[int, str] = {}
        relplt = elf.get_section_by_name(".rela.plt") or elf.get_section_by_name(".rel.plt")
        if relplt is None:
            return names
        symtab = elf.get_section(relplt["sh_link"])
        got_to_name = {}
        for rel in relplt.iter_relocations():
            sym = symtab.get_symbol(rel["r_info_sym"])
            if sym is not None and sym.name:
                got_to_name[rel["r_offset"]] = sym.name.split("@")[0]
        names.update({addr: f"{n}@got" for addr, n in got_to_name.items()})
        # PLT-Stubs: jmp [rip+X] -> GOT-Eintrag. Wir scannen .plt/.plt.sec in 16-Byte-Schritten.
        for secname in (".plt.sec", ".plt"):
            plt = elf.get_section_by_name(secname)
            if plt is None or not disasm.available("x64" if elf.elfclass == 64 else "x86"):
                continue
            arch = "x64" if elf.elfclass == 64 else "x86"
            if elf["e_machine"] not in ("EM_X86_64", "EM_386"):
                break
            data, base = plt.data(), plt["sh_addr"]
            for off in range(0, len(data), 16):
                stub = disasm.disassemble(data[off:off + 16], base + off, arch, max_insns=3, names=names)
                for line in stub.splitlines():
                    if "@got" in line and ("jmp" in line):
                        names[base + off] = line.rsplit("; ", 1)[-1].replace("@got", "@plt")
                        break
        return names
