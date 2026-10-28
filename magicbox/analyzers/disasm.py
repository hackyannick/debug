"""Disassemblierung einzelner Funktionen mit Capstone (optional)."""

from __future__ import annotations

import re

try:
    import capstone
except ImportError:  # pragma: no cover - optionale Abhängigkeit
    capstone = None

# Architektur-Schlüssel -> (cs_arch, cs_mode)
ARCHS = {}
if capstone is not None:
    ARCHS = {
        "x86": (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        "x64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        "arm": (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
        "thumb": (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB),
        "arm64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    }

STOP_MNEMONICS = {"ret", "retn", "retf", "hlt", "ud2"}


def available(arch: str | None) -> bool:
    return capstone is not None and arch in ARCHS


def disassemble(code: bytes, address: int, arch: str, max_insns: int = 80,
                names: dict[int, str] | None = None) -> str:
    """Disassembliert ab ``address`` bis zu ``max_insns`` Befehle oder bis zum Return.

    ``names`` bildet Adressen auf Symbolnamen ab (Imports, Funktionen) und wird
    als Kommentar an Sprung-/Aufrufziele angehängt.
    """
    if not available(arch):
        return ""
    cs_arch, cs_mode = ARCHS[arch]
    md = capstone.Cs(cs_arch, cs_mode)
    md.skipdata = True
    names = names or {}
    lines = []
    for count, insn in enumerate(md.disasm(code, address)):
        if count >= max_insns:
            lines.append("    ; … (gekürzt)")
            break
        comment = ""
        target = _target(insn)
        if target is not None and target in names:
            comment = f"  ; {names[target]}"
        lines.append(f"{insn.address:#010x}:  {insn.mnemonic:<8} {insn.op_str}{comment}")
        if insn.mnemonic in STOP_MNEMONICS and count > 2:
            break
    return "\n".join(lines)


def _target(insn) -> int | None:
    """Ermittelt das Ziel eines Sprungs/Aufrufs oder einer RIP-relativen Speicheradresse."""
    op = insn.op_str
    if "rip" in op and "[" in op:
        m = re.search(r"rip\s*([+-])\s*(0x[0-9a-f]+|\d+)", op)
        if m:
            disp = int(m.group(2), 0)
            return insn.address + insn.size + (disp if m.group(1) == "+" else -disp)
    m = re.search(r"\[(0x[0-9a-f]+)\]", op)  # call dword ptr [0x402000] (x86-IAT)
    if m:
        return int(m.group(1), 16)
    m = re.fullmatch(r"#?(0x[0-9a-f]+)", op.strip())  # call 0x401000 / bl #0x1000
    if m:
        return int(m.group(1), 16)
    return None
