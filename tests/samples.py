"""Erzeugt kleine, gültige Testdateien im Speicher (keine Binärdateien im Repo nötig)."""

from __future__ import annotations

import struct


def tiny_pe64(imports: dict[str, list[str]] | None = None) -> bytes:
    """Minimales PE32+ (x64) mit einer .text-Sektion und optionaler Importtabelle in .idata."""
    imports = imports or {"KERNEL32.dll": ["ExitProcess", "VirtualAlloc"], "WS2_32.dll": ["connect", "send"]}
    file_align, sect_align, image_base = 0x200, 0x1000, 0x140000000
    text_rva, idata_rva = 0x1000, 0x2000

    # --- .idata aufbauen
    n = len(imports)
    desc_size = 20 * (n + 1)
    names_blob = b""
    thunks_blob = b""
    hint_blob = b""
    layout = []
    # Reihenfolge: Deskriptoren | ILT/IAT-Arrays | Hint/Name | DLL-Namen
    thunk_off = desc_size
    for dll, funcs in imports.items():
        layout.append((dll, funcs, thunk_off))
        thunk_off += 8 * (len(funcs) + 1) * 2  # ILT + IAT
    hint_off = thunk_off
    func_rvas = {}
    for dll, funcs, _ in layout:
        for f in funcs:
            func_rvas[(dll, f)] = idata_rva + hint_off + len(hint_blob)
            entry = struct.pack("<H", 0) + f.encode() + b"\0"
            if len(entry) % 2:
                entry += b"\0"
            hint_blob += entry
    name_off = hint_off + len(hint_blob)
    dll_rvas = {}
    for dll, _, _ in layout:
        dll_rvas[dll] = idata_rva + name_off + len(names_blob)
        names_blob += dll.encode() + b"\0"
    descs = b""
    for dll, funcs, off in layout:
        ilt_rva = idata_rva + off
        iat_rva = ilt_rva + 8 * (len(funcs) + 1)
        descs += struct.pack("<IIIII", ilt_rva, 0, 0, dll_rvas[dll], iat_rva)
        arr = b"".join(struct.pack("<Q", func_rvas[(dll, f)]) for f in funcs) + b"\0" * 8
        thunks_blob += arr + arr
    descs += b"\0" * 20
    idata = descs + thunks_blob + hint_blob + names_blob
    idata += b"\0" * (-len(idata) % file_align)

    code = b"\x48\x83\xec\x28" + b"\x31\xc9" + b"\x48\x83\xc4\x28" + b"\xc3"  # sub rsp; xor ecx; add rsp; ret
    text = code + b"\0" * (file_align - len(code))

    dos = b"MZ" + b"\0" * 0x3A + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0x65000000, 0, 0, 240, 0x22)
    data_dirs = [(0, 0)] * 16
    data_dirs[1] = (idata_rva, len(descs))
    opt = struct.pack("<HBBIIIII", 0x20B, 14, 0, len(text), len(idata), 0, text_rva, text_rva)
    opt += struct.pack("<QII", image_base, sect_align, file_align)
    opt += struct.pack("<HHHHHHI", 6, 0, 0, 0, 6, 0, 0)
    size_of_image = idata_rva + sect_align
    headers_size = file_align
    opt += struct.pack("<IIIHH", size_of_image, headers_size, 0, 3, 0x8160)
    opt += struct.pack("<QQQQII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    opt += b"".join(struct.pack("<II", *d) for d in data_dirs)
    sec_text = struct.pack("<8sIIIIIIHHI", b".text", len(code), text_rva, len(text), headers_size, 0, 0, 0, 0, 0x60000020)
    sec_idata = struct.pack("<8sIIIIIIHHI", b".idata", len(idata), idata_rva, len(idata), headers_size + len(text),
                            0, 0, 0, 0, 0xC0000040)
    header = dos + b"PE\0\0" + coff + opt + sec_text + sec_idata
    header += b"\0" * (headers_size - len(header))
    return header + text + idata
