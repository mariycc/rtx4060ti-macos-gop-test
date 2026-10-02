"""Read-only checks for an x86_64 Mach-O kernel extension, not a runtime test."""
import argparse
import json
from pathlib import Path
import struct


def check(data, required_class=None):
    def require(condition, message):
        if not condition:
            raise ValueError(message)

    require(len(data) >= 32, "Truncated Mach-O header")
    magic, cpu, subtype, kind, count, command_bytes, flags, _ = struct.unpack_from(
        "<IiiIIIII", data
    )
    require(magic == 0xFEEDFACF, "Expected thin little-endian Mach-O 64")
    require(cpu == 0x01000007, "Expected x86_64")
    require(kind == 11, "Expected MH_KEXT_BUNDLE; ordinary bundles are rejected")
    require(command_bytes <= len(data) - 32, "Load commands outside file")
    require(count <= command_bytes // 8, "Invalid load-command count")
    forbidden = {
        0xC, 0xD, 0xE, 0x20, 0x22, 0x80000018, 0x8000001C,
        0x8000001F, 0x80000022, 0x80000023, 0x80000028,
        0x80000033, 0x80000034,
    }
    sections = []
    symbols = None
    dynamic_relocations = 0
    offset = 32
    for _ in range(count):
        require(offset + 8 <= 32 + command_bytes, "Truncated load command")
        command, size = struct.unpack_from("<II", data, offset)
        require(size >= 8 and size % 8 == 0, "Invalid command size")
        require(size <= 32 + command_bytes - offset, "Command outside table")
        require(command not in forbidden, "User-space dyld load command found")
        if command == 0x19:
            require(size >= 72, "Truncated segment")
            segment = struct.unpack_from("<II16sQQQQiiII", data, offset)
            nsections = segment[9]
            require(nsections <= (size - 72) // 80, "Truncated section table")
            file_offset, file_size = segment[5:7]
            require(file_offset <= len(data) and file_size <= len(data) - file_offset,
                    "Segment outside file")
            for index in range(nsections):
                section = struct.unpack_from("<16s16sQQIIIIIIII", data,
                                             offset + 72 + index * 80)
                name = section[0].split(b"\0", 1)[0].decode("ascii")
                section_size, file_offset, reloc_offset, reloc_count = (
                    section[3], section[4], section[6], section[7]
                )
                section_type = section[8] & 0xFF
                require(section_type not in (7, 8), "Lazy pointers or symbol stubs found")
                if section_type not in (1, 12, 18):
                    require(file_offset <= len(data) and
                            section_size <= len(data) - file_offset,
                            "Section outside file")
                require(reloc_offset <= len(data) and
                        reloc_count <= (len(data) - reloc_offset) // 8,
                        "Relocation table outside file")
                sections.append({"Name": name, "Bytes": section_size,
                                 "Relocations": reloc_count})
        elif command == 2:
            require(size == 24 and symbols is None, "Invalid symbol table command")
            symbols = struct.unpack_from("<IIII", data, offset + 8)
        elif command == 11:
            require(size == 80, "Invalid dynamic symbol table")
            dynamic = struct.unpack_from("<20I", data, offset)
            for reloc_offset, reloc_count in (dynamic[16:18], dynamic[18:20]):
                require(reloc_offset <= len(data) and
                        reloc_count <= (len(data) - reloc_offset) // 8,
                        "Dynamic relocation table outside file")
                dynamic_relocations += reloc_count
        offset += size
    require(offset == 32 + command_bytes, "Incorrect load-command size")
    require(symbols is not None, "Missing symbol table")
    sym_offset, sym_count, str_offset, str_size = symbols
    require(sym_offset <= len(data) and sym_count <= (len(data) - sym_offset) // 16,
            "Symbol table outside file")
    require(str_offset <= len(data) and str_size <= len(data) - str_offset,
            "String table outside file")
    strings = data[str_offset:str_offset + str_size]
    defined = set()
    imports = set()
    for index in range(sym_count):
        str_index, typ, _, _, value = struct.unpack_from(
            "<IBBHQ", data, sym_offset + index * 16
        )
        if typ & 0xE0:
            continue
        require(str_index < str_size, "Symbol string index outside table")
        terminator = strings.find(b"\0", str_index)
        require(terminator >= 0, "Unterminated symbol name")
        name = strings[str_index:terminator].decode("ascii")
        if typ & 0x0E == 0:
            require(value == 0, "Unresolved common symbol")
            if name:
                imports.add(name)
        elif typ & 0x0E in (2, 14):
            # The linker can make private entry points local N_PEXT|N_SECT.
            # They must still be defined; requiring N_EXT would reject real kexts.
            defined.add(name)
    require({"_kmod_info", "__start", "__stop"} <= defined,
            "Missing kmod entry points")
    require(any(s["Name"] == "__mod_init_func" and s["Bytes"] >= 8 for s in sections),
            "Missing C++ module initialization")
    if required_class:
        require(any(n.startswith("__ZTV") and required_class in n for n in defined),
                "Missing expected IOFramebuffer class vtable")
    require(not imports or dynamic_relocations or any(s["Relocations"] for s in sections),
            "Kernel imports present without relocation tables")
    return {
        "Architecture": "x86_64", "MachOType": "MH_KEXT_BUNDLE",
        "HeaderFlags": hex(flags), "CPUSubtype": subtype,
        "DynamicRelocations": dynamic_relocations,
        "Sections": sections, "KernelImports": sorted(imports),
        "FormatChecksPassed": True, "KernelSymbolsResolved": False,
        "RuntimeTested": False, "GUIBootVerified": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--class-name", default=None)
    args = parser.parse_args()
    try:
        result = check(args.binary.read_bytes(), args.class_name)
    except (ValueError, OSError, UnicodeError, struct.error) as error:
        parser.exit(1, f"Kext format check failed: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
