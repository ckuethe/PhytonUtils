#!/usr/bin/env python3
"""Convert Phyton firmware images into ELF binaries loadable into a disassembler.

The reconstructed firmware image is a flat STM32L475 flash dump at 0x08000000.
The generated ELF also maps the STM32L475 memory regions (SRAM1/SRAM2) and the
peripheral registers described by the CMSIS-SVD file, so a disassembler
(Ghidra/IDA) can recognise RAM and peripheral addresses.

Usage:
    python3 hardsoft2elf.py [input.bin ...] [--svd PATH]
Without arguments, processes every firmware image in HardSoft/.
Outputs are written as <name>.elf next to each input (or into HardSoft/dec/).
"""

import os
import struct
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from phytonutils.firmware import firmware as ff  # noqa: E402

# --- ELF32 (little-endian) constants ---
ELFCLASS32 = 1
ELFDATA2LSB = 1
EV_CURRENT = 1
ET_EXEC = 2
EM_ARM = 0x28
PT_LOAD = 1
PF_X = 1
PF_W = 2
PF_R = 4
SHT_PROGBITS = 1
SHT_NOBITS = 8
SHT_STRTAB = 3
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
SHF_WRITE = 0x1

BASE_ADDRESS = ff.BASE_ADDRESS

# --- Coarse ARM Cortex-M 512 MB regions (full 4 GB coverage) ---
# name, address, size, flags
COARSE_REGIONS = [
    ("CODE", 0x00000000, 0x20000000, PF_R | PF_X),
    ("SRAM", 0x20000000, 0x20000000, PF_R | PF_W),
    ("PERIPH", 0x40000000, 0x20000000, PF_R | PF_W),
    ("EXT_RAM", 0x60000000, 0x20000000, PF_R | PF_W),
    ("EXT_DEV1", 0x80000000, 0x20000000, PF_R | PF_W),
    ("EXT_DEV2", 0xA0000000, 0x20000000, PF_R | PF_W),
    ("SYSREG", 0xC0000000, 0x20000000, PF_R | PF_W),
    ("PRIV", 0xE0000000, 0x20000000, PF_R | PF_W),
]

# --- STM32L4x5 sub-regions (refinements of the coarse blocks) ---
# name, address, size, flags
MEMORY_REGIONS = [
    ("FLASH_ALIAS", 0x00000000, 0x100000, PF_R | PF_X),      # remappable code alias (<= 1 MB flash)
    ("SRAM2", 0x10000000, 0x08000, PF_R | PF_W),             # 32 KB parity-checked RAM
    ("SRAM1", 0x20000000, 0x18000, PF_R | PF_W),             # 96 KB general-purpose RAM
    ("BITBAND_SRAM", 0x22000000, 0x300000, PF_R | PF_W),     # bit-band alias for SRAM1
    ("BITBAND_PERIPH", 0x42000000, 0x2000000, PF_R | PF_W),  # bit-band alias for peripherals (1 MB)
    ("SYSMEM", 0x1FFF0000, 0x08000, PF_R | PF_W),            # system memory (boot)
    ("FSMC", 0xA0000000, 0x20000000, PF_R | PF_W),           # external memory banks 0xA0000000-BFFFFFFF
]


def _parse_svd(path):
    """Return a list of (name, base, extent) for peripherals that have registers."""
    tree = ET.parse(path)
    peripherals = []
    for p in tree.getroot().findall(".//peripheral"):
        name = p.find("name").text
        base = int(p.find("baseAddress").text, 0)
        extent = 4
        for r in p.findall(".//register"):
            off = int(r.find("addressOffset").text, 0)
            size = int(r.find("size").text, 0) if r.find("size") is not None else 32
            extent = max(extent, off + size // 8)
        if extent > 4 or p.findall(".//register"):
            peripherals.append((name, base, extent))
    # sort by address for stable layout
    peripherals.sort(key=lambda x: x[1])
    return peripherals


def _flag_str(flags):
    return "".join(ch for ch, bit in (("R", PF_R), ("W", PF_W), ("X", PF_X)) if flags & bit)


def build_regions(filesz, load_addr, svd_path):
    """Assemble the ordered region list.

    Ordered coarsest -> finest so the most specific block wins for overlapping
    addresses in the disassembler. Returns [(name, addr, size, flags, is_nobits)].
    """
    regions = []
    for name, addr, size, flags in COARSE_REGIONS:
        regions.append((name, addr, size, flags, True))
    for name, addr, size, flags in MEMORY_REGIONS:
        regions.append((name, addr, size, flags, True))
    regions.append(("FLASH", load_addr, filesz, PF_R | PF_X, False))
    if svd_path:
        for name, base, extent in _parse_svd(svd_path):
            regions.append((name, base, extent, PF_R | PF_W, True))
    return regions


def build_elf(data, load_addr, entry, svd_path=None, verbose=False):
    """Build an ELF32 executable with memory + peripheral mappings."""
    filesz = len(data)
    data_pad = (-filesz) & 3
    file_data = data + b"\x00" * data_pad

    # Segments/sections are ordered from coarsest to finest so that, in the
    # disassembler, the most specific block wins for overlapping addresses.
    regions = build_regions(filesz, load_addr, svd_path)

    if verbose:
        print("memory regions:")
        for name, addr, size, flags, _nobits in regions:
            print(
                f"  {name:14s} {addr:08x}..{addr+size:08x} "
                f"size=0x{size:08x} flags={_flag_str(flags)}"
            )

    segments = []  # (name, addr, size, flags, file_offset). None = NOBITS.
    sections = []  # (name, addr, size, flags, is_nobits)
    for name, addr, size, flags, nobits in regions:
        segments.append((name, addr, size, flags, None))
        sections.append((name, addr, size, flags, nobits))

    num_phdrs = len(segments)
    data_offset = 52 + 32 * num_phdrs
    # The FLASH segment carries the reconstructed image bytes
    for i in range(len(segments)):
        if segments[i][0] == "FLASH":
            segments[i] = ("FLASH", load_addr, filesz, PF_R | PF_X, data_offset)

    # Section name string table: \0<name>\0...\0.shstrtab\0
    shstr_parts = [b"\0"]
    sh_name_offsets = {}
    for name, _addr, _size, _flags, _nobits in sections:
        sh_name_offsets[name] = sum(len(p) for p in shstr_parts)
        shstr_parts.append(name.encode())
        shstr_parts.append(b"\0")
    sh_name_offsets[".shstrtab"] = sum(len(p) for p in shstr_parts)
    shstr_parts.append(b".shstrtab")
    shstr_parts.append(b"\0")
    shstrtab = b"".join(shstr_parts)
    shstrtab_offset = data_offset + filesz + data_pad

    num_sections = 1 + len(sections) + 1  # NULL + regions + .shstrtab
    shoff = shstrtab_offset + len(shstrtab)
    shoff = (shoff + 3) & ~3

    # ELF header
    ehdr = struct.pack(
        "<16sHH5I6H",
        b"\x7fELF" + bytes([ELFCLASS32, ELFDATA2LSB, EV_CURRENT]) + bytes(13),
        ET_EXEC, EM_ARM, 1, entry, 52, shoff,
        0, 52, 32, num_phdrs, 40, num_sections, num_sections - 1,
    )

    # Program headers
    phdrs = b""
    for name, addr, size, flags, off in segments:
        phdrs += struct.pack(
            "<IIIIIIII",
            PT_LOAD,
            off if off is not None else 0,
            addr, addr,
            size if off is not None else 0,
            size,
            flags, 0x1000,
        )

    # Section headers
    shdrs = b"\x00" * 40  # NULL section
    for name, addr, size, flags, nobits in sections:
        sh_flags = SHF_ALLOC
        if flags & PF_W:
            sh_flags |= SHF_WRITE
        if flags & PF_X:
            sh_flags |= SHF_EXECINSTR
        shdrs += struct.pack(
            "<IIIIIIIIII",
            sh_name_offsets[name],
            SHT_NOBITS if nobits else SHT_PROGBITS,
            sh_flags, addr,
            0, size, 0, 0, 4, 0,
        )
    shdrs += struct.pack(
        "<IIIIIIIIII",
        sh_name_offsets[".shstrtab"],
        SHT_STRTAB, 0, 0,
        shstrtab_offset, len(shstrtab), 0, 0, 1, 0,
    )

    return ehdr + phdrs + file_data + shstrtab + b"\x00" * (shoff - shstrtab_offset - len(shstrtab)) + shdrs


def firmware_to_elf(fw, svd_path, verbose=False):
    """Return ELF bytes for a decoded firmware."""
    code = fw.entries[0].code()
    load_addr = BASE_ADDRESS
    entry = 0
    blocks = fw.entries[0].blocks
    if blocks:
        idx = blocks[0].header.addr - load_addr
        if idx + 8 <= len(code):
            entry = struct.unpack("<I", code[idx + 4 : idx + 8])[0]
    return build_elf(code, load_addr, entry, svd_path, verbose=verbose)


DEFAULT_SVD = "/home/ckuethe/ghidra/cmsis-svd-stm32/stm32l4/STM32L4x5.svd"


def validate_elf(path):
    """Parse the generated ELF with pyelftools (if installed) to confirm it is well-formed."""
    try:
        from elftools.elf.elffile import ELFFile  # noqa: F401
    except ImportError:
        return True
    with open(path, "rb") as f:
        elffile = ELFFile(f)
        if elffile.elfclass != 32 or elffile.header["e_machine"] != "EM_ARM":
            return False
        # Touch every segment and section to force full parsing
        for seg in elffile.iter_segments():
            _ = seg["p_type"]
        for sec in elffile.iter_sections():
            _ = sec.name
    return True


def convert_file(path, out_path, svd_path, validate=True, verbose=False):
    with open(path, "rb") as f:
        data = f.read()
    fw = ff.load_firmware(data)
    elf_bytes = firmware_to_elf(fw, svd_path, verbose=verbose)
    with open(out_path, "wb") as f:
        f.write(elf_bytes)
    ok = validate_elf(out_path) if validate else True
    print(
        f"{os.path.basename(path)} -> {os.path.basename(out_path)}: "
        f"{len(data)}B -> ELF, entry 0x{struct.unpack('<I', elf_bytes[24:28])[0]:08x}, "
        f"blocks={len(fw.entries[0].blocks)}"
        + (" [validated]" if ok else " [FAILED VALIDATION]")
    )


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(
        description="Decrypt Phyton firmware images and convert them into "
        "disassembler-ready ARM ELF binaries with STM32L475 memory and "
        "peripheral mappings.",
    )
    parser.add_argument(
        "images",
        nargs="*",
        metavar="IMAGE.bin",
        help="Firmware image(s) to convert. If omitted, every image in "
        "HardSoft/ is processed.",
    )
    parser.add_argument(
        "--svd",
        default=DEFAULT_SVD,
        metavar="PATH",
        help="CMSIS-SVD file describing the MCU peripherals "
        "(default: %(default)s). If unset, peripherals are omitted.",
    )
    parser.add_argument(
        "--out",
        default=None,
        metavar="PATH",
        help="Directory for the generated .elf files. When processing a "
        "single image, may also be an output filename.",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip pyelftools validation of the generated ELF files.",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print every memory region as it is created.",
    )
    args = parser.parse_args(argv)

    svd_path = args.svd
    if svd_path and not os.path.exists(svd_path):
        print(f"warning: SVD file not found ({svd_path}); peripherals omitted")
        svd_path = None

    if args.images:
        inputs = args.images
    else:
        inputs = [
            os.path.join("HardSoft", n)
            for n in sorted(os.listdir("HardSoft"))
            if n.endswith(".bin") and not n.endswith(".dec.bin")
        ]
        if not inputs:
            parser.error("no firmware images found in HardSoft/")
        args.out = args.out or os.path.join("HardSoft", "dec")

    single = len(inputs) == 1
    for path in inputs:
        base = os.path.basename(path).replace(".bin", ".elf")
        if args.out:
            if single and os.path.basename(args.out).endswith(".elf"):
                out_path = args.out
            else:
                os.makedirs(args.out, exist_ok=True)
                out_path = os.path.join(args.out, base)
        else:
            out_path = os.path.join(os.path.dirname(path), base)
        try:
            convert_file(path, out_path, svd_path, args.no_validate, args.verbose)
        except Exception as exc:  # noqa: BLE001
            print(f"{os.path.basename(path)}: FAILED - {exc}")


if __name__ == "__main__":
    main()
